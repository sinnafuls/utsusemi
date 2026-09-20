//! Local loopback proxy listeners.

pub mod http;
pub mod socks5;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::upstream::{Tunnel, UpstreamError, UpstreamHandle, EXIT_REPLY_TIMEOUT};

/// 16 KiB per direction: large enough that a saturated link is not syscall
/// bound, small enough that ten thousand idle tunnels do not cost 100 MB.
const BUFFER_SIZE: usize = 16 * 1024;

/// Live counters surfaced by `utsusemi status`.
#[derive(Debug, Default)]
pub struct Stats {
    pub active: AtomicU64,
    pub total: AtomicU64,
    pub failed: AtomicU64,
    /// Failures caused by exits that took the tunnel and answered nothing.
    /// Kept apart from `failed` because only these say the exit is bad: a
    /// target the proxy refuses (403) or a client speaking nonsense would
    /// otherwise keep throwing away a perfectly good exit.
    pub silent_exits: AtomicU64,
    pub up_bytes: AtomicU64,
    pub down_bytes: AtomicU64,
    /// Why the most recent attempt failed, and when. A bare failure count
    /// cannot distinguish "one client spoke garbage" from "every request is
    /// being rejected by the upstream", which is exactly the case where the
    /// desktop looks broken and nothing says why.
    last_failure: Mutex<Option<(String, Instant)>>,
}

impl Stats {
    pub fn snapshot(&self) -> StatsSnapshot {
        let (last_failure, last_failure_secs_ago) = match self.last_failure() {
            Some((msg, at)) => (Some(msg), Some(at.elapsed().as_secs())),
            None => (None, None),
        };
        StatsSnapshot {
            active: self.active.load(Ordering::Relaxed),
            total: self.total.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            silent_exits: self.silent_exits.load(Ordering::Relaxed),
            up_bytes: self.up_bytes.load(Ordering::Relaxed),
            down_bytes: self.down_bytes.load(Ordering::Relaxed),
            last_failure,
            last_failure_secs_ago,
        }
    }

    /// Count a connection that never reached the splice, and keep why.
    pub fn fail(&self, reason: impl Into<String>) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut slot) = self.last_failure.lock() {
            *slot = Some((reason.into(), Instant::now()));
        }
    }

    /// Count a failure that is the exit's fault: it accepted the tunnel and
    /// never spoke.
    pub fn fail_silent_exit(&self, reason: impl Into<String>) {
        self.silent_exits.fetch_add(1, Ordering::Relaxed);
        self.fail(reason);
    }

    fn last_failure(&self) -> Option<(String, Instant)> {
        self.last_failure.lock().ok()?.clone()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatsSnapshot {
    pub active: u64,
    pub total: u64,
    pub failed: u64,
    #[serde(default)]
    pub silent_exits: u64,
    pub up_bytes: u64,
    pub down_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure_secs_ago: Option<u64>,
}

/// Keeps `active` honest: decrements on every exit path, including panics.
struct ActiveGuard(Arc<Stats>);

impl ActiveGuard {
    fn enter(stats: Arc<Stats>) -> Self {
        stats.total.fetch_add(1, Ordering::Relaxed);
        stats.active.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(stats)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Upstream dials allowed at once, across every client connection. Webshare's
/// base residential tier is flagged `is_high_concurrency: false`, and racing
/// exits multiplies connections fast: without a ceiling the relay answers a
/// flaky pool by hammering it, which is how a plan gets throttled.
const MAX_CONCURRENT_DIALS: usize = 8;

/// Everything a listener needs: where to forward, where to count, and how
/// much of the backbone it may use at once.
#[derive(Clone)]
pub struct Relay {
    pub upstream: UpstreamHandle,
    pub stats: Arc<Stats>,
    dial_slots: Arc<tokio::sync::Semaphore>,
}

impl Relay {
    pub fn new(upstream: UpstreamHandle) -> Self {
        Relay {
            upstream,
            stats: Arc::new(Stats::default()),
            dial_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DIALS)),
        }
    }

    /// A dialer for tunnels to `host:port`, sharing this relay's dial budget.
    pub fn tunnel_dialer(&self, host: &str, port: u16) -> Dialer {
        Dialer {
            kind: DialKind::Tunnel {
                upstream: self.upstream.clone(),
                host: host.into(),
                port,
            },
            slots: self.dial_slots.clone(),
        }
    }

    /// A dialer for plain connections to the upstream itself.
    pub fn raw_dialer(&self) -> Dialer {
        Dialer {
            kind: DialKind::Raw {
                upstream: self.upstream.clone(),
            },
            slots: self.dial_slots.clone(),
        }
    }
}

/// Opens replacement tunnels to the same target. Owned and cloneable so that
/// racing attempts can run as independent tasks, and budgeted so that racing
/// cannot flood the backbone.
#[derive(Clone)]
pub struct Dialer {
    kind: DialKind,
    slots: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
enum DialKind {
    /// Handshake a tunnel to `host:port` through the current upstream.
    Tunnel {
        upstream: UpstreamHandle,
        host: Arc<str>,
        port: u16,
    },
    /// Plain connection to the upstream itself, for absolute-form HTTP that
    /// carries its own target in the request line.
    Raw { upstream: UpstreamHandle },
}

impl Dialer {
    pub async fn open(&self) -> Result<Tunnel, UpstreamError> {
        // Held for the handshake only: an established tunnel is the client's
        // to keep, but the stampede of attempts is ours to throttle.
        let _slot = self.slots.acquire().await;
        match &self.kind {
            DialKind::Tunnel {
                upstream,
                host,
                port,
            } => crate::upstream::connect_through(&upstream.get(), host, *port).await,
            DialKind::Raw { upstream } => {
                crate::upstream::dial_raw(&upstream.get())
                    .await
                    .map(|stream| Tunnel {
                        stream,
                        prelude: Vec::new(),
                    })
            }
        }
    }
}

/// How hard a single client connection hunts for an exit that answers.
#[derive(Debug, Clone, Copy)]
pub struct ExitPolicy {
    /// Time one exit gets to answer before it is written off.
    pub reply_timeout: std::time::Duration,
    /// Wait before adding another exit to the race rather than replacing one.
    pub hedge_delay: std::time::Duration,
    /// Exits racing at once.
    pub max_in_flight: usize,
    /// Total time to spend finding an exit before the client is told no.
    pub budget: std::time::Duration,
}

impl Default for ExitPolicy {
    fn default() -> Self {
        ExitPolicy {
            reply_timeout: EXIT_REPLY_TIMEOUT,
            hedge_delay: std::time::Duration::from_millis(700),
            max_in_flight: 4,
            budget: std::time::Duration::from_secs(20),
        }
    }
}

impl ExitPolicy {
    /// One exit, no replay. For requests that must not be sent twice.
    pub fn single() -> Self {
        ExitPolicy {
            max_in_flight: 1,
            budget: EXIT_REPLY_TIMEOUT,
            ..ExitPolicy::default()
        }
    }
}

/// Run a client connection over a tunnel, racing exits until one answers.
///
/// The Webshare gateway answers CONNECT before the exit has reached anything,
/// so an established tunnel proves nothing: a dead residential exit swallows
/// the client's first message and never replies, which downstream looks like
/// a page that never loads. Until the first upstream byte arrives nothing has
/// been handed to the client, so the request can be replayed — on several
/// exits at once — without the client ever knowing.
///
/// Racing rather than retrying in sequence is what makes a pool with a low
/// share of working exits usable: the client pays one exit's latency, not the
/// sum of every dead one's timeout. Once an exit answers it is spliced
/// through and every later request on that connection rides it, which is
/// exactly how a browser stays fast on a flaky pool.
///
/// `prefix` is anything already read from the client that belongs upstream.
pub async fn serve_tunnel(
    mut client: TcpStream,
    mut tunnel: Tunnel,
    stats: Arc<Stats>,
    target: &str,
    prefix: Vec<u8>,
    policy: ExitPolicy,
    dialer: Dialer,
) {
    let mut pending = prefix;

    if tunnel.prelude.is_empty() && pending.is_empty() {
        // Nobody has spoken yet. Whoever does first decides: a client request
        // can still be replayed, an upstream greeting (SSH, SMTP) means this
        // exit is alive and the tunnel is committed.
        let mut from_client = vec![0u8; BUFFER_SIZE];
        let mut from_exit = vec![0u8; BUFFER_SIZE];
        tokio::select! {
            read = client.read(&mut from_client) => match read {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    from_client.truncate(n);
                    pending = from_client;
                }
            },
            read = tunnel.stream.read(&mut from_exit) => match read {
                Ok(0) | Err(_) => {
                    stats.fail_silent_exit(format!(
                        "exit closed the tunnel to {target} without a word"
                    ));
                    return;
                }
                Ok(n) => {
                    from_exit.truncate(n);
                    tunnel.prelude = from_exit;
                }
            },
        }
    }

    if tunnel.prelude.is_empty() {
        let payload: Arc<[u8]> = Arc::from(pending);
        match race_exits(tunnel, payload, &policy, &dialer, &stats).await {
            Some(live) => tunnel = live,
            None => {
                stats.fail_silent_exit(format!(
                    "no exit answered for {target} within {}s ({} raced at a time)",
                    policy.budget.as_secs(),
                    policy.max_in_flight
                ));
                return;
            }
        }
    }

    splice(client, tunnel, stats).await;
}

/// Push `payload` at exits until one replies, adding a fresh exit to the race
/// every `hedge_delay` and replacing any that fails. Returns the winning
/// tunnel with the reply already in its prelude.
async fn race_exits(
    first: Tunnel,
    payload: Arc<[u8]>,
    policy: &ExitPolicy,
    dialer: &Dialer,
    stats: &Arc<Stats>,
) -> Option<Tunnel> {
    let deadline = tokio::time::Instant::now() + policy.budget;
    let mut racing = tokio::task::JoinSet::new();

    racing.spawn(try_exit(
        Some(first),
        payload.clone(),
        policy.reply_timeout,
        dialer.clone(),
        stats.clone(),
    ));
    let mut in_flight = 1usize;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return None;
        }
        let next_hedge = policy.hedge_delay.min(deadline - now);

        match tokio::time::timeout(next_hedge, racing.join_next()).await {
            // An exit answered: everything still racing is dropped, which
            // closes those tunnels.
            Ok(Some(Ok(Some(live)))) => return Some(live),
            // An exit failed or its task died; replace it.
            Ok(Some(_)) => in_flight = in_flight.saturating_sub(1),
            // Nothing left racing at all.
            Ok(None) => in_flight = 0,
            // Nobody has answered yet; widen the search.
            Err(_) => {}
        }

        if in_flight < policy.max_in_flight {
            racing.spawn(try_exit(
                None,
                payload.clone(),
                policy.reply_timeout,
                dialer.clone(),
                stats.clone(),
            ));
            in_flight += 1;
        }
    }
}

/// One exit's turn: open it (unless handed one), send the request, and wait
/// for a first byte. `None` means it is a black hole.
async fn try_exit(
    existing: Option<Tunnel>,
    payload: Arc<[u8]>,
    reply_timeout: std::time::Duration,
    dialer: Dialer,
    stats: Arc<Stats>,
) -> Option<Tunnel> {
    let mut tunnel = match existing {
        Some(t) => t,
        None => dialer.open().await.ok()?,
    };

    tunnel.stream.write_all(&payload).await.ok()?;
    tunnel.stream.flush().await.ok()?;
    stats
        .up_bytes
        .fetch_add(payload.len() as u64, Ordering::Relaxed);

    let mut reply = vec![0u8; BUFFER_SIZE];
    let read = tokio::time::timeout(reply_timeout, tunnel.stream.read(&mut reply))
        .await
        .ok()?
        .ok()?;
    if read == 0 {
        return None;
    }
    reply.truncate(read);
    tunnel.prelude = reply;
    Some(tunnel)
}

/// Join a client socket to an established tunnel and pump until both
/// directions close.
pub async fn splice(mut client: TcpStream, tunnel: Tunnel, stats: Arc<Stats>) {
    let _guard = ActiveGuard::enter(stats.clone());

    if !tunnel.prelude.is_empty() {
        stats
            .down_bytes
            .fetch_add(tunnel.prelude.len() as u64, Ordering::Relaxed);
        if let Err(e) = client.write_all(&tunnel.prelude).await {
            tracing::debug!("client went away before the prelude landed: {e}");
            return;
        }
    }

    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = tunnel.stream.into_split();

    let outbound = pump(client_read, upstream_write, &stats.up_bytes);
    let inbound = pump(upstream_read, client_write, &stats.down_bytes);

    // Both halves always run to completion: a one-directional close (a client
    // that stops sending but still reads) must not tear down the response.
    let (out, inb) = tokio::join!(outbound, inbound);
    if let Err(e) = out {
        tracing::trace!("outbound copy ended: {e}");
    }
    if let Err(e) = inb {
        tracing::trace!("inbound copy ended: {e}");
    }
}

async fn pump<R, W>(mut reader: R, mut writer: W, counter: &AtomicU64) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
        // Counted as it flows so `utsusemi status` shows live throughput.
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
    writer.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    /// Exits that behave like the ones causing trouble: the tunnel is open,
    /// the request goes in, and only the `answer_from`-th one ever replies.
    async fn exit_pool(answer_from: usize) -> (std::net::SocketAddr, Arc<AtomicU64>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let opened = Arc::new(AtomicU64::new(0));
        let counter = opened.clone();

        tokio::spawn(async move {
            let mut parked = Vec::new();
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let n = counter.fetch_add(1, Ordering::SeqCst) as usize;
                if n + 1 < answer_from {
                    // Swallow the request, answer never.
                    parked.push(socket);
                    continue;
                }
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if socket.read(&mut buf).await.unwrap_or(0) > 0 {
                        let _ = socket.write_all(b"PONG").await;
                        let _ = socket.flush().await;
                    }
                });
            }
        });

        (addr, opened)
    }

    /// Client socket plus the server side of the same connection.
    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        (client, server)
    }

    /// A dialer that opens plain connections to the fake exit pool.
    fn dialer_to(addr: std::net::SocketAddr) -> Dialer {
        let endpoint: crate::endpoint::Endpoint = addr.to_string().parse().expect("endpoint");
        Relay::new(UpstreamHandle::new(endpoint)).raw_dialer()
    }

    fn sequential() -> ExitPolicy {
        ExitPolicy {
            reply_timeout: Duration::from_millis(150),
            hedge_delay: Duration::from_secs(60),
            max_in_flight: 1,
            budget: Duration::from_secs(3),
        }
    }

    #[tokio::test]
    async fn a_silent_exit_is_replaced_and_the_request_replayed() {
        let (exits, opened) = exit_pool(3).await;
        let (mut app, relay_side) = socket_pair().await;
        let stats = Arc::new(Stats::default());

        let first = Tunnel {
            stream: TcpStream::connect(exits).await.expect("exit"),
            prelude: Vec::new(),
        };
        let served = tokio::spawn({
            let stats = stats.clone();
            async move {
                serve_tunnel(
                    relay_side,
                    first,
                    stats,
                    "example.com:443",
                    b"PING".to_vec(),
                    sequential(),
                    dialer_to(exits),
                )
                .await;
            }
        });

        let mut got = [0u8; 4];
        app.read_exact(&mut got)
            .await
            .expect("reply from third exit");
        assert_eq!(&got, b"PONG");
        assert_eq!(opened.load(Ordering::SeqCst), 3, "two exits written off");
        assert_eq!(
            stats.snapshot().failed,
            0,
            "a recovered request is not a failure"
        );

        drop(app);
        let _ = served.await;
    }

    #[tokio::test]
    async fn exits_are_raced_so_one_dead_exit_costs_no_waiting() {
        // Only the fourth exit answers, and each one is allowed a full second
        // of silence: sequentially this could not finish inside three.
        let (exits, _) = exit_pool(4).await;
        let (mut app, relay_side) = socket_pair().await;
        let stats = Arc::new(Stats::default());

        let first = Tunnel {
            stream: TcpStream::connect(exits).await.expect("exit"),
            prelude: Vec::new(),
        };
        let policy = ExitPolicy {
            reply_timeout: Duration::from_secs(1),
            hedge_delay: Duration::from_millis(20),
            max_in_flight: 4,
            budget: Duration::from_secs(3),
        };

        let started = std::time::Instant::now();
        let served = tokio::spawn({
            let stats = stats.clone();
            async move {
                serve_tunnel(
                    relay_side,
                    first,
                    stats,
                    "example.com:443",
                    b"PING".to_vec(),
                    policy,
                    dialer_to(exits),
                )
                .await;
            }
        });

        let mut got = [0u8; 4];
        app.read_exact(&mut got)
            .await
            .expect("a racing exit answers");
        assert_eq!(&got, b"PONG");
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "raced, not queued behind three silences: {:?}",
            started.elapsed()
        );

        drop(app);
        let _ = served.await;
    }

    #[tokio::test]
    async fn every_exit_silent_is_reported_not_left_hanging() {
        let (exits, _) = exit_pool(usize::MAX).await;
        let (mut app, relay_side) = socket_pair().await;
        let stats = Arc::new(Stats::default());

        let first = Tunnel {
            stream: TcpStream::connect(exits).await.expect("exit"),
            prelude: Vec::new(),
        };
        serve_tunnel(
            relay_side,
            first,
            stats.clone(),
            "example.com:443",
            b"PING".to_vec(),
            ExitPolicy {
                reply_timeout: Duration::from_millis(100),
                hedge_delay: Duration::from_millis(50),
                max_in_flight: 3,
                budget: Duration::from_millis(600),
            },
            dialer_to(exits),
        )
        .await;

        // The client is released instead of waiting forever on a dead exit.
        let mut buf = [0u8; 1];
        assert_eq!(
            app.read(&mut buf).await.unwrap_or(0),
            0,
            "connection closed"
        );

        let snap = stats.snapshot();
        assert_eq!(snap.failed, 1);
        let reason = snap.last_failure.expect("a reason");
        assert!(reason.contains("example.com:443"), "{reason}");
        assert!(reason.contains("raced"), "{reason}");
    }
}
