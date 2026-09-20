//! Local loopback proxy listeners.

pub mod http;
pub mod socks5;

use std::future::Future;
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

    fn last_failure(&self) -> Option<(String, Instant)> {
        self.last_failure.lock().ok()?.clone()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatsSnapshot {
    pub active: u64,
    pub total: u64,
    pub failed: u64,
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

/// Everything a listener needs: where to forward, and where to count.
#[derive(Clone)]
pub struct Relay {
    pub upstream: UpstreamHandle,
    pub stats: Arc<Stats>,
}

impl Relay {
    pub fn new(upstream: UpstreamHandle) -> Self {
        Relay {
            upstream,
            stats: Arc::new(Stats::default()),
        }
    }
}

/// How patient a single client connection is with dead exits.
#[derive(Debug, Clone, Copy)]
pub struct ExitPolicy {
    /// Time one exit gets to answer before it is written off.
    pub reply_timeout: std::time::Duration,
    /// Exits to burn before the client is told there is nothing there.
    pub attempts: u32,
}

impl Default for ExitPolicy {
    fn default() -> Self {
        ExitPolicy {
            reply_timeout: EXIT_REPLY_TIMEOUT,
            attempts: 3,
        }
    }
}

/// Run a client connection over a tunnel, replacing the exit while it is
/// still safe to do so.
///
/// The Webshare gateway answers CONNECT before the exit has reached anything,
/// so an established tunnel proves nothing: a dead residential exit swallows
/// the client's first message and never replies, which downstream looks like
/// a page that never loads. Until the first upstream byte arrives nothing has
/// been handed to the client, so the request can be replayed on a fresh
/// tunnel — a fresh exit, on a rotating endpoint — without the client ever
/// knowing.
///
/// `prefix` is anything already read from the client that belongs upstream.
/// `reconnect` opens a replacement tunnel to the same target.
pub async fn serve_tunnel<F, Fut>(
    mut client: TcpStream,
    mut tunnel: Tunnel,
    stats: Arc<Stats>,
    target: &str,
    prefix: Vec<u8>,
    policy: ExitPolicy,
    mut reconnect: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Tunnel, UpstreamError>>,
{
    let mut pending = prefix;
    let mut attempt = 1;

    while tunnel.prelude.is_empty() {
        if pending.is_empty() {
            // Nobody has spoken yet. Whoever does first decides: a client
            // request can still be retried, an upstream greeting (SSH, SMTP)
            // means the exit is alive and the tunnel is committed.
            let mut buf = vec![0u8; BUFFER_SIZE];
            let mut up = vec![0u8; BUFFER_SIZE];
            tokio::select! {
                read = client.read(&mut buf) => match read {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        buf.truncate(n);
                        pending = buf;
                    }
                },
                read = tunnel.stream.read(&mut up) => match read {
                    Ok(0) | Err(_) => {
                        stats.fail(format!("exit closed the tunnel to {target} without a word"));
                        return;
                    }
                    Ok(n) => {
                        up.truncate(n);
                        tunnel.prelude = up;
                        break;
                    }
                },
            }
        }

        if tunnel.stream.write_all(&pending).await.is_err() || tunnel.stream.flush().await.is_err()
        {
            stats.fail(format!("exit dropped the request to {target}"));
            return;
        }
        stats
            .up_bytes
            .fetch_add(pending.len() as u64, Ordering::Relaxed);

        let mut up = vec![0u8; BUFFER_SIZE];
        let first = tokio::time::timeout(policy.reply_timeout, tunnel.stream.read(&mut up)).await;

        match first {
            Ok(Ok(n)) if n > 0 => {
                up.truncate(n);
                tunnel.prelude = up;
                break;
            }
            // Silent or closed: the exit is a black hole. Nothing has reached
            // the client, so try the next one with the same request.
            _ => {
                if attempt >= policy.attempts {
                    stats.fail(format!(
                        "no exit answered for {target} ({} tried, {}s each)",
                        policy.attempts,
                        policy.reply_timeout.as_secs_f32()
                    ));
                    return;
                }
                attempt += 1;
                tracing::debug!("silent exit for {target}, trying another ({attempt})");
                tunnel = match reconnect().await {
                    Ok(t) => t,
                    Err(e) => {
                        stats.fail(format!("replacing the silent exit for {target}: {e}"));
                        return;
                    }
                };
            }
        }
    }

    splice(client, tunnel, stats).await;
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

    fn impatient() -> ExitPolicy {
        ExitPolicy {
            reply_timeout: Duration::from_millis(150),
            attempts: 3,
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
                    impatient(),
                    || async move {
                        Ok(Tunnel {
                            stream: TcpStream::connect(exits).await.expect("exit"),
                            prelude: Vec::new(),
                        })
                    },
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
            impatient(),
            || async move {
                Ok(Tunnel {
                    stream: TcpStream::connect(exits).await.expect("exit"),
                    prelude: Vec::new(),
                })
            },
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
        assert!(reason.contains("3 tried"), "{reason}");
    }
}
