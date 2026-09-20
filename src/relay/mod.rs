//! Local loopback proxy listeners.

pub mod http;
pub mod socks5;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::upstream::{Tunnel, UpstreamHandle};

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
}

impl Stats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            active: self.active.load(Ordering::Relaxed),
            total: self.total.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            up_bytes: self.up_bytes.load(Ordering::Relaxed),
            down_bytes: self.down_bytes.load(Ordering::Relaxed),
        }
    }

    pub fn fail(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct StatsSnapshot {
    pub active: u64,
    pub total: u64,
    pub failed: u64,
    pub up_bytes: u64,
    pub down_bytes: u64,
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
