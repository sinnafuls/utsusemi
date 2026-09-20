//! Control channel between the CLI and a running relay.
//!
//! Line-delimited JSON over loopback TCP. Every request carries the token from
//! the (owner-only) state file: loopback alone would let any local process
//! re-point the relay at an upstream of its choosing, which is a
//! man-in-the-middle on everything the desktop sends.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream as StdTcpStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::TcpListener;
use tokio::sync::Notify;

use crate::endpoint::{Endpoint, Session, WebshareUser};
use crate::relay::{Relay, StatsSnapshot};
use crate::state::RunState;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Live counters and current targeting.
    Status,
    /// Restore the system proxy and exit.
    Stop,
    /// Roll the sticky session id so the next request gets a new exit IP.
    Rotate,
    /// Point at a different endpoint without dropping the listeners.
    Switch { endpoint: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub token: String,
    #[serde(flatten)]
    pub request: Request,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReply {
    pub endpoint: String,
    pub summary: String,
    pub http: String,
    pub socks5: String,
    pub profile: Option<String>,
    pub uptime_secs: u64,
    pub system_proxy: bool,
    pub stats: StatsSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reply {
    Ok,
    Status(Box<StatusReply>),
    Switched { endpoint: String, summary: String },
    Error { message: String },
}

/// Shared context the control server reads and mutates.
pub struct ControlContext {
    pub relay: Relay,
    pub state: std::sync::Mutex<RunState>,
    pub shutdown: Notify,
}

pub async fn serve(listener: TcpListener, ctx: Arc<ControlContext>) -> Result<()> {
    loop {
        let (socket, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("control accept failed: {e}");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(socket, ctx).await {
                tracing::debug!("control connection ended: {e}");
            }
        });
    }
}

async fn handle(socket: tokio::net::TcpStream, ctx: Arc<ControlContext>) -> Result<()> {
    let (read_half, mut write_half) = socket.into_split();
    let mut lines = AsyncBufReader::new(read_half).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Envelope>(&line) {
            Ok(envelope) => dispatch(envelope, &ctx).await,
            Err(e) => Reply::Error {
                message: format!("malformed request: {e}"),
            },
        };
        let mut bytes = serde_json::to_vec(&reply)?;
        bytes.push(b'\n');
        write_half.write_all(&bytes).await?;
        write_half.flush().await?;
    }
    Ok(())
}

async fn dispatch(envelope: Envelope, ctx: &Arc<ControlContext>) -> Reply {
    {
        let state = match ctx.state.lock() {
            Ok(s) => s,
            Err(_) => {
                return Reply::Error {
                    message: "internal state lock poisoned".into(),
                }
            }
        };
        if !constant_time_eq(envelope.token.as_bytes(), state.token.as_bytes()) {
            return Reply::Error {
                message: "invalid control token".into(),
            };
        }
    }

    match envelope.request {
        Request::Status => {
            let state = ctx.state.lock().expect("state lock");
            let endpoint = ctx.relay.upstream.get();
            Reply::Status(Box::new(StatusReply {
                endpoint: endpoint.redacted(),
                summary: endpoint
                    .webshare_user()
                    .map(|u| u.summary())
                    .unwrap_or_else(|| "no Webshare targeting".into()),
                http: state.http.clone(),
                socks5: state.socks5.clone(),
                profile: state.profile.clone(),
                uptime_secs: state.uptime_secs(),
                system_proxy: state.system_proxy,
                stats: ctx.relay.stats.snapshot(),
            }))
        }
        Request::Stop => {
            ctx.shutdown.notify_waiters();
            Reply::Ok
        }
        Request::Rotate => {
            let current = ctx.relay.upstream.get();
            let Some(mut user) = current.webshare_user() else {
                return Reply::Error {
                    message: "endpoint has no Webshare username to rotate".into(),
                };
            };
            // A rotating endpoint already picks a new IP per request; rolling a
            // sticky session id is the only thing rotation can mean here.
            user.session = match user.session {
                Session::Rotate => Session::Rotate,
                _ => Session::Sticky(WebshareUser::new_sticky_id()),
            };
            let updated = current.with_username(user.build());
            apply_switch(ctx, updated).await
        }
        Request::Switch { endpoint } => match endpoint.parse::<Endpoint>() {
            Ok(parsed) => apply_switch(ctx, parsed).await,
            Err(e) => Reply::Error {
                message: format!("invalid endpoint: {e}"),
            },
        },
    }
}

/// Swap the live upstream, but only after proving the new one works. A switch
/// that silently installs a dead endpoint is worse than a refused switch: the
/// system proxy keeps pointing here and every request on the desktop fails.
async fn apply_switch(ctx: &Arc<ControlContext>, endpoint: Endpoint) -> Reply {
    let summary = endpoint
        .webshare_user()
        .map(|u| u.summary())
        .unwrap_or_else(|| "no Webshare targeting".into());
    let redacted = endpoint.redacted();

    if let Err(e) = crate::upstream::probe(&endpoint).await {
        tracing::warn!("refusing switch to {redacted}: {e}");
        return Reply::Error {
            message: format!("{redacted} does not work, keeping the current upstream: {e}"),
        };
    }

    ctx.relay.upstream.set(endpoint.clone());
    if let Ok(mut state) = ctx.state.lock() {
        state.endpoint = endpoint;
        if let Err(e) = state.save() {
            tracing::warn!("could not persist switched endpoint: {e}");
        }
    }
    tracing::info!("upstream switched to {redacted}");

    Reply::Switched {
        endpoint: redacted,
        summary,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Blocking client used by the CLI.
pub fn request(addr: &str, token: &str, req: Request) -> Result<Reply> {
    let stream = StdTcpStream::connect(addr)
        .with_context(|| format!("connecting to the running relay at {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let envelope = Envelope {
        token: token.to_string(),
        request: req,
    };
    let mut line = serde_json::to_string(&envelope)?;
    line.push('\n');

    let mut writer = stream.try_clone()?;
    writer.write_all(line.as_bytes())?;
    writer.flush()?;

    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    if response.trim().is_empty() {
        bail!("relay closed the control connection without replying");
    }
    Ok(serde_json::from_str(&response)?)
}

/// Generate a control token.
pub fn new_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
