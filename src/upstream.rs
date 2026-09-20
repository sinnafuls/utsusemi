//! Dialling the Webshare upstream proxy.
//!
//! Two upstream protocols are supported, because Webshare's backbone speaks
//! both: HTTP `CONNECT` (ports 80/3128/9999-19999) and SOCKS5 (port 1080).
//!
//! Target hostnames are *never* resolved locally. They go to the exit node
//! verbatim, so DNS is answered from the residential IP's vantage point.
//! Resolving here would leak the real location and defeat geo targeting.

use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::endpoint::{Endpoint, Scheme};

/// How long to wait for the upstream TCP connect and handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Refuse absurd proxy response headers rather than buffering forever.
const MAX_HEAD: usize = 16 * 1024;
/// Target used to prove an upstream actually works before anything depends on
/// it. Webshare's own echo host: reachable from every exit, and a 407 here is
/// unambiguous.
const PROBE_HOST: &str = "ipv4.webshare.io";
const PROBE_PORT: u16 = 443;

/// Hot-swappable upstream. `switch`/`rotate` replace it while the relay keeps
/// listening, so existing sockets drain on the old exit and new connections
/// use the new one.
#[derive(Clone)]
pub struct UpstreamHandle(Arc<RwLock<Arc<Endpoint>>>);

impl UpstreamHandle {
    pub fn new(endpoint: Endpoint) -> Self {
        UpstreamHandle(Arc::new(RwLock::new(Arc::new(endpoint))))
    }

    pub fn get(&self) -> Arc<Endpoint> {
        self.0.read().expect("upstream lock poisoned").clone()
    }

    pub fn set(&self, endpoint: Endpoint) {
        *self.0.write().expect("upstream lock poisoned") = Arc::new(endpoint);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("cannot reach upstream proxy {addr}: {source}")]
    Dial {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("upstream proxy rejected the credentials{}", .reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default())]
    Auth {
        /// What the proxy said, when it said anything. Webshare puts the real
        /// cause in the `Proxy-Authenticate` realm: bad password and "that
        /// country is not in your proxy list" both arrive as a bare 407.
        reason: Option<String>,
    },
    #[error("upstream proxy refused target {target}: {reason}")]
    Refused { target: String, reason: String },
    #[error("upstream protocol error: {0}")]
    Protocol(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// An established tunnel to the target.
pub struct Tunnel {
    pub stream: TcpStream,
    /// Payload bytes the proxy coalesced into the handshake response. Protocols
    /// where the server speaks first (SSH, SMTP, IMAP) routinely land here, so
    /// they must be replayed to the client before splicing.
    pub prelude: Vec<u8>,
}

/// Open a raw TCP connection to the proxy itself, with no handshake. Used for
/// plain HTTP requests, which an HTTP upstream accepts in absolute form.
pub async fn dial_raw(upstream: &Endpoint) -> Result<TcpStream, UpstreamError> {
    let addr = upstream.address();
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
        .await
        .map_err(|_| UpstreamError::Dial {
            addr: addr.clone(),
            source: std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out after 15s"),
        })?
        .map_err(|source| UpstreamError::Dial {
            addr: addr.clone(),
            source,
        })?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Open a tunnel to `host:port` through `upstream`.
pub async fn connect_through(
    upstream: &Endpoint,
    host: &str,
    port: u16,
) -> Result<Tunnel, UpstreamError> {
    let stream = dial_raw(upstream).await?;

    let handshake = async {
        match upstream.scheme {
            Scheme::Http => http_connect(stream, upstream, host, port).await,
            Scheme::Socks5 => socks5_connect(stream, upstream, host, port).await,
        }
    };
    tokio::time::timeout(CONNECT_TIMEOUT, handshake)
        .await
        .map_err(|_| {
            UpstreamError::Protocol("upstream proxy handshake timed out after 15s".into())
        })?
}

/// Prove the upstream is usable: full dial plus handshake to a known-good
/// target, then throw the tunnel away. Called before anything (the Windows
/// system proxy, a live switch) starts depending on the endpoint, because a
/// bad endpoint otherwise only shows up as every request in the desktop
/// failing.
pub async fn probe(upstream: &Endpoint) -> Result<(), UpstreamError> {
    connect_through(upstream, PROBE_HOST, PROBE_PORT)
        .await
        .map(drop)
}

// HTTP CONNECT

async fn http_connect(
    mut stream: TcpStream,
    upstream: &Endpoint,
    host: &str,
    port: u16,
) -> Result<Tunnel, UpstreamError> {
    let target = format!("{host}:{port}");
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(auth) = upstream.basic_auth_header() {
        request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    request.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let (head, prelude) = read_http_head(&mut stream).await?;
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| UpstreamError::Protocol("empty response to CONNECT".into()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| {
            UpstreamError::Protocol(format!("unparseable CONNECT status line: {status_line}"))
        })?;

    match status {
        200..=299 => Ok(Tunnel { stream, prelude }),
        407 => Err(UpstreamError::Auth {
            reason: auth_reason(&head),
        }),
        _ => Err(UpstreamError::Refused {
            target,
            reason: status_line.trim().to_string(),
        }),
    }
}

/// Pull the realm out of `Proxy-Authenticate: Basic realm="..."`. Webshare
/// states the actual reason there ("The proxy you are connecting is not in
/// your list."), while the body is always the same generic sentence.
fn auth_reason(head: &str) -> Option<String> {
    let line = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("proxy-authenticate:"))?;
    let realm = line.split_once("realm=")?.1.trim();
    let realm = realm.trim_matches('"').trim();
    (!realm.is_empty()).then(|| realm.to_string())
}

/// Read up to and including `\r\n\r\n`, returning the head and any bytes that
/// followed it in the same read.
async fn read_http_head(stream: &mut TcpStream) -> Result<(String, Vec<u8>), UpstreamError> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(UpstreamError::Protocol(
                "upstream closed the connection during the handshake".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_header_end(&buf) {
            let rest = buf.split_off(end);
            let head = String::from_utf8_lossy(&buf).into_owned();
            return Ok((head, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(UpstreamError::Protocol(
                "upstream response header exceeded 16 KiB".into(),
            ));
        }
    }
}

/// Index just past the `\r\n\r\n` (or `\n\n`) that ends a header block.
pub(crate) fn find_header_end(buf: &[u8]) -> Option<usize> {
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

// SOCKS5 (RFC 1928 / RFC 1929)

async fn socks5_connect(
    mut stream: TcpStream,
    upstream: &Endpoint,
    host: &str,
    port: u16,
) -> Result<Tunnel, UpstreamError> {
    let credentials = upstream.credentials();

    // Method negotiation.
    let greeting: &[u8] = match credentials {
        Some(_) => &[0x05, 0x02, 0x00, 0x02],
        None => &[0x05, 0x01, 0x00],
    };
    stream.write_all(greeting).await?;
    stream.flush().await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        return Err(UpstreamError::Protocol(format!(
            "upstream is not SOCKS5 (version byte {:#04x}); is this an HTTP proxy port?",
            reply[0]
        )));
    }
    match reply[1] {
        0x00 => {}
        0x02 => {
            let (user, pass) = credentials.ok_or_else(|| UpstreamError::Auth {
                reason: Some(
                    "upstream demands a username and password, but the endpoint has none".into(),
                ),
            })?;
            username_password_auth(&mut stream, user, pass).await?;
        }
        0xFF => {
            return Err(UpstreamError::Auth {
                reason: Some("upstream rejected every offered SOCKS5 auth method".into()),
            })
        }
        other => {
            return Err(UpstreamError::Protocol(format!(
                "upstream selected unsupported SOCKS5 auth method {other:#04x}"
            )))
        }
    }

    // CONNECT request.
    let mut request = vec![0x05, 0x01, 0x00];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            request.push(0x01);
            request.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            request.push(0x04);
            request.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let bytes = host.as_bytes();
            if bytes.len() > 255 {
                return Err(UpstreamError::Protocol(format!(
                    "hostname too long for SOCKS5 ({} bytes)",
                    bytes.len()
                )));
            }
            request.push(0x03);
            request.push(bytes.len() as u8);
            request.extend_from_slice(bytes);
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(UpstreamError::Protocol(format!(
            "bad SOCKS5 reply version {:#04x}",
            head[0]
        )));
    }
    let target = format!("{host}:{port}");
    if head[1] != 0x00 {
        // Drain the bound address so the error path does not desync anything.
        let _ = read_socks_addr(&mut stream, head[3]).await;
        return Err(match head[1] {
            0x02 => UpstreamError::Auth {
                reason: Some(format!(
                    "not allowed to reach {target} with these credentials"
                )),
            },
            code => UpstreamError::Refused {
                target,
                reason: socks_reply_reason(code).to_string(),
            },
        });
    }
    read_socks_addr(&mut stream, head[3]).await?;

    Ok(Tunnel {
        stream,
        prelude: Vec::new(),
    })
}

async fn username_password_auth(
    stream: &mut TcpStream,
    user: &str,
    pass: &str,
) -> Result<(), UpstreamError> {
    if user.len() > 255 || pass.len() > 255 {
        return Err(UpstreamError::Protocol(
            "SOCKS5 username/password must each be at most 255 bytes".into(),
        ));
    }
    let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
    msg.push(0x01); // RFC 1929 sub-negotiation version
    msg.push(user.len() as u8);
    msg.extend_from_slice(user.as_bytes());
    msg.push(pass.len() as u8);
    msg.extend_from_slice(pass.as_bytes());
    stream.write_all(&msg).await?;
    stream.flush().await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(UpstreamError::Auth {
            reason: Some(format!(
                "username/password rejected (status {:#04x})",
                reply[1]
            )),
        });
    }
    Ok(())
}

/// Consume a SOCKS5 address field so the stream lands on the first payload byte.
async fn read_socks_addr(stream: &mut TcpStream, atyp: u8) -> Result<(), UpstreamError> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 4 + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 16 + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        other => {
            return Err(UpstreamError::Protocol(format!(
                "unknown SOCKS5 address type {other:#04x}"
            )))
        }
    }
    Ok(())
}

pub(crate) fn socks_reply_reason(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown SOCKS5 failure",
    }
}

/// Parse a `host:port` authority without resolving it.
pub(crate) fn split_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            Some((host.to_string(), port.parse().ok()?))
        }
        _ => {
            if authority.is_empty() {
                None
            } else {
                Some((authority.to_string(), default_port))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_header_terminator() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\n"), Some(19));
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n"), None);
    }

    #[test]
    fn extracts_the_reason_webshare_puts_in_the_407_realm() {
        let head = "HTTP/1.1 407 Proxy Authentication Required\r\n\
                    Proxy-Authenticate: Basic realm=\"The proxy you are connecting is not in your list.\"\r\n\
                    Content-Length: 121\r\n\r\n";
        assert_eq!(
            auth_reason(head).as_deref(),
            Some("The proxy you are connecting is not in your list.")
        );
        assert_eq!(
            auth_reason("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"),
            None
        );
        assert_eq!(
            auth_reason("HTTP/1.1 407 x\r\nproxy-authenticate: Basic realm=\"\"\r\n\r\n"),
            None
        );
    }

    #[test]
    fn splits_authorities_without_resolving() {
        assert_eq!(
            split_authority("example.com:8080", 80),
            Some(("example.com".into(), 8080))
        );
        assert_eq!(
            split_authority("example.com", 80),
            Some(("example.com".into(), 80))
        );
        assert_eq!(split_authority("[::1]:443", 80), Some(("::1".into(), 443)));
    }

    #[test]
    fn socks_reply_codes_are_named() {
        assert_eq!(socks_reply_reason(0x05), "connection refused");
    }
}
