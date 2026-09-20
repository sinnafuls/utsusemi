//! Local HTTP proxy listener: CONNECT tunnels plus absolute-form forwarding.
//!
//! This is the listener the Windows system proxy points at. It must accept
//! everything WinINET throws at it, which means both `CONNECT host:443` for
//! TLS and old-style `GET http://host/path` for plain HTTP.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::{serve_tunnel, Dialer, ExitPolicy, Relay};
use crate::endpoint::Scheme;
use crate::upstream::{self, split_authority, Tunnel, UpstreamError};

/// Client request heads larger than this are a client bug or an attack.
const MAX_HEAD: usize = 32 * 1024;

pub async fn serve(listener: TcpListener, relay: Relay) -> anyhow::Result<()> {
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // EMFILE and friends are transient; a dead listener is not.
                tracing::warn!("http accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let relay = relay.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(socket, relay).await {
                tracing::debug!("http connection from {peer} ended: {e}");
            }
        });
    }
}

async fn handle(mut client: TcpStream, relay: Relay) -> std::io::Result<()> {
    client.set_nodelay(true)?;

    let (head, body_prefix) = match read_head(&mut client).await? {
        Some(parts) => parts,
        // Client opened and closed without sending anything: a port probe.
        None => return Ok(()),
    };

    let Some(request) = Request::parse(&head) else {
        relay
            .stats
            .fail("client sent something that is not an HTTP proxy request");
        return respond(
            &mut client,
            400,
            "Bad Request",
            "This is the utsusemi proxy listener, not a web server.\n\
             Point your application's HTTP proxy setting at this address instead.\n",
        )
        .await;
    };

    let upstream_endpoint = relay.upstream.get();

    if request.method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = split_authority(&request.target, 443) else {
            relay
                .stats
                .fail(format!("malformed CONNECT target `{}`", request.target));
            return respond(&mut client, 400, "Bad Request", "Malformed CONNECT target.\n").await;
        };

        let tunnel = match upstream::connect_through(&upstream_endpoint, &host, port).await {
            Ok(t) => t,
            Err(e) => {
                relay.stats.fail(format!("CONNECT {host}:{port}: {e}"));
                tracing::warn!("CONNECT {host}:{port} failed: {e}");
                let (code, reason) = status_for(&e);
                return respond(&mut client, code, reason, &explain(&e)).await;
            }
        };

        client
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;

        // Anything the client pipelined after the CONNECT head belongs to the
        // tunnel, and doubles as the payload replayed if this exit turns out
        // to be a black hole.
        let target = format!("{host}:{port}");
        serve_tunnel(
            client,
            tunnel,
            relay.stats.clone(),
            &target,
            body_prefix,
            ExitPolicy::default(),
            Dialer::Tunnel {
                upstream: relay.upstream.clone(),
                host: host.into(),
                port,
            },
        )
        .await;
        return Ok(());
    }

    // Absolute-form plain HTTP: GET http://host/path HTTP/1.1
    let Some((host, port, path)) = parse_absolute_uri(&request.target) else {
        relay.stats.fail(format!(
            "request target `{}` is neither CONNECT nor absolute-form",
            request.target
        ));
        return respond(
            &mut client,
            400,
            "Bad Request",
            "This is the utsusemi proxy listener, not a web server.\n\
             Only CONNECT and absolute-form requests are served here.\n",
        )
        .await;
    };

    // An HTTP upstream speaks absolute-form natively, so hand the request
    // straight over with our credentials attached. A SOCKS5 upstream cannot,
    // so tunnel to the origin and send an ordinary origin-form request.
    let (tunnel, head_out) = match upstream_endpoint.scheme {
        Scheme::Http => {
            let stream = match upstream::dial_raw(&upstream_endpoint).await {
                Ok(s) => s,
                Err(e) => {
                    relay
                        .stats
                        .fail(format!("upstream dial for {host}:{port}: {e}"));
                    tracing::warn!("upstream dial for {host}:{port} failed: {e}");
                    let (code, reason) = status_for(&e);
                    return respond(&mut client, code, reason, &explain(&e)).await;
                }
            };
            let head_out = request.rewrite(
                &request.target,
                upstream_endpoint.basic_auth_header().as_deref(),
            );
            (
                Tunnel {
                    stream,
                    prelude: Vec::new(),
                },
                head_out,
            )
        }
        Scheme::Socks5 => {
            let tunnel = match upstream::connect_through(&upstream_endpoint, &host, port).await {
                Ok(t) => t,
                Err(e) => {
                    relay.stats.fail(format!("tunnel to {host}:{port}: {e}"));
                    tracing::warn!("tunnel to {host}:{port} failed: {e}");
                    let (code, reason) = status_for(&e);
                    return respond(&mut client, code, reason, &explain(&e)).await;
                }
            };
            (tunnel, request.rewrite(&path, None))
        }
    };

    let mut payload = head_out.into_bytes();
    payload.extend_from_slice(&body_prefix);

    let target = format!("{host}:{port}");
    let dialer = match upstream_endpoint.scheme {
        // The replayed payload is the whole absolute-form request, so a raw
        // connection to the backbone is all a replacement needs; only SOCKS5
        // has to redo a handshake.
        Scheme::Http => Dialer::Raw {
            upstream: relay.upstream.clone(),
        },
        Scheme::Socks5 => Dialer::Tunnel {
            upstream: relay.upstream.clone(),
            host: host.into(),
            port,
        },
    };
    // Replaying is only safe for methods that may be sent twice. A POST that
    // a silent exit had already forwarded must not be duplicated.
    let policy = if is_replayable(request.method) {
        ExitPolicy::default()
    } else {
        ExitPolicy::single()
    };

    serve_tunnel(
        client,
        tunnel,
        relay.stats.clone(),
        &target,
        payload,
        policy,
        dialer,
    )
    .await;
    Ok(())
}

/// Methods RFC 9110 defines as safe or idempotent, and therefore harmless to
/// send to a second exit when the first one swallowed them.
fn is_replayable(method: &str) -> bool {
    ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"]
        .iter()
        .any(|m| method.eq_ignore_ascii_case(m))
}

/// Read the request head, returning it plus any bytes that followed it.
/// `None` means the client closed before sending a complete head.
async fn read_head(client: &mut TcpStream) -> std::io::Result<Option<(String, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = upstream::find_header_end(&buf) {
            let rest = buf.split_off(end);
            return Ok(Some((String::from_utf8_lossy(&buf).into_owned(), rest)));
        }
        if buf.len() > MAX_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head exceeded 32 KiB",
            ));
        }
    }
}

struct Request<'a> {
    method: &'a str,
    target: String,
    version: &'a str,
    header_lines: Vec<&'a str>,
}

impl<'a> Request<'a> {
    fn parse(head: &'a str) -> Option<Request<'a>> {
        let mut lines = head.split("\r\n");
        let request_line = lines.next()?;
        let mut parts = request_line.split(' ');
        let method = parts.next()?;
        let target = parts.next()?.to_string();
        let version = parts.next().unwrap_or("HTTP/1.1");
        if method.is_empty() || target.is_empty() || !version.starts_with("HTTP/") {
            return None;
        }
        let header_lines = lines.filter(|l| !l.is_empty()).collect();
        Some(Request {
            method,
            target,
            version,
            header_lines,
        })
    }

    /// Re-emit the head with a new request target, dropping hop-by-hop proxy
    /// headers and optionally injecting our upstream credentials.
    fn rewrite(&self, target: &str, proxy_auth: Option<&str>) -> String {
        let mut out = format!("{} {} {}\r\n", self.method, target, self.version);
        for line in &self.header_lines {
            let name = line.split(':').next().unwrap_or("").trim();
            if name.eq_ignore_ascii_case("proxy-authorization")
                || name.eq_ignore_ascii_case("proxy-connection")
            {
                continue;
            }
            out.push_str(line);
            out.push_str("\r\n");
        }
        if let Some(auth) = proxy_auth {
            out.push_str("Proxy-Authorization: ");
            out.push_str(auth);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out
    }
}

/// Split `http://host:port/path?query` without resolving anything.
fn parse_absolute_uri(target: &str) -> Option<(String, u16, String)> {
    let (scheme, rest) = target.split_once("://")?;
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..split];
    let path = if split == rest.len() {
        "/".to_string()
    } else {
        rest[split..].to_string()
    };
    // Userinfo in a proxied request target is legal but never ours to forward.
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = split_authority(authority, default_port)?;
    Some((host, port, path))
}

fn status_for(e: &UpstreamError) -> (u16, &'static str) {
    match e {
        UpstreamError::Auth { .. } => (502, "Bad Gateway"),
        UpstreamError::Dial { .. } => (502, "Bad Gateway"),
        UpstreamError::Refused { .. } => (502, "Bad Gateway"),
        UpstreamError::Protocol(_) => (502, "Bad Gateway"),
        UpstreamError::Io(_) => (502, "Bad Gateway"),
    }
}

/// Turn an upstream failure into something a human reads in a browser tab and
/// immediately knows what to do about.
fn explain(e: &UpstreamError) -> String {
    match e {
        UpstreamError::Auth { reason } => format!(
            "Webshare rejected the proxy credentials{}\n\
             Check the endpoint's username and password, and that the country \
             you are targeting exists in your proxy list:\n\
             utsusemi status && utsusemi connect --country <code>\n",
            match reason {
                Some(r) => format!(": {r}"),
                None => ".".to_string(),
            }
        ),
        UpstreamError::Dial { addr, source } => format!(
            "Could not reach the Webshare backbone at {addr}: {source}\n\
             Check your internet connection, or try the gateway IP if your \
             network blocks p.webshare.io.\n"
        ),
        UpstreamError::Refused { target, reason } => {
            format!("Webshare refused to connect to {target}: {reason}\n")
        }
        other => format!("Upstream proxy error: {other}\n"),
    }
}

async fn respond(
    client: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    );
    client.write_all(response.as_bytes()).await?;
    client.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_absolute_uris() {
        assert_eq!(
            parse_absolute_uri("http://example.com/a?b=1"),
            Some(("example.com".into(), 80, "/a?b=1".into()))
        );
        assert_eq!(
            parse_absolute_uri("http://example.com:8080"),
            Some(("example.com".into(), 8080, "/".into()))
        );
        assert_eq!(parse_absolute_uri("/just/a/path"), None);
    }

    #[test]
    fn rewrite_strips_proxy_headers_and_injects_auth() {
        let head = "GET http://example.com/ HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Proxy-Connection: keep-alive\r\n\
                    Proxy-Authorization: Basic old\r\n\r\n";
        let request = Request::parse(head).unwrap();
        let out = request.rewrite("/", Some("Basic new"));
        assert!(out.starts_with("GET / HTTP/1.1\r\n"));
        assert!(out.contains("Host: example.com"));
        assert!(!out.contains("Proxy-Connection"));
        assert!(!out.contains("Basic old"));
        assert!(out.contains("Proxy-Authorization: Basic new"));
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn rejects_non_proxy_requests() {
        assert!(Request::parse("GARBAGE\r\n\r\n").is_none());
        let request = Request::parse("GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(parse_absolute_uri(&request.target).is_none());
    }
}
