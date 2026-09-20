//! Local SOCKS5 listener (RFC 1928, CONNECT only).
//!
//! No authentication: the listener is bound to loopback, and requiring a
//! password here would only break the clients that make SOCKS worth having.

use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::{splice, Relay};
use crate::upstream::{self, UpstreamError};

const VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

pub async fn serve(listener: TcpListener, relay: Relay) -> anyhow::Result<()> {
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("socks5 accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let relay = relay.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(socket, relay).await {
                tracing::debug!("socks5 connection from {peer} ended: {e}");
            }
        });
    }
}

async fn handle(mut client: TcpStream, relay: Relay) -> std::io::Result<()> {
    client.set_nodelay(true)?;

    // Greeting: VER NMETHODS METHODS...
    let mut prefix = [0u8; 2];
    client.read_exact(&mut prefix).await?;
    if prefix[0] != VERSION {
        relay.stats.fail(format!(
            "client on the SOCKS5 port does not speak SOCKS5 (version byte {:#04x})",
            prefix[0]
        ));
        // Not SOCKS5. Most often a browser pointed at the wrong port.
        return Ok(());
    }
    let mut methods = vec![0u8; prefix[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        client.write_all(&[VERSION, 0xFF]).await?;
        relay
            .stats
            .fail("client offered no SOCKS5 auth method this listener accepts");
        return Ok(());
    }
    client.write_all(&[VERSION, 0x00]).await?;

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    if head[0] != VERSION {
        relay
            .stats
            .fail(format!("bad SOCKS5 request version {:#04x}", head[0]));
        return Ok(());
    }
    let (host, port) = match read_target(&mut client, head[3]).await {
        Ok(target) => target,
        Err(e) => {
            relay.stats.fail(format!("unreadable SOCKS5 target: {e}"));
            let _ = reply(&mut client, REP_GENERAL_FAILURE).await;
            return Err(e);
        }
    };
    if head[1] != CMD_CONNECT {
        // BIND and UDP ASSOCIATE cannot be relayed through an HTTP backbone.
        relay.stats.fail(format!(
            "SOCKS5 command {:#04x} is not supported; only CONNECT is relayed",
            head[1]
        ));
        reply(&mut client, REP_CMD_NOT_SUPPORTED).await?;
        return Ok(());
    }

    let upstream_endpoint = relay.upstream.get();
    let tunnel = match upstream::connect_through(&upstream_endpoint, &host, port).await {
        Ok(t) => t,
        Err(e) => {
            relay
                .stats
                .fail(format!("socks5 connect {host}:{port}: {e}"));
            tracing::warn!("socks5 connect {host}:{port} failed: {e}");
            reply(&mut client, reply_code(&e)).await?;
            return Ok(());
        }
    };

    reply(&mut client, REP_SUCCESS).await?;
    splice(client, tunnel, relay.stats.clone()).await;
    Ok(())
}

/// Read DST.ADDR + DST.PORT. Domain names are returned verbatim: resolving
/// here would leak DNS locally instead of at the exit node.
async fn read_target(client: &mut TcpStream, atyp: u8) -> std::io::Result<(String, u16)> {
    let host = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF-8 hostname")
            })?
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 address type {other:#04x}"),
            ))
        }
    };

    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    Ok((host, u16::from_be_bytes(port)))
}

fn reply_code(e: &UpstreamError) -> u8 {
    match e {
        UpstreamError::Refused { .. } => REP_CONNECTION_REFUSED,
        UpstreamError::Dial { .. } => REP_HOST_UNREACHABLE,
        // There is no SOCKS5 code for "the proxy rejected *our* credentials",
        // so the client sees a general failure and the reason goes to the log.
        UpstreamError::Auth { .. } => REP_GENERAL_FAILURE,
        _ => REP_GENERAL_FAILURE,
    }
}

/// BND.ADDR/BND.PORT are meaningless for a relayed CONNECT; RFC 1928 permits
/// reporting 0.0.0.0:0 and every client in practice ignores it.
async fn reply(client: &mut TcpStream, code: u8) -> std::io::Result<()> {
    let response = [VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    client.write_all(&response).await?;
    client.flush().await
}
