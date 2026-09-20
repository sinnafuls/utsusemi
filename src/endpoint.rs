//! Parsing and construction of Webshare proxy endpoints.
//!
//! Two layers live here. `Endpoint` is a generic upstream proxy (scheme, host,
//! port, credentials) and is what the relay dials. `WebshareUser` is the
//! Webshare backbone username grammar, `{user}-{country..}-{geo}-{session}`,
//! which is where geo targeting and session stickiness actually live. Parsing
//! it lets us re-target or re-roll a session without asking the user to paste
//! a fresh endpoint.

use std::fmt;
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// Transport spoken to the upstream proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Socks5,
}

impl Scheme {
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Socks5 => 1080,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Socks5 => "socks5",
        }
    }
}

impl FromStr for Scheme {
    type Err = EndpointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "http" | "https" => Ok(Scheme::Http),
            "socks5" | "socks5h" | "socks" => Ok(Scheme::Socks5),
            other => Err(EndpointError::UnknownScheme(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("unknown proxy scheme `{0}` (expected http or socks5)")]
    UnknownScheme(String),
    #[error("endpoint is missing a host")]
    MissingHost,
    #[error("invalid port `{0}`")]
    BadPort(String),
    #[error("endpoint is empty")]
    Empty,
}

/// A fully resolved upstream proxy the relay can dial.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Endpoint {
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn credentials(&self) -> Option<(&str, &str)> {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
            _ => None,
        }
    }

    /// `Proxy-Authorization` header value for HTTP upstreams, if credentialed.
    pub fn basic_auth_header(&self) -> Option<String> {
        self.credentials()
            .map(|(u, p)| format!("Basic {}", BASE64.encode(format!("{u}:{p}"))))
    }

    /// The Webshare username grammar, when the username parses as one.
    pub fn webshare_user(&self) -> Option<WebshareUser> {
        self.username.as_deref().map(WebshareUser::parse)
    }

    /// Replace the username, keeping everything else. Used by `rotate`/`target`.
    pub fn with_username(&self, username: String) -> Endpoint {
        Endpoint {
            username: Some(username),
            ..self.clone()
        }
    }

    /// Full URL including credentials. Only for handing to child processes.
    pub fn to_url(&self) -> String {
        match self.credentials() {
            Some((u, p)) => format!(
                "{}://{}:{}@{}:{}",
                self.scheme.as_str(),
                pct_encode(u),
                pct_encode(p),
                self.host,
                self.port
            ),
            None => format!("{}://{}:{}", self.scheme.as_str(), self.host, self.port),
        }
    }

    /// Safe-to-log form: username kept (it carries the geo targeting), password masked.
    pub fn redacted(&self) -> String {
        match (&self.username, &self.password) {
            (Some(u), Some(_)) => format!(
                "{}://{}:****@{}:{}",
                self.scheme.as_str(),
                u,
                self.host,
                self.port
            ),
            (Some(u), None) => format!("{}://{}@{}:{}", self.scheme.as_str(), u, self.host, self.port),
            _ => format!("{}://{}:{}", self.scheme.as_str(), self.host, self.port),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

impl FromStr for Endpoint {
    type Err = EndpointError;

    /// Accepts every shape Webshare hands out:
    ///
    /// ```text
    /// user-de-rotate:pass@p.webshare.io:80
    /// http://user:pass@p.webshare.io:80
    /// socks5://user:pass@p.webshare.io:1080
    /// p.webshare.io:80                       (IP authorization, no credentials)
    /// ```
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let raw = raw.trim().trim_matches('"').trim_matches('\'');
        if raw.is_empty() {
            return Err(EndpointError::Empty);
        }

        let (scheme, rest) = match raw.split_once("://") {
            Some((s, rest)) => (s.parse::<Scheme>()?, rest),
            None => (Scheme::Http, raw),
        };
        // Drop any trailing path/query Webshare's curl snippets include.
        let rest = rest.split(['/', '?', '#']).next().unwrap_or(rest);

        // Split on the *last* '@' so passwords containing '@' survive.
        let (userinfo, hostport) = match rest.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, rest),
        };

        let (host, port) = split_host_port(hostport)?;
        let port = match port {
            Some(p) => p,
            None => scheme.default_port(),
        };

        let (username, password) = match userinfo {
            None => (None, None),
            Some(info) => match info.split_once(':') {
                Some((u, p)) => (Some(pct_decode(u)), Some(pct_decode(p))),
                None => (Some(pct_decode(info)), None),
            },
        };

        Ok(Endpoint {
            scheme,
            host: host.to_string(),
            port,
            username: username.filter(|s| !s.is_empty()),
            password: password.filter(|s| !s.is_empty()),
        })
    }
}

fn split_host_port(s: &str) -> Result<(&str, Option<u16>), EndpointError> {
    if s.is_empty() {
        return Err(EndpointError::MissingHost);
    }
    // Bracketed IPv6 literal.
    if let Some(close) = s.strip_prefix('[').and_then(|r| r.find(']').map(|i| i + 1)) {
        let host = &s[1..close];
        let tail = &s[close + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p.parse().map_err(|_| EndpointError::BadPort(p.to_string()))?),
            None => None,
        };
        return Ok((host, port));
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port = port
                .parse()
                .map_err(|_| EndpointError::BadPort(port.to_string()))?;
            Ok((host, Some(port)))
        }
        _ => Ok((s, None)),
    }
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// Webshare username grammar

/// Geo filter encoded in the username. Webshare allows exactly one of these,
/// and `Asn` additionally cannot be combined with a country.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Geo {
    State(String),
    City(String),
    PostalCode(String),
    Asn(String),
}

impl Geo {
    fn token(&self) -> String {
        match self {
            Geo::State(v) => format!("state_{v}"),
            Geo::City(v) => format!("city_{v}"),
            Geo::PostalCode(v) => format!("postalcode_{v}"),
            Geo::Asn(v) => format!("asn_{v}"),
        }
    }

    fn parse(tok: &str) -> Option<Geo> {
        let (kind, value) = tok.split_once('_')?;
        let value = value.to_string();
        match kind {
            "state" => Some(Geo::State(value)),
            "city" => Some(Geo::City(value)),
            "postalcode" => Some(Geo::PostalCode(value)),
            "asn" => Some(Geo::Asn(value)),
            _ => None,
        }
    }
}

impl fmt::Display for Geo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (k, v) = match self {
            Geo::State(v) => ("state", v),
            Geo::City(v) => ("city", v),
            Geo::PostalCode(v) => ("zip", v),
            Geo::Asn(v) => ("asn", v),
        };
        write!(f, "{k}={v}")
    }
}

/// How the exit IP behaves across requests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Session {
    /// No session token: Webshare's account default.
    #[default]
    Default,
    /// New exit IP for every request.
    Rotate,
    /// Same exit IP for the dashboard-configured duration.
    Sticky(String),
}

/// A parsed Webshare backbone username.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebshareUser {
    pub base: String,
    pub countries: Vec<String>,
    pub geo: Option<Geo>,
    pub session: Session,
}

impl WebshareUser {
    /// Infallible: anything that is not recognised as a parameter stays part of
    /// the base username, so a non-Webshare username round-trips unchanged.
    pub fn parse(username: &str) -> WebshareUser {
        let mut parts = username.split('-');
        let base = parts.next().unwrap_or_default().to_string();

        let mut countries = Vec::new();
        let mut geo = None;
        let mut session = Session::Default;
        let mut base_extra: Vec<&str> = Vec::new();

        for tok in parts {
            if tok == "rotate" {
                session = Session::Rotate;
            } else if !tok.is_empty() && tok.chars().all(|c| c.is_ascii_digit()) {
                session = Session::Sticky(tok.to_string());
            } else if tok.len() == 2 && tok.chars().all(|c| c.is_ascii_alphabetic()) {
                countries.push(tok.to_ascii_lowercase());
            } else if let Some(g) = Geo::parse(tok) {
                geo = Some(g);
            } else {
                // Unrecognised: it belonged to the base username after all.
                base_extra.push(tok);
            }
        }

        let base = if base_extra.is_empty() {
            base
        } else {
            format!("{base}-{}", base_extra.join("-"))
        };

        WebshareUser {
            base,
            countries,
            geo,
            session,
        }
    }

    /// Re-emit in Webshare's documented order:
    /// `{username}-{country..}-{geo}-{session}`.
    pub fn build(&self) -> String {
        let mut s = self.base.clone();
        for c in &self.countries {
            s.push('-');
            s.push_str(c);
        }
        if let Some(g) = &self.geo {
            s.push('-');
            s.push_str(&g.token());
        }
        match &self.session {
            Session::Default => {}
            Session::Rotate => s.push_str("-rotate"),
            Session::Sticky(id) => {
                s.push('-');
                s.push_str(id);
            }
        }
        s
    }

    /// Human summary for status output, e.g. `de+fr+nl, city=munich, rotating`.
    pub fn summary(&self) -> String {
        let mut bits = Vec::new();
        bits.push(if self.countries.is_empty() {
            "worldwide".to_string()
        } else {
            self.countries.join("+")
        });
        if let Some(g) = &self.geo {
            bits.push(g.to_string());
        }
        bits.push(match &self.session {
            Session::Default => "account default".to_string(),
            Session::Rotate => "rotating".to_string(),
            Session::Sticky(id) => format!("sticky #{id}"),
        });
        bits.join(", ")
    }

    /// Fresh random sticky session id.
    pub fn new_sticky_id() -> String {
        use rand::Rng;
        rand::thread_rng().gen_range(1_000_000u32..9_999_999).to_string()
    }
}

impl fmt::Display for WebshareUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_credentialed_endpoint() {
        let e: Endpoint = "qvogitwfresidential-de-fr-nl-rotate:secret@p.webshare.io:80"
            .parse()
            .unwrap();
        assert_eq!(e.scheme, Scheme::Http);
        assert_eq!(e.host, "p.webshare.io");
        assert_eq!(e.port, 80);
        assert_eq!(e.username.as_deref(), Some("qvogitwfresidential-de-fr-nl-rotate"));
        assert_eq!(e.password.as_deref(), Some("secret"));
    }

    #[test]
    fn parses_socks5_and_defaults_port() {
        let e: Endpoint = "socks5://user:pw@p.webshare.io".parse().unwrap();
        assert_eq!(e.scheme, Scheme::Socks5);
        assert_eq!(e.port, 1080);
    }

    #[test]
    fn parses_ip_authorized_endpoint_without_credentials() {
        let e: Endpoint = "p.webshare.io:9999".parse().unwrap();
        assert!(e.credentials().is_none());
        assert_eq!(e.port, 9999);
    }

    #[test]
    fn strips_trailing_path_from_curl_snippets() {
        let e: Endpoint = "http://user:pw@p.webshare.io:80/".parse().unwrap();
        assert_eq!(e.host, "p.webshare.io");
        assert_eq!(e.port, 80);
    }

    #[test]
    fn password_may_contain_at_sign() {
        let e: Endpoint = "user:p@ss@p.webshare.io:80".parse().unwrap();
        assert_eq!(e.password.as_deref(), Some("p@ss"));
        assert_eq!(e.host, "p.webshare.io");
    }

    #[test]
    fn redaction_hides_password_but_keeps_targeting() {
        let e: Endpoint = "user-de-rotate:secret@p.webshare.io:80".parse().unwrap();
        let shown = e.redacted();
        assert!(!shown.contains("secret"));
        assert!(shown.contains("user-de-rotate"));
    }

    #[test]
    fn username_grammar_round_trips() {
        for raw in [
            "myuser",
            "myuser-us",
            "myuser-us-1234",
            "myuser-us-rotate",
            "myuser-de-fr-nl-rotate",
            "myuser-us-city_los_angeles-rotate",
            "myuser-us-state_arizona-rotate",
            "myuser-us-postalcode_77001-rotate",
            "myuser-asn_3-rotate",
        ] {
            assert_eq!(WebshareUser::parse(raw).build(), raw, "round trip {raw}");
        }
    }

    #[test]
    fn username_grammar_extracts_parameters() {
        let u = WebshareUser::parse("myuser-us-city_los_angeles-rotate");
        assert_eq!(u.base, "myuser");
        assert_eq!(u.countries, vec!["us"]);
        assert_eq!(u.geo, Some(Geo::City("los_angeles".into())));
        assert_eq!(u.session, Session::Rotate);
    }

    #[test]
    fn sticky_id_replaces_rotate() {
        let mut u = WebshareUser::parse("myuser-de-rotate");
        u.session = Session::Sticky("4242".into());
        assert_eq!(u.build(), "myuser-de-4242");
    }
}
