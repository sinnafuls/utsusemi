//! Egress identity checks: what the internet actually sees.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExitInfo {
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

impl ExitInfo {
    pub fn location(&self) -> String {
        let bits: Vec<&str> = [
            self.city.as_deref(),
            self.region.as_deref(),
            self.country.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect();

        if bits.is_empty() {
            "unknown location".to_string()
        } else {
            bits.join(", ")
        }
    }
}

#[derive(Deserialize)]
struct IpInfo {
    ip: String,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    org: Option<String>,
}

#[derive(Deserialize)]
struct IpApi {
    query: String,
    #[serde(default, rename = "countryCode")]
    country_code: Option<String>,
    #[serde(default, rename = "regionName")]
    region_name: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default, rename = "as")]
    autonomous_system: Option<String>,
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(TIMEOUT).build()
}

/// Look up the egress identity through a local HTTP proxy (`host:port`).
pub fn via_http_proxy(proxy_addr: &str) -> Result<ExitInfo> {
    let proxy = ureq::Proxy::new(format!("http://{proxy_addr}"))
        .with_context(|| format!("`{proxy_addr}` is not a usable proxy address"))?;
    let agent = ureq::AgentBuilder::new()
        .timeout(TIMEOUT)
        .proxy(proxy)
        .build();
    lookup(&agent)
}

/// Look up the egress identity without a proxy.
pub fn direct() -> Result<ExitInfo> {
    lookup(&agent())
}

/// Two providers because one of them is always having a bad day, and a proxy
/// tool that cannot tell you your exit IP is useless.
fn lookup(agent: &ureq::Agent) -> Result<ExitInfo> {
    let primary = match agent.get("https://ipinfo.io/json").call() {
        Ok(resp) => match resp.into_json::<IpInfo>() {
            Ok(info) => {
                return Ok(ExitInfo {
                    ip: info.ip,
                    country: info.country,
                    region: info.region,
                    city: info.city,
                    org: info.org,
                })
            }
            Err(e) => format!("ipinfo.io returned unreadable JSON: {e}"),
        },
        Err(e) => format!("ipinfo.io: {e}"),
    };

    let fallback = match agent.get("http://ip-api.com/json/").call() {
        Ok(resp) => match resp.into_json::<IpApi>() {
            Ok(info) => {
                return Ok(ExitInfo {
                    ip: info.query,
                    country: info.country_code,
                    region: info.region_name,
                    city: info.city,
                    org: info.autonomous_system,
                })
            }
            Err(e) => format!("ip-api.com returned unreadable JSON: {e}"),
        },
        Err(e) => format!("ip-api.com: {e}"),
    };

    anyhow::bail!("could not determine the exit IP.\n  {primary}\n  {fallback}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_skips_missing_fields() {
        let info = ExitInfo {
            ip: "1.2.3.4".into(),
            country: Some("DE".into()),
            ..Default::default()
        };
        assert_eq!(info.location(), "DE");
        assert_eq!(ExitInfo::default().location(), "unknown location");
    }
}
