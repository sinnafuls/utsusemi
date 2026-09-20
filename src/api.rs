//! Webshare REST API client (https://apidocs.webshare.io).
//!
//! Only the read-only endpoints needed to build an endpoint and describe the
//! account. Nothing here is required to use the relay: pasting an endpoint
//! string works without an API key at all.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::endpoint::{Endpoint, Geo, Scheme, Session, WebshareUser};

pub const API_BASE: &str = "https://proxy.webshare.io/api/v2";
/// Backbone host for every rotating/sticky residential connection.
pub const BACKBONE_HOST: &str = "p.webshare.io";
pub const BACKBONE_HTTP_PORT: u16 = 80;

const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Account {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
}

/// The account's default proxy credentials, so an endpoint can be built
/// without copying anything out of the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub state: String,
    /// Countries present in the proxy list, by proxy count. The backbone's
    /// `-de` style country filter only picks from these, so a country missing
    /// here is a 407 waiting to happen.
    #[serde(default)]
    pub countries: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Subscription {
    #[serde(default)]
    pub plan: Option<i64>,
    #[serde(default)]
    pub term: String,
    #[serde(default)]
    pub end_date: Option<String>,
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub throttled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Plan {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub status: String,
    /// Bandwidth allowance in GB; `0` means unlimited.
    #[serde(default)]
    pub bandwidth_limit: f64,
    #[serde(default)]
    pub proxy_type: String,
    #[serde(default)]
    pub proxy_subtype: String,
    #[serde(default)]
    pub proxy_count: i64,
}

impl Plan {
    pub fn describe(&self) -> String {
        let kind = match (self.proxy_type.as_str(), self.proxy_subtype.as_str()) {
            ("", "") => "unknown".to_string(),
            (t, "") => t.to_string(),
            (t, s) => format!("{t}/{s}"),
        };
        let bandwidth = if self.bandwidth_limit <= 0.0 {
            "unlimited bandwidth".to_string()
        } else {
            format!("{} GB", self.bandwidth_limit)
        };
        format!("{kind}, {bandwidth}")
    }

    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// Rotating residential plans are the only ones that serve the 80M pool,
    /// and they are reached through a username the proxy-list plan does not
    /// share.
    pub fn is_residential(&self) -> bool {
        self.proxy_subtype == "residential"
    }
}

/// Paginated list envelope used by most list endpoints.
#[derive(Deserialize)]
struct Page<T> {
    results: Vec<T>,
}

pub struct Client {
    key: String,
}

impl Client {
    pub fn new(key: impl Into<String>) -> Self {
        Client { key: key.into() }
    }

    fn get_value(&self, path: &str) -> Result<Option<serde_json::Value>> {
        let url = format!("{API_BASE}{path}");
        let response = ureq::get(&url)
            .set("Authorization", &format!("Token {}", self.key))
            .set("Accept", "application/json")
            .timeout(TIMEOUT)
            .call();

        match response {
            Ok(resp) => Ok(Some(resp.into_json().with_context(|| {
                format!("Webshare returned a response for {path} that is not JSON")
            })?)),
            // 404 is meaningful for optional resources (free accounts have no
            // subscription), so the caller decides what to do about it.
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Err(anyhow::anyhow!("{}", describe_status(code, &body)))
            }
            Err(ureq::Error::Transport(t)) => Err(anyhow::anyhow!(
                "could not reach the Webshare API ({t}). Check your internet connection; \
                 if a proxy is active, note that API calls do not go through it."
            )),
        }
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let value = self
            .get_value(path)?
            .ok_or_else(|| anyhow::anyhow!("Webshare has no resource at {path}"))?;
        serde_json::from_value(value)
            .with_context(|| format!("unexpected response shape from {path}"))
    }

    /// Fetch a resource that may be returned either bare or wrapped in a
    /// pagination envelope, and take the first item.
    fn get_first<T: DeserializeOwned>(&self, path: &str, empty_msg: &str) -> Result<T> {
        let value = self
            .get_value(path)?
            .ok_or_else(|| anyhow::anyhow!("Webshare has no resource at {path}"))?;

        if value.get("results").is_some() {
            let page: Page<T> = serde_json::from_value(value)
                .with_context(|| format!("unexpected list shape from {path}"))?;
            return page
                .results
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("{empty_msg}"));
        }
        serde_json::from_value(value)
            .with_context(|| format!("unexpected response shape from {path}"))
    }

    pub fn account(&self) -> Result<Account> {
        self.get("/profile/")
    }

    pub fn proxy_config(&self) -> Result<ProxyConfig> {
        self.get_first(
            "/proxy/config/",
            "this Webshare account has no proxy configuration yet. \
             Open the dashboard once to provision it",
        )
    }

    /// Countries the account's proxy list actually contains, keyed by the
    /// uppercase ISO code Webshare reports.
    pub fn proxy_countries(&self) -> Result<BTreeMap<String, u64>> {
        Ok(self.proxy_config()?.countries)
    }

    pub fn subscription(&self) -> Result<Option<Subscription>> {
        match self.get_value("/subscription/")? {
            None => Ok(None),
            Some(value) => Ok(Some(
                serde_json::from_value(value).context("unexpected subscription shape")?,
            )),
        }
    }

    /// The plan currently attached to the subscription, when there is one.
    pub fn active_plan(&self) -> Result<Option<Plan>> {
        let Some(subscription) = self.subscription()? else {
            return Ok(None);
        };
        let Some(plan_id) = subscription.plan else {
            return Ok(None);
        };
        match self.get_value(&format!("/subscription/plan/{plan_id}/"))? {
            None => Ok(None),
            Some(value) => Ok(Some(
                serde_json::from_value(value).context("unexpected plan shape")?,
            )),
        }
    }

    /// Every plan on the account, active or not. `/subscription/` only ever
    /// names one of them, so an account holding both a proxy-list plan and a
    /// rotating residential plan is invisible without this.
    pub fn plans(&self) -> Result<Vec<Plan>> {
        let page: Page<Plan> = self.get("/subscription/plan/")?;
        Ok(page.results)
    }

    /// Whether the account can reach the rotating residential pool.
    pub fn has_active_residential(&self) -> Result<bool> {
        Ok(self
            .plans()?
            .iter()
            .any(|p| p.is_active() && p.is_residential()))
    }

    /// Assemble a backbone endpoint from the account credentials plus the
    /// requested targeting. This is what makes `utsusemi connect --country de
    /// --rotate` work with nothing pasted. `residential` addresses the
    /// rotating residential pool instead of the account's own proxy list.
    pub fn default_endpoint(
        &self,
        countries: &[String],
        geo: Option<Geo>,
        session: Session,
        residential: bool,
    ) -> Result<Endpoint> {
        let config = self.proxy_config()?;
        let user = WebshareUser {
            base: config.username,
            countries: countries.iter().map(|c| c.to_ascii_lowercase()).collect(),
            geo,
            session,
        };
        let user = if residential {
            user.to_residential()
        } else {
            user
        };

        Ok(Endpoint {
            scheme: Scheme::Http,
            host: BACKBONE_HOST.to_string(),
            port: BACKBONE_HTTP_PORT,
            username: Some(user.build()),
            password: Some(config.password),
        })
    }
}

fn describe_status(code: u16, body: &str) -> String {
    let detail = {
        let trimmed = body.trim();
        if trimmed.len() > 300 {
            format!("{}…", &trimmed[..300])
        } else {
            trimmed.to_string()
        }
    };
    match code {
        401 => "Webshare rejected the API key. Generate a new one at \
                https://dashboard.webshare.io/userapi/keys and run `utsusemi login <key>`."
            .to_string(),
        403 => format!(
            "Webshare refused this request (403). The plan may not include this feature. {detail}"
        ),
        429 => "Webshare rate limit hit. Wait 60 seconds and try again.".to_string(),
        _ => format!("Webshare API error {code}: {detail}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_description_handles_unlimited() {
        let plan = Plan {
            proxy_type: "shared".into(),
            proxy_subtype: "residential".into(),
            bandwidth_limit: 0.0,
            ..Default::default()
        };
        assert_eq!(plan.describe(), "shared/residential, unlimited bandwidth");
    }

    #[test]
    fn status_401_is_actionable() {
        let msg = describe_status(401, "");
        assert!(msg.contains("utsusemi login"));
    }
}
