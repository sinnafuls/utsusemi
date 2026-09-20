//! On-disk configuration, saved profiles, and runtime state paths.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::endpoint::Endpoint;

/// `%APPDATA%\utsusemi` on Windows, `~/.config/utsusemi` elsewhere.
/// `UTSUSEMI_HOME` overrides it, for portable installs and testing.
pub fn home_dir() -> PathBuf {
    if let Some(custom) = std::env::var_os("UTSUSEMI_HOME") {
        return PathBuf::from(custom);
    }
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("utsusemi")
}

pub fn config_path() -> PathBuf {
    home_dir().join("config.toml")
}

pub fn state_path() -> PathBuf {
    home_dir().join("state.json")
}

pub fn log_path() -> PathBuf {
    home_dir().join("utsusemi.log")
}

fn default_http_listen() -> String {
    "127.0.0.1:18080".to_string()
}

fn default_socks_listen() -> String {
    "127.0.0.1:11080".to_string()
}

fn default_bypass() -> String {
    // Keep loopback, link-local and RFC1918 traffic off the proxy, otherwise
    // printers, NAS boxes and localhost dev servers break the moment you connect.
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;\
     172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;\
     172.30.*;172.31.*;192.168.*;169.254.*;*.local;<local>"
        .to_string()
}

const fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    /// Local HTTP/CONNECT proxy listener.
    #[serde(default = "default_http_listen")]
    pub http: String,
    /// Local SOCKS5 listener.
    #[serde(default = "default_socks_listen")]
    pub socks5: String,
}

impl Default for ListenConfig {
    fn default() -> Self {
        ListenConfig {
            http: default_http_listen(),
            socks5: default_socks_listen(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemProxyConfig {
    /// Point the Windows system proxy at our local listener while connected.
    #[serde(default = "yes")]
    pub enable: bool,
    /// WinINET `ProxyOverride` list.
    #[serde(default = "default_bypass")]
    pub bypass: String,
    /// Also set the machine-wide WinHTTP proxy (`netsh winhttp`). Needs admin
    /// and affects services, so it is off unless asked for.
    #[serde(default)]
    pub winhttp: bool,
}

impl Default for SystemProxyConfig {
    fn default() -> Self {
        SystemProxyConfig {
            enable: true,
            bypass: default_bypass(),
            winhttp: false,
        }
    }
}

/// A saved endpoint the user can connect to by name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Full endpoint string, exactly as pasted from the Endpoint Generator.
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Webshare API key from https://dashboard.webshare.io/userapi/keys
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Profile used when `connect` is given no argument.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub listen: ListenConfig,
    #[serde(default)]
    pub system_proxy: SystemProxyConfig,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl Config {
    pub fn load() -> Result<Config> {
        Self::load_from(&config_path())
    }

    pub fn load_from(path: &Path) -> Result<Config> {
        match fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .with_context(|| format!("parsing config at {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("reading config at {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let text = toml::to_string_pretty(self).context("serialising config")?;
        write_private(&path, text.as_bytes())
            .with_context(|| format!("writing config to {}", path.display()))
    }

    /// Resolve a connect argument: either a literal endpoint or a profile name.
    pub fn resolve(&self, arg: Option<&str>) -> Result<(Option<String>, Endpoint)> {
        let name = match arg {
            Some(a) => a,
            None => self.default_profile.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "no endpoint given and no default profile set.\n\
                     Paste one:  utsusemi connect \"user-de-rotate:pass@p.webshare.io:80\"\n\
                     Or save one: utsusemi profile add <name> \"<endpoint>\""
                )
            })?,
        };

        if let Some(profile) = self.profiles.get(name) {
            let endpoint = profile
                .url
                .parse()
                .with_context(|| format!("profile `{name}` has an invalid endpoint"))?;
            return Ok((Some(name.to_string()), endpoint));
        }

        let endpoint: Endpoint = name.parse().with_context(|| {
            format!("`{name}` is neither a saved profile nor a valid proxy endpoint")
        })?;
        Ok((None, endpoint))
    }
}

/// Write a file with an owner-only ACL where the platform supports it.
/// Credentials live in these files, so they must not be world readable.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
