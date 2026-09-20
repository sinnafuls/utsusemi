//! Windows system proxy control (WinINET, optionally WinHTTP).
//!
//! The original settings are snapshotted to disk *before* the first change, so
//! a crash, a hard reboot or a `TerminateProcess` still leaves a later
//! `utsusemi disconnect` able to put the machine back exactly as it was.

use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A snapshot of the user's WinINET proxy configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxySnapshot {
    pub enabled: bool,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub bypass: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pac_url: Option<String>,
    /// Raw `netsh winhttp show proxy` output captured before we changed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winhttp: Option<String>,
}

pub fn backup_path() -> PathBuf {
    crate::config::home_dir().join("sysproxy-backup.json")
}

#[cfg(windows)]
mod imp {
    use super::*;

    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    const SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    /// Do not flash a console window when shelling out from a detached relay.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn open(write: bool) -> Result<RegKey> {
        let access = if write { KEY_READ | KEY_WRITE } else { KEY_READ };
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(SETTINGS_KEY, access)
            .map_err(|e| anyhow::anyhow!("opening HKCU\\{SETTINGS_KEY}: {e}"))
    }

    /// Absent values are normal, not errors: a machine that has never had a
    /// proxy configured simply has no `ProxyServer`.
    fn read_string(key: &RegKey, name: &str) -> Option<String> {
        key.get_value::<String, _>(name).ok().filter(|s| !s.is_empty())
    }

    pub fn current() -> Result<ProxySnapshot> {
        let key = open(false)?;
        Ok(ProxySnapshot {
            enabled: key.get_value::<u32, _>("ProxyEnable").unwrap_or(0) != 0,
            server: read_string(&key, "ProxyServer").unwrap_or_default(),
            bypass: read_string(&key, "ProxyOverride").unwrap_or_default(),
            pac_url: read_string(&key, "AutoConfigURL"),
            winhttp: None,
        })
    }

    pub fn apply(server: &str, bypass: &str, also_winhttp: bool) -> Result<()> {
        // Never overwrite an existing backup: `switch` re-applies while
        // connected, and clobbering would save *our* settings as the original.
        let backup = backup_path();
        if !backup.exists() {
            let mut snapshot = current()?;
            if also_winhttp {
                snapshot.winhttp = Some(netsh(&["winhttp", "show", "proxy"]).unwrap_or_default());
            }
            let bytes = serde_json::to_vec_pretty(&snapshot)?;
            crate::config::write_private(&backup, &bytes)?;
        }

        let key = open(true)?;
        key.set_value("ProxyEnable", &1u32)?;
        key.set_value("ProxyServer", &server.to_string())?;
        key.set_value("ProxyOverride", &bypass.to_string())?;

        // A PAC script wins over the manual proxy, so leaving AutoConfigURL in
        // place would silently bypass the relay entirely. It is in the backup.
        if key.get_value::<String, _>("AutoConfigURL").is_ok() {
            key.delete_value("AutoConfigURL")
                .map_err(|e| anyhow::anyhow!("clearing the PAC script URL: {e}"))?;
        }

        notify_changed();

        if also_winhttp {
            netsh(&[
                "winhttp",
                "set",
                "proxy",
                &format!("proxy-server={server}"),
                &format!("bypass-list={bypass}"),
            ])
            .map_err(|e| {
                anyhow::anyhow!(
                    "WinINET proxy is set, but the machine-wide WinHTTP proxy failed: {e}\n\
                     WinHTTP mode needs an elevated shell. Run utsusemi as Administrator \
                     or drop --winhttp."
                )
            })?;
        }
        Ok(())
    }

    pub fn restore() -> Result<bool> {
        let backup = backup_path();
        if !backup.exists() {
            return Ok(false);
        }
        let snapshot: ProxySnapshot = serde_json::from_slice(&std::fs::read(&backup)?)?;
        let key = open(true)?;

        key.set_value("ProxyEnable", &u32::from(snapshot.enabled))?;
        restore_value(&key, "ProxyServer", &snapshot.server);
        restore_value(&key, "ProxyOverride", &snapshot.bypass);
        match &snapshot.pac_url {
            Some(url) => {
                let _ = key.set_value("AutoConfigURL", url);
            }
            None => {
                let _ = key.delete_value("AutoConfigURL");
            }
        }

        if snapshot.winhttp.is_some() {
            if let Err(e) = netsh(&["winhttp", "reset", "proxy"]) {
                tracing::warn!("could not reset the WinHTTP proxy: {e}");
            }
        }

        notify_changed();
        std::fs::remove_file(&backup)?;
        Ok(true)
    }

    /// Writing an empty string would leave a stray empty value behind, so an
    /// originally-absent value is deleted instead.
    fn restore_value(key: &RegKey, name: &str, value: &str) {
        let result = if value.is_empty() {
            key.delete_value(name).or(Ok(()))
        } else {
            key.set_value(name, &value.to_string())
        };
        if let Err(e) = result {
            tracing::warn!("could not restore {name}: {e}");
        }
    }

    /// Tell running processes to re-read the settings. Best effort: the
    /// registry write is what actually matters, and apps that miss the
    /// broadcast pick it up on their next connection anyway.
    fn notify_changed() {
        use windows_sys::Win32::Networking::WinInet::{
            InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
        };
        for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
            let ok = unsafe {
                InternetSetOptionW(std::ptr::null(), option, std::ptr::null(), 0)
            };
            if ok == 0 {
                tracing::warn!(
                    "InternetSetOptionW({option}) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    fn netsh(args: &[&str]) -> Result<String> {
        use std::os::windows::process::CommandExt;

        let output = std::process::Command::new("netsh")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| anyhow::anyhow!("running netsh: {e}"))?;
        if !output.status.success() {
            anyhow::bail!(
                "netsh {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn current() -> Result<ProxySnapshot> {
        Ok(ProxySnapshot::default())
    }

    pub fn apply(_server: &str, _bypass: &str, _also_winhttp: bool) -> Result<()> {
        anyhow::bail!(
            "system-wide proxy integration is Windows-only for now.\n\
             Use `utsusemi connect --no-system-proxy` and point apps at the local \
             listener with HTTP_PROXY/HTTPS_PROXY, or `utsusemi run -- <command>`."
        )
    }

    pub fn restore() -> Result<bool> {
        Ok(false)
    }
}

/// Read the current settings.
pub fn current() -> Result<ProxySnapshot> {
    imp::current()
}

/// Back up the current settings, then point the system proxy at `server`.
pub fn apply(server: &str, bypass: &str, also_winhttp: bool) -> Result<()> {
    imp::apply(server, bypass, also_winhttp)
}

/// Restore from the on-disk backup. Returns false when there was nothing to do.
pub fn restore() -> Result<bool> {
    imp::restore()
}
