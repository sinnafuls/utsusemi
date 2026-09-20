//! Runtime state for a live connection, persisted so a second `utsusemi`
//! invocation can find, query and stop the running relay.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{state_path, write_private};
use crate::endpoint::Endpoint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunState {
    pub pid: u32,
    /// Control channel the CLI talks to (`127.0.0.1:<port>`).
    pub control: String,
    /// Shared secret authenticating control requests.
    pub token: String,
    pub http: String,
    pub socks5: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub endpoint: Endpoint,
    pub started_at: u64,
    /// Whether this run touched the Windows system proxy.
    #[serde(default)]
    pub system_proxy: bool,
}

impl RunState {
    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn uptime_secs(&self) -> u64 {
        Self::now().saturating_sub(self.started_at)
    }

    pub fn path() -> PathBuf {
        state_path()
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        let bytes = serde_json::to_vec_pretty(self).context("serialising run state")?;
        write_private(&path, &bytes).with_context(|| format!("writing {}", path.display()))
    }

    pub fn load() -> Result<Option<RunState>> {
        let path = Self::path();
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// State of a relay that is actually alive. Stale files (killed process,
    /// hard reboot) are cleared so the next connect starts clean.
    pub fn load_live() -> Result<Option<RunState>> {
        let Some(state) = Self::load()? else {
            return Ok(None);
        };
        if process_alive(state.pid) {
            Ok(Some(state))
        } else {
            let _ = Self::clear();
            Ok(None)
        }
    }

    pub fn clear() -> Result<()> {
        match fs::remove_file(Self::path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Is a process with this pid currently running?
#[cfg(windows)]
pub fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = GetExitCodeProcess(handle, &mut code) != 0;
        CloseHandle(handle);
        ok && code == STILL_ACTIVE as u32
    }
}

#[cfg(not(windows))]
pub fn process_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Terminate the relay process. Used only as a fallback when the control
/// channel is unreachable.
#[cfg(windows)]
pub fn kill(pid: u32) -> Result<()> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            anyhow::bail!("cannot open process {pid} to terminate it");
        }
        let ok = TerminateProcess(handle, 1) != 0;
        CloseHandle(handle);
        if !ok {
            anyhow::bail!("failed to terminate process {pid}");
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn kill(pid: u32) -> Result<()> {
    let status = std::process::Command::new("kill")
        .arg(pid.to_string())
        .status()?;
    anyhow::ensure!(status.success(), "failed to kill process {pid}");
    Ok(())
}
