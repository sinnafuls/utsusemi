//! Utsusemi routes a Windows desktop through a Webshare residential proxy.
//!
//! A local relay listens on loopback and forwards every connection to the
//! Webshare backbone, attaching the proxy credentials on the way out. The
//! Windows system proxy is then pointed at that loopback listener.
//!
//! The relay exists because WinINET has nowhere to store proxy credentials.
//! Without it, every application would prompt for a password or fail with a
//! 407 response.

pub mod api;
pub mod config;
pub mod control;
pub mod endpoint;
pub mod ipcheck;
pub mod relay;
pub mod state;
pub mod sysproxy;
pub mod upstream;

pub use endpoint::{Endpoint, Scheme, Session, WebshareUser};
