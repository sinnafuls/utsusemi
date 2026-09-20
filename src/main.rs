//! Command line entry point.

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use tokio::net::TcpListener;

use utsusemi::config::{self, Config, Profile};
use utsusemi::control::{self, ControlContext, Reply, Request};
use utsusemi::endpoint::{Endpoint, Geo, Scheme, Session, WebshareUser};
use utsusemi::relay::{self, Relay};
use utsusemi::state::{self, RunState};
use utsusemi::upstream::UpstreamHandle;
use utsusemi::{api, ipcheck, sysproxy};

/// Set on the detached child so it knows to run the relay instead of
/// spawning another child.
const DAEMON_ENV: &str = "UTSUSEMI_DAEMON";

#[derive(Parser)]
#[command(
    name = "utsusemi",
    version,
    about = "Route your desktop through Webshare residential proxies",
    long_about = "Utsusemi runs a local proxy on loopback that forwards everything to the \
                  Webshare backbone with your credentials attached, then points the \
                  Windows system proxy at it.\n\n\
                  Windows cannot store proxy credentials itself, which is why pasting an \
                  authenticated proxy straight into Internet Options does not work.\n\n\
                  The name is the ninja substitution trick: what gets struck is a husk, \
                  not you."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the relay and route the desktop through it
    Connect(ConnectArgs),
    /// Stop the relay and restore the previous system proxy
    Disconnect,
    /// Show the live connection
    Status {
        /// Emit JSON instead of a human summary
        #[arg(long)]
        json: bool,
    },
    /// Get a new exit IP without dropping the connection
    Rotate,
    /// Re-point the running relay at a different endpoint or profile
    Switch {
        /// Endpoint string or saved profile name
        target: String,
        #[command(flatten)]
        targeting: Targeting,
    },
    /// Show the IP the internet currently sees
    Ip {
        /// Bypass the relay and report the real IP
        #[arg(long)]
        direct: bool,
    },
    /// Run one command through the relay without touching the system proxy
    Run {
        /// Program and arguments
        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },
    /// Manage saved endpoints
    #[command(subcommand)]
    Profile(ProfileCmd),
    /// Store a Webshare API key (https://dashboard.webshare.io/userapi/keys)
    Login {
        /// The API key; omitted reads it from stdin
        key: Option<String>,
    },
    /// Show the Webshare account behind the stored API key
    Account,
    /// Print an endpoint string built from your account credentials
    Endpoint {
        #[command(flatten)]
        targeting: Targeting,
        /// Emit a SOCKS5 endpoint instead of HTTP
        #[arg(long)]
        socks5: bool,
    },
    /// Print where configuration and logs live
    Where,
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Save an endpoint under a name
    Add {
        name: String,
        endpoint: String,
        /// Free-text reminder shown in `profile list`
        #[arg(long)]
        note: Option<String>,
    },
    /// List saved profiles
    #[command(alias = "ls")]
    List,
    /// Delete a saved profile
    #[command(alias = "remove")]
    Rm { name: String },
    /// Set the profile `connect` uses when given no argument
    Default { name: String },
}

/// Geo/session overrides layered on top of whatever endpoint was resolved.
#[derive(Args, Clone, Default)]
struct Targeting {
    /// Country to exit from; repeat for several (e.g. -c de -c fr)
    #[arg(short = 'c', long = "country", value_name = "CC")]
    countries: Vec<String>,
    /// City to exit from, e.g. munich
    #[arg(long, value_name = "NAME")]
    city: Option<String>,
    /// US state to exit from, e.g. arizona
    #[arg(long, value_name = "NAME")]
    state: Option<String>,
    /// US ZIP code to exit from
    #[arg(long, value_name = "CODE")]
    zip: Option<String>,
    /// ASN to exit from; cannot be combined with a country
    #[arg(long, value_name = "ASN")]
    asn: Option<String>,
    /// New exit IP on every request
    #[arg(long, conflicts_with = "sticky")]
    rotate: bool,
    /// Keep one exit IP; pass an id to reuse a session, omit to generate one
    #[arg(long, value_name = "ID", num_args = 0..=1, default_missing_value = "auto")]
    sticky: Option<String>,
}

impl Targeting {
    fn is_empty(&self) -> bool {
        self.countries.is_empty()
            && self.city.is_none()
            && self.state.is_none()
            && self.zip.is_none()
            && self.asn.is_none()
            && !self.rotate
            && self.sticky.is_none()
    }

    fn geo(&self) -> Result<Option<Geo>> {
        let set: Vec<Geo> = [
            self.state.clone().map(Geo::State),
            self.city.clone().map(Geo::City),
            self.zip.clone().map(Geo::PostalCode),
            self.asn.clone().map(Geo::Asn),
        ]
        .into_iter()
        .flatten()
        .collect();

        if set.len() > 1 {
            bail!("Webshare accepts only one of --city, --state, --zip or --asn at a time");
        }
        if self.asn.is_some() && !self.countries.is_empty() {
            bail!("--asn cannot be combined with --country: ASN targeting runs across the whole pool");
        }
        Ok(set.into_iter().next())
    }

    fn session(&self) -> Session {
        match (&self.sticky, self.rotate) {
            (Some(id), _) if id == "auto" => Session::Sticky(WebshareUser::new_sticky_id()),
            (Some(id), _) => Session::Sticky(id.clone()),
            (None, true) => Session::Rotate,
            (None, false) => Session::Default,
        }
    }

    /// Rewrite an endpoint's Webshare username with these overrides.
    /// Unset options leave the existing value alone.
    fn apply(&self, endpoint: Endpoint) -> Result<Endpoint> {
        if self.is_empty() {
            return Ok(endpoint);
        }
        let Some(mut user) = endpoint.webshare_user() else {
            bail!("this endpoint has no username, so geo targeting cannot be applied");
        };

        if !self.countries.is_empty() {
            for c in &self.countries {
                if c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_alphabetic()) {
                    bail!("`{c}` is not a 2-letter ISO country code");
                }
            }
            user.countries = self.countries.iter().map(|c| c.to_ascii_lowercase()).collect();
        }
        if let Some(geo) = self.geo()? {
            if matches!(geo, Geo::Asn(_)) {
                user.countries.clear();
            }
            user.geo = Some(geo);
        }
        match self.session() {
            Session::Default => {}
            other => user.session = other,
        }
        Ok(endpoint.with_username(user.build()))
    }
}

#[derive(Args)]
struct ConnectArgs {
    /// Endpoint string or saved profile name; omitted uses the default profile
    target: Option<String>,
    #[command(flatten)]
    targeting: Targeting,
    /// Talk SOCKS5 to Webshare instead of HTTP (upstream port defaults to 1080)
    #[arg(long)]
    socks5: bool,
    /// Stay in the foreground and log to the terminal
    #[arg(short = 'f', long)]
    foreground: bool,
    /// Leave the Windows system proxy alone; only expose the local listeners
    #[arg(long)]
    no_system_proxy: bool,
    /// Also set the machine-wide WinHTTP proxy (requires Administrator)
    #[arg(long)]
    winhttp: bool,
    /// Local HTTP listener address
    #[arg(long, value_name = "ADDR")]
    http: Option<String>,
    /// Local SOCKS5 listener address
    #[arg(long, value_name = "ADDR")]
    socks: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Connect(args) => cmd_connect(args),
        Command::Disconnect => cmd_disconnect(),
        Command::Status { json } => cmd_status(json),
        Command::Rotate => cmd_rotate(),
        Command::Switch { target, targeting } => cmd_switch(target, targeting),
        Command::Ip { direct } => cmd_ip(direct),
        Command::Run { argv } => cmd_run(argv),
        Command::Profile(cmd) => cmd_profile(cmd),
        Command::Login { key } => cmd_login(key),
        Command::Account => cmd_account(),
        Command::Endpoint { targeting, socks5 } => cmd_endpoint(targeting, socks5),
        Command::Where => cmd_where(),
    }
}

// connect

fn cmd_connect(args: ConnectArgs) -> Result<()> {
    let config = Config::load()?;

    if std::env::var_os(DAEMON_ENV).is_some() {
        return run_daemon(args, config);
    }

    if let Some(existing) = RunState::load_live()? {
        bail!(
            "already connected via {} (pid {}).\n\
             Use `utsusemi switch <endpoint>` to re-target, or `utsusemi disconnect` first.",
            existing.endpoint.redacted(),
            existing.pid
        );
    }

    // Resolve before forking so errors surface in this terminal.
    let (_, endpoint) = resolve_endpoint(&config, args.target.as_deref(), &args.targeting, args.socks5)?;
    println!("Endpoint  {}", endpoint.redacted());
    if let Some(user) = endpoint.webshare_user() {
        println!("Targeting {}", user.summary());
    }

    if args.foreground {
        return run_daemon(args, config);
    }
    spawn_detached(&args)
}

/// Work out which upstream to use, from the strongest source available:
/// an explicit argument, a saved profile, or the account's default credentials.
fn resolve_endpoint(
    config: &Config,
    target: Option<&str>,
    targeting: &Targeting,
    socks5: bool,
) -> Result<(Option<String>, Endpoint)> {
    let (profile, endpoint) = match (target, config.default_profile.as_deref()) {
        (None, None) => {
            let key = config.api_key.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "nothing to connect to.\n\
                     Paste an endpoint:   utsusemi connect \"user-de-rotate:pass@p.webshare.io:80\"\n\
                     Save one as default: utsusemi profile add home \"<endpoint>\" && utsusemi profile default home\n\
                     Or store an API key: utsusemi login <key>   (then `utsusemi connect --country de --rotate`)"
                )
            })?;
            let endpoint = api::Client::new(key)
                .default_endpoint(&targeting.countries, targeting.geo()?, targeting.session())
                .context("building an endpoint from your Webshare account")?;
            (None, endpoint)
        }
        _ => config.resolve(target)?,
    };

    let mut endpoint = targeting.apply(endpoint)?;
    if socks5 && endpoint.scheme != Scheme::Socks5 {
        endpoint.scheme = Scheme::Socks5;
        // Port 80 is HTTP-only on the backbone; move to the SOCKS5 port unless
        // the user pinned a port in the 9999-19999 range that serves both.
        if endpoint.port == 80 || endpoint.port == 3128 {
            endpoint.port = 1080;
        }
    }
    Ok((profile, endpoint))
}

/// Relaunch ourselves detached, with output going to the log file.
fn spawn_detached(args: &ConnectArgs) -> Result<()> {
    use std::process::{Command as StdCommand, Stdio};

    let exe = std::env::current_exe().context("locating the utsusemi executable")?;
    let log_path = config::log_path();
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening {}", log_path.display()))?;

    let mut cmd = StdCommand::new(exe);
    cmd.arg("connect");
    if let Some(t) = &args.target {
        cmd.arg(t);
    }
    for c in &args.targeting.countries {
        cmd.arg("--country").arg(c);
    }
    if let Some(v) = &args.targeting.city {
        cmd.arg("--city").arg(v);
    }
    if let Some(v) = &args.targeting.state {
        cmd.arg("--state").arg(v);
    }
    if let Some(v) = &args.targeting.zip {
        cmd.arg("--zip").arg(v);
    }
    if let Some(v) = &args.targeting.asn {
        cmd.arg("--asn").arg(v);
    }
    if args.targeting.rotate {
        cmd.arg("--rotate");
    }
    if let Some(v) = &args.targeting.sticky {
        cmd.arg("--sticky").arg(v);
    }
    if args.socks5 {
        cmd.arg("--socks5");
    }
    if args.no_system_proxy {
        cmd.arg("--no-system-proxy");
    }
    if args.winhttp {
        cmd.arg("--winhttp");
    }
    if let Some(v) = &args.http {
        cmd.arg("--http").arg(v);
    }
    if let Some(v) = &args.socks {
        cmd.arg("--socks").arg(v);
    }

    cmd.env(DAEMON_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: survive this console
        // closing, and do not receive its Ctrl+C.
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
    }

    let child = cmd.spawn().context("starting the background relay")?;
    let pid = child.id();

    // Wait for the relay to publish its state, so we can report real ports.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(st) = RunState::load()? {
            if st.pid == pid {
                println!("Listening http://{}  socks5://{}", st.http, st.socks5);
                if st.system_proxy {
                    println!("System proxy -> {}", st.http);
                } else {
                    println!("System proxy untouched (use `utsusemi run -- <cmd>` or set HTTP_PROXY)");
                }
                println!("Connected. `utsusemi status` to inspect, `utsusemi disconnect` to stop.");
                return Ok(());
            }
        }
        if !state::process_alive(pid) {
            bail!(
                "the relay exited during startup. Last log lines from {}:\n{}",
                config::log_path().display(),
                tail_log(20)
            );
        }
        if Instant::now() > deadline {
            let _ = state::kill(pid);
            bail!("the relay did not come up within 15s; see {}", config::log_path().display());
        }
        std::thread::sleep(Duration::from_millis(120));
    }
}

fn tail_log(lines: usize) -> String {
    let text = std::fs::read_to_string(config::log_path()).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

// daemon

fn run_daemon(args: ConnectArgs, config: Config) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(daemon_main(args, config))
}

async fn daemon_main(args: ConnectArgs, config: Config) -> Result<()> {
    init_logging(args.foreground);

    let (profile, endpoint) =
        resolve_endpoint(&config, args.target.as_deref(), &args.targeting, args.socks5)?;

    let http_addr = args.http.as_deref().unwrap_or(&config.listen.http);
    let socks_addr = args.socks.as_deref().unwrap_or(&config.listen.socks5);

    let http_listener = bind(http_addr).await?;
    let socks_listener = bind(socks_addr).await?;
    let control_listener = bind("127.0.0.1:0").await?;

    let http_local = http_listener.local_addr()?;
    let socks_local = socks_listener.local_addr()?;
    let control_local = control_listener.local_addr()?;

    let relay = Relay::new(UpstreamHandle::new(endpoint.clone()));
    let want_system_proxy = config.system_proxy.enable && !args.no_system_proxy;

    let run_state = RunState {
        pid: std::process::id(),
        control: control_local.to_string(),
        token: control::new_token(),
        http: http_local.to_string(),
        socks5: socks_local.to_string(),
        profile,
        endpoint: endpoint.clone(),
        started_at: RunState::now(),
        system_proxy: want_system_proxy,
    };

    if want_system_proxy {
        let winhttp = config.system_proxy.winhttp || args.winhttp;
        sysproxy::apply(&http_local.to_string(), &config.system_proxy.bypass, winhttp)
            .context("pointing the Windows system proxy at the relay")?;
        tracing::info!("system proxy -> {http_local}");
    }

    run_state.save()?;
    tracing::info!(
        "relay up: http={http_local} socks5={socks_local} upstream={}",
        endpoint.redacted()
    );

    let ctx = Arc::new(ControlContext {
        relay: relay.clone(),
        state: std::sync::Mutex::new(run_state),
        shutdown: tokio::sync::Notify::new(),
    });

    let http_task = tokio::spawn(relay::http::serve(http_listener, relay.clone()));
    let socks_task = tokio::spawn(relay::socks5::serve(socks_listener, relay.clone()));
    let control_task = tokio::spawn(control::serve(control_listener, ctx.clone()));

    let reason = tokio::select! {
        _ = ctx.shutdown.notified() => "stop requested",
        _ = shutdown_signal() => "signal received",
        r = http_task => { log_task_exit("http listener", r); "http listener stopped" }
        r = socks_task => { log_task_exit("socks5 listener", r); "socks5 listener stopped" }
        r = control_task => { log_task_exit("control listener", r); "control listener stopped" }
    };
    tracing::info!("shutting down: {reason}");

    teardown();
    Ok(())
}

fn log_task_exit(name: &str, result: Result<anyhow::Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => tracing::warn!("{name} returned unexpectedly"),
        Ok(Err(e)) => tracing::error!("{name} failed: {e:#}"),
        Err(e) => tracing::error!("{name} panicked: {e}"),
    }
}

/// Restore the desktop to how we found it. Safe to call twice.
fn teardown() {
    match sysproxy::restore() {
        Ok(true) => tracing::info!("system proxy restored"),
        Ok(false) => {}
        Err(e) => tracing::error!("could not restore the system proxy: {e:#}"),
    }
    if let Err(e) = RunState::clear() {
        tracing::warn!("could not clear run state: {e}");
    }
}

/// Ctrl+C, plus the console-close and shutdown events, because closing the
/// window must not leave the system proxy pointing at a dead port.
async fn shutdown_signal() {
    #[cfg(windows)]
    {
        use tokio::signal::windows;
        let mut close = match windows::ctrl_close() {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        let mut shutdown = match windows::ctrl_shutdown() {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        let mut brk = match windows::ctrl_break() {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = close.recv() => {}
            _ = shutdown.recv() => {}
            _ = brk.recv() => {}
        }
    }
    #[cfg(not(windows))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn bind(addr: &str) -> Result<TcpListener> {
    let parsed: SocketAddr = addr
        .parse()
        .with_context(|| format!("`{addr}` is not a valid host:port listen address"))?;
    TcpListener::bind(parsed).await.with_context(|| {
        format!("cannot listen on {addr} (already in use? another utsusemi running?)")
    })
}

fn init_logging(foreground: bool) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("UTSUSEMI_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    if foreground {
        builder.with_ansi(std::io::stdout().is_terminal()).init();
    } else {
        // Detached: stdout is already redirected to the log file.
        builder.with_ansi(false).init();
    }
}

// lifecycle commands

fn live_state() -> Result<RunState> {
    RunState::load_live()?.ok_or_else(|| anyhow::anyhow!("not connected (`utsusemi connect` first)"))
}

fn cmd_disconnect() -> Result<()> {
    let Some(st) = RunState::load_live()? else {
        // Nothing running, but a crash may have left the system proxy pointing
        // at a dead port. Clean that up rather than reporting "not connected".
        return match sysproxy::restore() {
            Ok(true) => {
                RunState::clear()?;
                println!("Not connected; restored a leftover system proxy setting.");
                Ok(())
            }
            Ok(false) => {
                println!("Not connected.");
                Ok(())
            }
            Err(e) => Err(e),
        };
    };

    match control::request(&st.control, &st.token, Request::Stop) {
        Ok(Reply::Ok) => {}
        Ok(Reply::Error { message }) => bail!("relay refused to stop: {message}"),
        Ok(other) => bail!("unexpected reply from relay: {other:?}"),
        Err(e) => {
            tracing::debug!("control channel unreachable: {e:#}");
            state::kill(st.pid).context("relay was unreachable and could not be terminated")?;
            sysproxy::restore()?;
            RunState::clear()?;
            println!("Relay was unresponsive; terminated it and restored the system proxy.");
            return Ok(());
        }
    }

    // Give it a moment to restore the system proxy and clear its state.
    let deadline = Instant::now() + Duration::from_secs(10);
    while state::process_alive(st.pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(80));
    }
    if state::process_alive(st.pid) {
        state::kill(st.pid)?;
    }
    sysproxy::restore()?;
    RunState::clear()?;
    println!("Disconnected. System proxy restored.");
    Ok(())
}

fn cmd_status(json: bool) -> Result<()> {
    let Some(st) = RunState::load_live()? else {
        if json {
            println!("{}", serde_json::json!({ "connected": false }));
        } else {
            println!("Disconnected.");
            let snap = sysproxy::current().unwrap_or_default();
            if snap.enabled && snap.server.contains("127.0.0.1") {
                println!(
                    "Warning: the system proxy still points at {} with nothing listening.\n\
                     Run `utsusemi disconnect` to clear it.",
                    snap.server
                );
            }
        }
        return Ok(());
    };

    let reply = control::request(&st.control, &st.token, Request::Status)?;
    let status = match reply {
        Reply::Status(s) => s,
        Reply::Error { message } => bail!("{message}"),
        other => bail!("unexpected reply from relay: {other:?}"),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    let s = &status.stats;
    println!("Connected    {}", status.endpoint);
    println!("Targeting    {}", status.summary);
    if let Some(p) = &status.profile {
        println!("Profile      {p}");
    }
    println!("Listening    http://{}  socks5://{}", status.http, status.socks5);
    println!(
        "System proxy {}",
        if status.system_proxy { "on" } else { "off (local listeners only)" }
    );
    println!("Uptime       {}", format_duration(status.uptime_secs));
    println!(
        "Connections  {} active, {} total, {} failed",
        s.active, s.total, s.failed
    );
    println!(
        "Transferred  {} up, {} down",
        format_bytes(s.up_bytes),
        format_bytes(s.down_bytes)
    );
    Ok(())
}

fn cmd_rotate() -> Result<()> {
    let st = live_state()?;
    match control::request(&st.control, &st.token, Request::Rotate)? {
        Reply::Switched { endpoint, summary } => {
            println!("Rotated. {endpoint}");
            println!("Targeting {summary}");
            Ok(())
        }
        Reply::Error { message } => bail!("{message}"),
        other => bail!("unexpected reply from relay: {other:?}"),
    }
}

fn cmd_switch(target: String, targeting: Targeting) -> Result<()> {
    let st = live_state()?;
    let config = Config::load()?;
    let (_, endpoint) = config.resolve(Some(&target))?;
    let endpoint = targeting.apply(endpoint)?;

    match control::request(
        &st.control,
        &st.token,
        Request::Switch {
            endpoint: endpoint.to_url(),
        },
    )? {
        Reply::Switched { endpoint, summary } => {
            println!("Switched to {endpoint}");
            println!("Targeting    {summary}");
            Ok(())
        }
        Reply::Error { message } => bail!("{message}"),
        other => bail!("unexpected reply from relay: {other:?}"),
    }
}

fn cmd_ip(direct: bool) -> Result<()> {
    if direct {
        let info = ipcheck::direct().context("looking up your real IP")?;
        println!("{}  ({})", info.ip, info.location());
        if let Some(org) = &info.org {
            println!("{org}");
        }
        return Ok(());
    }

    let st = live_state()?;
    let info = ipcheck::via_http_proxy(&st.http).context("looking up the exit IP through the relay")?;
    println!("{}  ({})", info.ip, info.location());
    if let Some(org) = &info.org {
        println!("{org}");
    }
    Ok(())
}

fn cmd_run(argv: Vec<String>) -> Result<()> {
    let st = live_state()?;
    let http = format!("http://{}", st.http);
    let socks = format!("socks5://{}", st.socks5);

    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .env("HTTP_PROXY", &http)
        .env("HTTPS_PROXY", &http)
        .env("http_proxy", &http)
        .env("https_proxy", &http)
        .env("ALL_PROXY", &socks)
        .env("all_proxy", &socks)
        .env("NO_PROXY", "localhost,127.0.0.1,::1")
        .env("no_proxy", "localhost,127.0.0.1,::1");

    let status = cmd
        .status()
        .with_context(|| format!("running `{}`", argv.join(" ")))?;
    std::process::exit(status.code().unwrap_or(1));
}

// configuration commands

fn cmd_profile(cmd: ProfileCmd) -> Result<()> {
    let mut config = Config::load()?;
    match cmd {
        ProfileCmd::Add {
            name,
            endpoint,
            note,
        } => {
            let parsed: Endpoint = endpoint
                .parse()
                .with_context(|| format!("`{endpoint}` is not a valid proxy endpoint"))?;
            config.profiles.insert(
                name.clone(),
                Profile {
                    url: endpoint,
                    note,
                },
            );
            if config.default_profile.is_none() {
                config.default_profile = Some(name.clone());
            }
            config.save()?;
            println!("Saved profile `{name}` -> {}", parsed.redacted());
            Ok(())
        }
        ProfileCmd::List => {
            if config.profiles.is_empty() {
                println!("No saved profiles. Add one: utsusemi profile add <name> \"<endpoint>\"");
                return Ok(());
            }
            for (name, profile) in &config.profiles {
                let marker = if config.default_profile.as_deref() == Some(name.as_str()) {
                    "*"
                } else {
                    " "
                };
                let summary = profile
                    .url
                    .parse::<Endpoint>()
                    .ok()
                    .and_then(|e| e.webshare_user().map(|u| u.summary()))
                    .unwrap_or_else(|| "unparsed".into());
                println!("{marker} {name:<16} {summary}");
                if let Some(note) = &profile.note {
                    println!("  {:<16} {note}", "");
                }
            }
            Ok(())
        }
        ProfileCmd::Rm { name } => {
            if config.profiles.remove(&name).is_none() {
                bail!("no profile named `{name}`");
            }
            if config.default_profile.as_deref() == Some(name.as_str()) {
                config.default_profile = config.profiles.keys().next().cloned();
            }
            config.save()?;
            println!("Removed profile `{name}`");
            Ok(())
        }
        ProfileCmd::Default { name } => {
            if !config.profiles.contains_key(&name) {
                bail!("no profile named `{name}`");
            }
            config.default_profile = Some(name.clone());
            config.save()?;
            println!("Default profile is now `{name}`");
            Ok(())
        }
    }
}

fn cmd_login(key: Option<String>) -> Result<()> {
    let key = match key {
        Some(k) => k,
        None => {
            eprint!("Webshare API key: ");
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .context("reading the API key from stdin")?;
            line.trim().to_string()
        }
    };
    if key.is_empty() {
        bail!("no API key given (create one at https://dashboard.webshare.io/userapi/keys)");
    }

    let account = api::Client::new(&key)
        .account()
        .context("verifying the API key")?;

    let mut config = Config::load()?;
    config.api_key = Some(key);
    config.save()?;
    println!("Signed in as {}", account.email);
    println!("Key stored in {}", config::config_path().display());
    Ok(())
}

fn cmd_account() -> Result<()> {
    let config = Config::load()?;
    let key = config
        .api_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("no API key stored (`utsusemi login <key>`)"))?;
    let client = api::Client::new(key);

    let account = client.account()?;
    println!("Account      {}", account.email);

    match client.proxy_config() {
        Ok(cfg) => println!("Proxy user   {}", cfg.username),
        Err(e) => println!("Proxy user   unavailable: {e}"),
    }
    match client.active_plan() {
        Ok(Some(plan)) => println!("Plan         {}", plan.describe()),
        Ok(None) => println!("Plan         free (no active plan)"),
        Err(e) => println!("Plan         unavailable: {e}"),
    }
    match client.subscription() {
        Ok(Some(sub)) => {
            if !sub.term.is_empty() {
                println!("Term         {}", sub.term);
            }
            if let Some(end) = &sub.end_date {
                println!("Renews       {end}");
            }
            if sub.throttled {
                println!("Warning      subscription is throttled (high bandwidth use)");
            }
            if sub.paused {
                println!("Warning      subscription is paused");
            }
        }
        Ok(None) => {}
        Err(e) => println!("Subscription unavailable: {e}"),
    }
    Ok(())
}

fn cmd_endpoint(targeting: Targeting, socks5: bool) -> Result<()> {
    let config = Config::load()?;
    let key = config
        .api_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("no API key stored (`utsusemi login <key>`)"))?;

    let mut endpoint = api::Client::new(key).default_endpoint(
        &targeting.countries,
        targeting.geo()?,
        targeting.session(),
    )?;
    if socks5 {
        endpoint.scheme = Scheme::Socks5;
        endpoint.port = 1080;
    }
    // Printed in full on purpose: this is the "copy it somewhere else" command.
    println!("{}", endpoint.to_url());
    Ok(())
}

fn cmd_where() -> Result<()> {
    println!("Config  {}", config::config_path().display());
    println!("State   {}", config::state_path().display());
    println!("Log     {}", config::log_path().display());
    println!("Backup  {}", sysproxy::backup_path().display());
    Ok(())
}

// formatting

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}
