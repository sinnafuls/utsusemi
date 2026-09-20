//! Keeping the relay on an exit that actually works.
//!
//! Webshare's rotating endpoints hand out a different exit per connection,
//! and on the residential pool a large share of those exits accept the tunnel
//! and then answer nothing. Measured on a live account: roughly one in ten
//! fresh exits carried TLS. A browser survives that only because it reuses
//! one tunnel per origin, so a single lucky exit serves everything.
//!
//! This module gives the relay the same advantage deliberately. A sticky
//! session id pins the exit behind it, so the fix is to find a session that
//! works and keep it, re-hunting when it goes bad. Hunting is parallel
//! because the pool is mostly bad: eight candidates at once turn a one-in-ten
//! lottery into a near-certainty in one round trip.

use std::time::Duration;

use crate::endpoint::{Endpoint, Session, WebshareUser};
use crate::relay::Relay;
use crate::upstream;

/// Sessions probed at once when hunting. Sized so that a pool where only a
/// tenth of exits work still yields a winner on the first round more often
/// than not.
const HUNT_CANDIDATES: usize = 8;
/// How often the pinned exit's health is reconsidered.
const CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// Failures inside one interval that mean the pinned exit has gone bad.
const FAILURE_TRIGGER: u64 = 2;

/// Swap the relay's upstream for a session that answers, if one can be found.
/// Returns the endpoint now in use, or `None` when nothing better was found
/// and the current upstream was left alone.
pub async fn hunt(relay: &Relay) -> Option<Endpoint> {
    let base = relay.upstream.get();
    let user = base.webshare_user()?;

    let mut racing = tokio::task::JoinSet::new();
    for _ in 0..HUNT_CANDIDATES {
        let candidate = base.with_username(
            WebshareUser {
                session: Session::Sticky(WebshareUser::new_sticky_id()),
                ..user.clone()
            }
            .build(),
        );
        racing.spawn(async move { upstream::probe(&candidate).await.ok().map(|()| candidate) });
    }

    while let Some(finished) = racing.join_next().await {
        if let Ok(Some(winner)) = finished {
            relay.upstream.set(winner.clone());
            tracing::info!("pinned a working exit: {}", winner.redacted());
            return Some(winner);
        }
    }

    tracing::warn!("no working exit among {HUNT_CANDIDATES} candidate sessions");
    None
}

/// Watch the failure counter and re-hunt whenever the pinned exit stops
/// carrying traffic. Runs for the life of the relay.
pub async fn maintain(relay: Relay) {
    let mut seen = relay.stats.snapshot().failed;

    loop {
        tokio::time::sleep(CHECK_INTERVAL).await;

        let failed = relay.stats.snapshot().failed;
        let fresh = failed.saturating_sub(seen);
        seen = failed;

        if fresh < FAILURE_TRIGGER {
            continue;
        }
        tracing::info!("{fresh} connections found no exit, hunting a new one");
        if hunt(&relay).await.is_some() {
            // Failures raised while hunting belong to the old exit.
            seen = relay.stats.snapshot().failed;
        }
    }
}
