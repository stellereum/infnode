//! Per-peer (ed25519-identity) reputation for the QUIC accept path.
//!
//! F8 residual (`docs/PENTEST_NET_API.md` M2): the accept path already gates
//! on source IP (pre-auth deadline, per-IP handshake buckets, failed-auth
//! strikes with cooldown). IP gates have a shared-IP blast radius (loopback:
//! one abusive peer bans `127.0.0.1` for everyone on a local cluster) and no
//! memory of *which identity* misbehaved. This layer scores the peer
//! **identity** instead — the node id (`[u8; 20]`, `blake3(ed25519_pub)[..20]`,
//! 1:1 with the ed25519 key — "ed25519 identity, not just IP") — so a ban
//! follows the offender across IPs and never touches well-behaved peers that
//! happen to share an address.
//!
//! It EXTENDS the existing hardening, it does not replace it: the IP bucket,
//! strike and deadline checks all stay exactly as they are. The identity
//! gate reads (never debits) the claimed id pre-auth; debits apply only
//! to the proven id on the authed path.
//!
//! ## Score model
//!
//! * `+reward` on a valid handshake / accepted message (good citizen).
//! * `-pen_*` on auth failure, oversize frame, rate-limit violation and
//!   protocol violation (bad signature, stale frame, src mismatch, decrypt
//!   failure) by the PROVEN identity only — pre-auth failures debit nobody.
//!   Scores clamp to `[REP_SCORE_MIN, REP_SCORE_MAX]`.
//! * Soft threshold: while `score <= soft` (and not banned) the identity is
//!   **throttled** — its handshakes are refused fail-closed, but no ban is
//!   imposed; decay alone can lift it out.
//! * Hard threshold: when `score <= ban_score` a **temp ban** is imposed
//!   (default ~10 min). The ban bites at the accept gate: new handshakes
//!   from the identity are refused while live connections stay governed by
//!   the existing per-connection controls (rate limiter answers, stream
//!   caps, timeouts) — a ban never turns an answered refusal into a dropped
//!   connection. Repeat offenders escalate: each new ban doubles the
//!   previous duration (`base * 2^(bans-1)`), capped at `max_ban_secs`.
//! * Forgiveness: scores decay toward 0 at `decay_per_sec`; an expired ban
//!   lifts a still-negative score to just above the soft threshold (one
//!   packet can neither re-ban nor re-throttle); a fully recovered score
//!   (`0`, no active ban) resets the escalation counter. There is NO
//!   permanent ban — no self-DoS footgun.
//!
//! ## Fail-closed notes
//!
//! * Unparsable env falls back to compiled defaults (same pattern as the
//!   existing `STELL_INF_*` gates in `node.rs`); no new config file format.
//! * Refusals that are *caused by* reputation carry NO extra penalty —
//!   penalising a refused handshake would make soft throttle permanent and
//!   defeat decay.
//! * Attribution rule (framing-impossible): failures are debited ONLY to
//!   the proven post-handshake identity (`authed` pid in `frame_loop` /
//!   `handle_stream`, set after a valid CHALLENGE). Pre-auth failures and
//!   frames whose claimed id does not match the proven id are NEVER
//!   debited to any identity — the connection is dropped fail-closed
//!   instead (the per-IP strike still binds the sender's address). A
//!   claimed id is unproven bytes any sender can stamp, so debiting it
//!   would let an attacker frame honest ids into temp-bans. The CHALLENGE
//!   gate below reads (never writes) reputation: refusals carry no penalty.
//! * App-layer policy refusals (oversized DHT value, bad TTL, ACL deny,
//!   unknown service) are well-formed requests answered with an error —
//!   they are NOT peer-abuse signals and carry no penalty. Only
//!   transport/protocol-level events penalise.
//!
//! ## Knobs (`STELL_INF_REP_*`, env, defaults in `RepConfig`)
//!
//! | env | default | meaning |
//! |-----|---------|---------|
//! | `STELL_INF_REP_SOFT_SCORE` | `-20` | `score <= soft` → throttled |
//! | `STELL_INF_REP_BAN_SCORE` | `-50` | `score <= ban` → temp ban |
//! | `STELL_INF_REP_BAN_SECS` | `600` | base ban duration (~10 min) |
//! | `STELL_INF_REP_MAX_BAN_SECS` | `3600` | escalation cap |
//! | `STELL_INF_REP_DECAY_PER_SEC` | `1` | score drift toward 0 / sec |
//! | `STELL_INF_REP_REWARD_VALID` | `1` | credit per valid handshake/message |
//! | `STELL_INF_REP_PEN_AUTH` | `10` | debit per auth failure |
//! | `STELL_INF_REP_PEN_OVERSIZE` | `10` | debit per oversize frame |
//! | `STELL_INF_REP_PEN_RATE` | `5` | debit per rate-limit violation |
//! | `STELL_INF_REP_PEN_PROTO` | `10` | debit per protocol violation |

use std::time::{Duration, Instant};

/// Lowest a score can sink (flood bound: one identity cannot accrue
/// unbounded negativity, and recovery always stays within reach of decay).
pub const REP_SCORE_MIN: i64 = -1000;
/// Highest a score can climb (a chatty peer banks no permanent trust).
pub const REP_SCORE_MAX: i64 = 100;
/// Soft cap on tracked identities; beyond it idle/neutral entries are
/// evicted first so a flood of fresh identities cannot grow memory
/// without bound (the IP layer still binds the sender's address).
pub const REP_MAP_CAP: usize = 8192;
/// Hard cap: beyond it only actively-banned entries survive.
pub const REP_MAP_HARD_CAP: usize = 16384;

/// Operators' own tuning surface: env `STELL_INF_REP_*`, sane defaults,
/// fail-closed on unparsable values (same pattern as the `STELL_INF_*`
/// accept-hardening gates in `node.rs`).
#[derive(Debug, Clone, Copy)]
pub struct RepConfig {
    /// `STELL_INF_REP_SOFT_SCORE`, default -20.
    pub soft_score: i64,
    /// `STELL_INF_REP_BAN_SCORE`, default -50.
    pub ban_score: i64,
    /// `STELL_INF_REP_BAN_SECS`, default 600 (~10 min).
    pub ban_secs: u64,
    /// `STELL_INF_REP_MAX_BAN_SECS`, default 3600.
    pub max_ban_secs: u64,
    /// `STELL_INF_REP_DECAY_PER_SEC`, default 1.
    pub decay_per_sec: u64,
    /// `STELL_INF_REP_REWARD_VALID`, default 1.
    pub reward_valid: i64,
    /// `STELL_INF_REP_PEN_AUTH`, default 10.
    pub pen_auth: i64,
    /// `STELL_INF_REP_PEN_OVERSIZE`, default 10.
    pub pen_oversize: i64,
    /// `STELL_INF_REP_PEN_RATE`, default 5.
    pub pen_rate: i64,
    /// `STELL_INF_REP_PEN_PROTO`, default 10.
    pub pen_proto: i64,
}

fn env_i64(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

impl RepConfig {
    /// Read the current `STELL_INF_REP_*` env (defaults on missing/garbage).
    /// Read per operation — like the existing accept-hardening getters —
    /// so tests can retune without a restart.
    pub fn load() -> Self {
        Self {
            soft_score: env_i64("STELL_INF_REP_SOFT_SCORE", -20),
            ban_score: env_i64("STELL_INF_REP_BAN_SCORE", -50),
            ban_secs: env_u64("STELL_INF_REP_BAN_SECS", 600).max(1),
            max_ban_secs: env_u64("STELL_INF_REP_MAX_BAN_SECS", 3600).max(1),
            decay_per_sec: env_u64("STELL_INF_REP_DECAY_PER_SEC", 1),
            reward_valid: env_i64("STELL_INF_REP_REWARD_VALID", 1).max(0),
            pen_auth: env_i64("STELL_INF_REP_PEN_AUTH", 10).max(0),
            pen_oversize: env_i64("STELL_INF_REP_PEN_OVERSIZE", 10).max(0),
            pen_rate: env_i64("STELL_INF_REP_PEN_RATE", 5).max(0),
            pen_proto: env_i64("STELL_INF_REP_PEN_PROTO", 10).max(0),
        }
    }
}

/// Per-identity reputation state. `score` is always decayed through
/// [`RepEntry::touch`] before any read or update, so expiry/forgiveness
/// needs no background task.
#[derive(Debug, Clone, Copy)]
pub struct RepEntry {
    pub(crate) score: i64,
    pub(crate) updated: Instant,
    pub(crate) ban_until: Option<Instant>,
    /// Bans imposed so far (escalation memory); reset on full recovery.
    pub(crate) bans: u32,
}

impl RepEntry {
    pub(crate) fn fresh(now: Instant) -> Self {
        Self {
            score: 0,
            updated: now,
            ban_until: None,
            bans: 0,
        }
    }

    /// Active ban still in force at `now`.
    pub(crate) fn banned_at(&self, now: Instant) -> bool {
        self.ban_until.is_some_and(|u| u > now)
    }

    /// Apply decay, expire bans with forgiveness, and clear escalation
    /// memory on full recovery. Must precede every score/ban read or write.
    pub(crate) fn touch(&mut self, cfg: &RepConfig, now: Instant) {
        let dt = now.saturating_duration_since(self.updated).as_secs_f64();
        if dt > 0.0 && cfg.decay_per_sec > 0 {
            let amt = (dt * cfg.decay_per_sec as f64) as i64;
            if self.score < 0 {
                self.score = (self.score + amt).min(0);
            } else if self.score > 0 {
                self.score = (self.score - amt).max(0);
            }
            self.updated = now;
        }
        if let Some(until) = self.ban_until {
            if now >= until {
                self.ban_until = None;
                // Forgive: lift a still-negative score to just above the
                // soft threshold, so a single packet after expiry can
                // neither re-ban nor re-throttle (no permanent footgun).
                // Never lift above neutral.
                let floor = cfg.soft_score.saturating_add(1).min(0);
                if self.score < floor {
                    self.score = floor;
                }
            }
        }
        // Full recovery clears escalation memory (fail-open NOT possible:
        // this only runs when no ban is active and the score is neutral).
        if self.ban_until.is_none() && self.score == 0 {
            self.bans = 0;
        }
    }
}

/// Pure score decay toward 0 (unit-testable core of [`RepEntry::touch`]).
pub fn decayed_score(score: i64, elapsed_secs: f64, rate_per_sec: u64) -> i64 {
    if elapsed_secs <= 0.0 || rate_per_sec == 0 {
        return score;
    }
    let amt = (elapsed_secs * rate_per_sec as f64) as i64;
    if score < 0 {
        (score + amt).min(0)
    } else if score > 0 {
        (score - amt).max(0)
    } else {
        0
    }
}

/// Escalating ban duration: `base * 2^(bans-1)`, capped at `max_secs`.
/// `bans` is the 1-based count *including* the ban being imposed.
pub fn ban_duration_secs(bans: u32, base: u64, max_secs: u64) -> u64 {
    let shift = bans.saturating_sub(1).min(20);
    let mult = 1u64.checked_shl(shift).unwrap_or(1 << 20);
    base.saturating_mul(mult).min(max_secs.max(1)).max(1)
}

/// Fail-closed classifier for frame-decoding errors: does this error look
/// like an oversize/length-abuse refusal (penalty kind `oversize`) rather
/// than a plain malformed frame (penalty kind `protocol`)? Both penalise
/// by default; the split only matters for operators who tune them apart.
pub fn oversize_looking(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m.contains("too large")
        || m.contains("too long")
        || m.contains("too many")
        || m.contains("length")
}

/// How long a still-active ban lasts from `now` (saturating).
pub fn ban_remaining(entry_until: Instant, now: Instant) -> Duration {
    entry_until.saturating_duration_since(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_moves_toward_zero_without_overshoot() {
        assert_eq!(decayed_score(-30, 2.0, 5), -20);
        assert_eq!(decayed_score(-3, 10.0, 5), 0);
        assert_eq!(decayed_score(7, 2.0, 5), 0);
        assert_eq!(decayed_score(50, 2.0, 5), 40);
        assert_eq!(decayed_score(0, 100.0, 5), 0);
        assert_eq!(decayed_score(-30, 0.0, 5), -30);
        assert_eq!(decayed_score(-30, 2.0, 0), -30);
    }

    #[test]
    fn ban_duration_doubles_then_caps() {
        assert_eq!(ban_duration_secs(1, 600, 3600), 600);
        assert_eq!(ban_duration_secs(2, 600, 3600), 1200);
        assert_eq!(ban_duration_secs(3, 600, 3600), 2400);
        assert_eq!(ban_duration_secs(4, 600, 3600), 3600);
        assert_eq!(ban_duration_secs(40, 600, 3600), 3600);
        assert_eq!(ban_duration_secs(1, 3, 30), 3);
        assert_eq!(ban_duration_secs(2, 3, 30), 6);
    }

    #[test]
    fn oversize_classifier_splits_kinds() {
        assert!(oversize_looking("payload too large"));
        assert!(oversize_looking("nonce too large"));
        assert!(oversize_looking("frame length mismatch"));
        assert!(oversize_looking("frame length overflow"));
        assert!(oversize_looking("too many bytes"));
        assert!(!oversize_looking("frame too short"));
        assert!(!oversize_looking("frame read timeout"));
        assert!(!oversize_looking("bad signature"));
        assert!(!oversize_looking("unsupported version"));
    }
}
