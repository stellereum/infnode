# infnode

> Testnet software — no real funds, no mainnet yet, no external audit yet.

Post-quantum QUIC+DHT transport layer for the Stellereum L1. Peer auth,
reputation with bans, backpressure caps, ML-KEM session keys, Falcon-512
handshake. Used as a dependency by the node.

<p align="center">
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange" alt="License"/></a>
</p>

## Highlights

- PQ handshake default-ON with identity registry and classical sunset at a fixed height
- Reputation with temp bans, throttle tiers and ban decay — spoof-framing impossible by construction
- Backpressure everywhere: per-peer caps on connections, sessions, subscriptions, outboxes, routes
- Circuit breaker on dead peers (17× fewer redials) + budgeted endpoint hygiene
- Frame codec 2.3× faster with byte-identical wire format, proven by differential fuzzing

## Layout

```text
crates/infnode/   the transport: QUIC endpoints, DHT, pubsub, reputation, caps
```

## Build & test

```bash
cargo build -p infnode
cargo test -p infnode          # full suite: unit + handshake + eclipse + pentest batteries
cargo clippy -p infnode --all-targets -- -D warnings
```

## Security

No external audit yet. Testnet only. Downgrade, eclipse, cap-bypass and
reputation-spoof batteries are in-tree (`tests/pentest_*`). **Never open a
public issue for a suspected vulnerability** — report via [`SECURITY.md`](SECURITY.md).

## Contributing · License

Keep `cargo test` green and clippy clean. MIT **or** Apache-2.0
([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)).
