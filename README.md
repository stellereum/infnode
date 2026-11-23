<h1 align="center">infnode</h1>

<p align="center">
  <strong>Post-quantum QUIC + DHT transport for the Stellereum node.</strong><br/>
  Falcon-512 peer identity · ML-KEM-768 sessions · Kademlia discovery · bounded storage and pubsub.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License: MIT OR Apache-2.0"/></a>
  <img src="https://img.shields.io/badge/status-testnet-yellow" alt="Testnet"/>
  <img src="https://img.shields.io/badge/language-Rust-000?logo=rust" alt="Rust"/>
  <a href="../docs-site/security/status.md"><img src="https://img.shields.io/badge/external%20audit-none%20completed-critical" alt="No external audit completed"/></a>
</p>

> [!WARNING]
> **Testnet software, no external audit.** `infnode` is the transport used by
> the Stellereum testnet. It has not been independently audited, has no mainnet
> deployment, and must not be treated as a hardened anonymity or file-sharing
> network. Testnet coins have no value.

`infnode` is the network layer of a Stellereum node: QUIC over UDP, a Kademlia
DHT, bounded pub/sub, chunk storage and mailbox services, all authenticated by a
Falcon-512 identity and keyed with ML-KEM-768. It does **not** run consensus and
does **not** decide blocks; it carries frames between nodes and exposes services
that the node uses.

The crate is consumed as a path dependency by
[`stellereum`](../stellereum/README.md). The workspace also contains
`crates/infmail`, an overlay that adds mail semantics on top of the transport;
that overlay is not required to run the L1 node.

## At a glance

| Property | Value |
| --- | --- |
| Transport | QUIC over UDP (`quinn`), TLS 1.3, TLS 1.2 disabled |
| Peer identity | Falcon-512 public key; `NodeId = BLAKE3("infnode-pqid-v1" ‖ pk)[..20]` |
| Key exchange | Ephemeral ML-KEM-768 per handshake |
| Discovery | Kademlia DHT (`k = 20`, `α = 3`) plus optional DNS TXT seeds |
| Frame limit | 32 MiB application frame; 64 KiB authentication frame |
| Storage | Chunked objects, replication/reward accounting capped at RF = 3 |
| Pub/sub | Topic subscriptions with bounded per-peer fan-out |
| Classical TLS pin | **None.** The QUIC certificate is a carrier; trust is the Falcon key bound into it |

## Identity model

### PQ-derived node id

There is no classical node identity. The only node id is derived from the
long-term Falcon-512 public key:

```text
NodeId = BLAKE3("infnode-pqid-v1" ‖ falcon_public_key)[..20]
display = "inf1:" + hex(NodeId)
```

The key lives in `keys/pq-identity.key` (directory `0700`, file `0600`). A
legacy `identity.key` (32-byte Ed25519 seed) is refused loudly rather than
silently reused. DHT routing records, TLS pins and federation TXT records all
bind to the same PQ id.

The node also holds an ML-KEM-768 key in `keys/e2e.key` for mailbox encryption.
Both files can be encrypted at rest with `STELL_NODE_PASSPHRASE` (preferred) or
`INFNODE_KEY_PASSPHRASE`: the `enc2:` format is Argon2id + XChaCha20-Poly1305.

### Peer pins

A configured peer must carry a Falcon-512 public key:

```yaml
peers:
  - name: node-b
    pq-pub: "<897-byte Falcon-512 public key, hex>"
    endpoints: ["203.0.113.10:9410"]
```

`pq-pub` is mandatory for a parsed operator config. The removed fields
`node-id` and `x-pub` fail loudly. `ed-pub` is accepted **only** as the frozen
consensus validator key (canonical name `consensus-pub`); it is never a
transport identity, authentication key or TLS pin.

### No classical TLS pin

QUIC still needs a certificate for the TLS 1.3 handshake, so the node creates a
self-signed certificate as a transport container. The certificate's own
Ed25519 key is **not** the trust anchor. The node signs a digest of the
certificate's SubjectPublicKeyInfo with its Falcon-512 key and embeds that tag
in a custom extension. The dialing side's `PinnedVerifier` checks:

1. the certificate carries the expected PQ TLS tag;
2. the tag verifies under the pinned `pq-pub`;
3. the common name matches the expected node id;
4. the certificate is valid at the current time and is self-consistent.

A missing tag, a mismatched tag, or a classical-only peer is refused
(`missing pq tls tag (classical peer refused)`). There is no fallback to an
Ed25519 or X25519 pin.

The handshake adds a second, independent check: `CHALLENGE` carries a nonce,
freshness value and the peer's `pq_pub`; `AUTH` signs the transcript; the
session key is derived from an ephemeral ML-KEM-768 exchange only after the
Falcon signature verifies. A CHALLENGE/AUTH without PQ fields is refused — there
is no height window and no classical compatibility mode.

## Services

Services are addressed by name and gated by each peer's `allow` list. `*` grants
everything; a trailing `*` is a prefix grant (`storage.*`); exact names are
exact. The ACL is checked before dispatch.

| Service | Direction | Purpose |
| --- | --- | --- |
| `storage.store` | peer → node | Store a chunk in a bucket (`files` or `mail`), content-addressed and replicated to peers |
| `storage.fetch` | peer → node | Fetch a chunk by id and bucket |
| `storage.delete` | peer → node | Delete a locally held chunk; replication peers are asked best-effort |
| `dht.sync` | peer → node | Return a full KV snapshot so a reconnecting replica can catch up |
| `mail.list` | peer → node | List mailbox index entries; used by the InfMail overlay, not by consensus |
| `consensus.sign` | whitelisted consensus signer → node | Sign a 32-byte state hash with the node's Falcon key; returns the signature and node id |
| `dht.lookup`, `dht.update`, `dht.store`, `dht.find_node`, `dht.find_value` | peer → node | Kademlia routing and KV operations |
| `pubsub.subscribe`, `pubsub.unsubscribe`, `pubsub.publish`, `pubsub.relay`, `pubsub.msg` | peer → node | Topic subscription, publish and relay |
| `core.echo`, `core.ping`, `core.perf`, `core.perf.up`, `core.perf.down`, `core.poke`, `core.info`, `core.health`, `core.storage` | peer → node | Reachability, throughput, NAT probe, node info, health and storage stats |

`consensus.sign` is not a general signing oracle. It refuses a caller that is
not a configured consensus signer, requires a 64-character state-hash string,
and signs only the BLAKE3 digest of that string. Keep it out of untrusted peer
`allow` lists.

## Configuration

`infnode` reads a YAML file (`node.yaml` by default). The important transport
keys are:

| Key | Meaning |
| --- | --- |
| `name` | Local peer name used by `ping`/`send --to` and logs |
| `listen` | QUIC bind address, normally `0.0.0.0:9410` |
| `client-listen` | Optional fixed local UDP port for outbound dials (stable NAT address) |
| `advertise` | Public `IP:port` other peers should dial; set it explicitly behind NAT |
| `peers` | Static peer list (`name`, mandatory `pq-pub`, `endpoints`, `allow`, `rate-limit-per-sec`, optional `role`, `storage-roles`) |
| `allow-unknown` | Accept unknown nodes via TOFU; off by default |
| `unknown-allow` | ACL for TOFU peers; defaults to discovery only (`dht.lookup`, `dht.update`, `dht.find_node`, `dht.find_value`) |
| `roles` | Named RBAC allow-lists expanded through a peer's `role` |
| `outbox-ttl-secs` | Retention for queued outbound messages; default 3600 |
| `storage-roles` | `mail`, `files`, both, or empty for all buckets |
| `metrics-listen` | Prometheus HTTP listener, e.g. `127.0.0.1:9401`; empty disables |
| `log-level` | `0` error, `1` warn, `2` info, `3` debug |
| `domain` | Federation domain whose DNS TXT record must confirm the validator |
| `web-listen`, `web-static`, `wallet` | InfMail overlay options; not needed for L1 transport |

A minimal two-node configuration:

```yaml
# /tmp/opencode/inf-a/node.yaml
name: inf-a
listen: "127.0.0.1:9411"
advertise: "127.0.0.1:9411"
allow-unknown: false
peers:
  - name: inf-b
    pq-pub: "<node-b Falcon-512 public key, 897 bytes hex>"
    endpoints: ["127.0.0.1:9412"]
    allow: ["*"]
    rate-limit-per-sec: 50
metrics-listen: "127.0.0.1:9401"
log-level: 2
```

Node B uses `listen`/`advertise` `127.0.0.1:9412` and pins A's `pq-pub` with
endpoint `127.0.0.1:9411`. Give each node a distinct `metrics-listen` port, or
leave metrics disabled. The `pq-pub` values come from `infnode keygen`; they are
long hex strings and must match exactly.

## Rate limits and DoS caps

Every queue and table that faces the network is bounded. The shed policy is
fail-closed: refuse the new item, keep serving the existing ones.

| Control | Value |
| --- | --- |
| Static peer request budget | `rate-limit-per-sec` per peer; `0` means unlimited and is only appropriate for a fully trusted static peer |
| Dynamic/TOFU peer budget | 20 requests/second |
| Connections per peer | 8 |
| Peers with tracked connections | 4,096 |
| Concurrent sessions | 4,096 |
| Subscription topics | 1,024 |
| Subscribers per topic | 1,024 |
| Connections per `(topic, peer)` | 8 |
| Peers with a pending outbox | 1,024 |
| Outbox depth per peer | 1,024 messages |
| Outbox flush budget | 32 messages per peer per cycle |
| Dynamically admitted peers | 2,048 |
| Route table entries | 4,096 |
| Application frame | 32 MiB |
| Authentication frame | 64 KiB |
| DNS TXT record | 4,096 bytes |

The reconnect path has a per-peer circuit breaker: five consecutive dial
failures park the peer, with backoff of 20 seconds, 5 minutes and then 30
minutes (cap). A successful outbound or inbound connection closes the breaker.
Authentication failures have a separate IP ban cooldown (default 300 seconds,
`STELL_INF_AUTH_BAN_COOLDOWN_SECS`). Transport reputation and bans are routing
signals, not consensus voting power.

## Run two nodes locally

```bash
cd infnode
cargo build --release -p infnode

# Keys and an initial config; existing keys are never overwritten
./target/release/infnode keygen --dir /tmp/opencode/inf-a
./target/release/infnode keygen --dir /tmp/opencode/inf-b
```

`keygen` prints `node_id`, `pq_pub` and `kem_ek` for each node. Put each node's
`pq_pub` into the other node's `node.yaml`, set `listen`/`advertise` to `9411`
and `9412` respectively, then start them in separate terminals:

```bash
./target/release/infnode serve --config /tmp/opencode/inf-a/node.yaml
./target/release/infnode serve --config /tmp/opencode/inf-b/node.yaml
```

Verify connectivity from a third shell:

```bash
./target/release/infnode ping \
  --config /tmp/opencode/inf-a/node.yaml \
  --to inf-b --count 3

./target/release/infnode status \
  --config /tmp/opencode/inf-a/node.yaml
```

`--to` accepts either the configured peer name or an `inf1:` node id. Keep the
data directories (`keys/`, `data/`) separate: two processes must not share a
store, and a key directory must never be copied between live nodes.

## DNS seed records

A seed record is one DNS TXT string:

```text
stellereum/v1 node_id=inf1:<40 hex> pq=<897-byte Falcon-512 public key hex> host=<name> port=<udp> [kem_hash=<32-byte blake3 hex>]
```

Rules enforced by the parser:

- the first token is exactly `stellereum/v1`;
- `node_id` must equal `BLAKE3("infnode-pqid-v1" ‖ pq)[..20]` rendered with
  the `inf1:` prefix;
- `pq` is mandatory and must be a valid Falcon-512 public key;
- `host` is a DNS name and `port` is a UDP port in `1024..=65535`;
- `kem_hash` is optional and, when present, is the BLAKE3 hash of the peer's
  full 1,184-byte ML-KEM-768 encapsulation key. It is a pin: the fetched key
  must hash to this value before use;
- legacy `x=` and `ed=` pins are refused with a migration message;
- the record must fit the 4,096-byte TXT budget.

Generate the base `node_id`/`pq`/`host`/`port` records from peer stanzas in
`node.yaml` with:

```bash
../scripts/print-dns-seed-txt.sh /tmp/opencode/inf-a/node.yaml
```

The script prints one record per peer. It does not invent a `kem_hash`; add
that pin yourself only when you publish and verify a KEM encapsulation key.
DNS-discovered peers are runtime discovery peers — they are never added to the
node's consensus validator set.

## Build and test

```bash
cd infnode
cargo build --release -p infnode
cargo test -p infnode
cargo clippy -p infnode --all-targets -- -D warnings
```

The suite covers the PQ handshake and KEM KATs, frame decoding, eclipse and
routing-table attacks, ACL and cap bypass, outbox backpressure, reputation
spoofing and endpoint hygiene. A green suite is not an external audit.

## Security

No independent external audit has been completed. The transport is testnet
software; do not expose it as a public anonymity network, do not put real value
behind it, and do not disable peer pins to "make it work".

Report suspected vulnerabilities privately through [`SECURITY.md`](SECURITY.md).
Never open a public issue for a vulnerability or post a working exploit. The
in-tree downgrade, eclipse, cap-bypass and reputation-spoof batteries are
regression evidence, not a substitute for review.

Operational rules that matter:

- keep `metrics-listen` on loopback unless a trusted collector fronts it;
- keep `allow-unknown` off unless you really want TOFU peers, and keep
  `unknown-allow` at discovery-only;
- never grant `consensus.sign` or `storage.*` to an untrusted peer;
- set `rate-limit-per-sec` for every static peer; `0` is unlimited;
- protect `keys/` (`0700`) and set a key passphrase; back up the passphrase with
  the keys.

## License

MIT **or** Apache-2.0. See [`LICENSE-MIT`](LICENSE-MIT) and
[`LICENSE-APACHE`](LICENSE-APACHE).
