//! Regression tests for concurrent per-stream handling in `frame_loop`.
//!
//! Before the change the accept loop awaited `handle_stream` for every stream,
//! so ONE slow or malformed stream stalled every other stream on the same QUIC
//! connection (and an error tore the whole connection down). After the change,
//! once a connection is authenticated each stream runs in its own task:
//!   * a hung stream no longer blocks concurrent requests, and
//!   * a failing stream is log-only and never kills the connection.
//!
//! These tests drive two real nodes over real QUIC using the crate's public
//! API plus the raw `quinn::Connection` held by `Node::peers` — the same harness
//! style as `pubsub_bidir_tests.rs`.

use infnode::config::{NodeConfig, PeerConfig};
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::node::Node;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn cfg(
    name: &str,
    listen: &str,
    peers: Vec<PeerConfig>,
    allow_unknown: bool,
    unknown_allow: Vec<String>,
) -> NodeConfig {
    NodeConfig {
        name: name.to_string(),
        listen: listen.to_string(),
        client_listen: None,
        advertise: None,
        peers,
        allow_unknown,
        unknown_allow,
        metrics_listen: None,
        log_level: Some(0),
        roles: Default::default(),
        outbox_ttl_secs: 3600,
        storage_roles: vec![],
        validators: vec![],
        domain: None,
        web_listen: None,
        wallet: None,
        web_static: None,
    }
}

fn peer_of(name: &str, keys: &NodeKeys, pq: &PqKeys, listen: &str) -> PeerConfig {
    PeerConfig {
        name: name.to_string(),
        ed_pub: hex::encode(keys.verifying.to_bytes()),
        pq_pub: Some(pq.pq_pub_hex()),
        endpoints: vec![listen.to_string()],
        allow: vec!["*".to_string()],
        rate_limit_per_sec: 0,
        role: None,
        storage_roles: vec![],
    }
}

struct Pair {
    node_a: Arc<Node>,
    node_b: Arc<Node>,
    pq_a: PqKeys,
    pq_b: PqKeys,
    tmp: PathBuf,
    a_serve: tokio::task::JoinHandle<anyhow::Result<()>>,
    b_serve: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Pair {
    async fn start(tag: &str, listen_a: &str, listen_b: &str) -> Pair {
        let tmp = std::env::temp_dir().join(format!("infnode-conc-{}-{}", tag, std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);

        // One-directional topology on purpose: A accepts unknown B (TOFU) and has
        // no configured peers, so only B ever dials. That keeps exactly ONE QUIC
        // connection per node, making the connection-liveness assertions
        // unambiguous (`stable_id()` is local to each endpoint).
        //
        // B must also be the LOWER PQ node id: `connect_or_get` implements a
        // tie-break where only the lower id initiates (simultaneous open made
        // both handshakes abort -- 6 failed handshakes/second on the live
        // stand). Generate until B wins the coin toss so this fixture keeps
        // its "only B dials" property under that rule (FULL-PQ: tie-break by
        // PQ id via `ceremony_local_id`, same construction as `Node::new`).
        let keys_a = NodeKeys::generate();
        let pq_a = PqKeys::generate();
        let mut keys_b = NodeKeys::generate();
        let mut pq_b = PqKeys::generate();
        for _ in 0..128 {
            let ida = infnode::node::ceremony_local_id(&keys_a, &pq_a);
            let idb = infnode::node::ceremony_local_id(&keys_b, &pq_b);
            if idb < ida {
                break;
            }
            keys_b = NodeKeys::generate();
            pq_b = PqKeys::generate();
        }
        assert!(
            infnode::node::ceremony_local_id(&keys_b, &pq_b)
                < infnode::node::ceremony_local_id(&keys_a, &pq_a),
            "could not generate a B key with a lower PQ node id"
        );
        let node_a = Node::new(
            cfg(
                "A",
                listen_a,
                vec![peer_of("B", &keys_b, &pq_b, listen_b)],
                false,
                vec![],
            ),
            keys_a.clone(),
            pq_a.clone(),
            tmp.join("a"),
            PathBuf::new(),
        )
        .await
        .expect("node A");
        let node_b = Node::new(
            cfg(
                "B",
                listen_b,
                vec![peer_of("A", &keys_a, &pq_a, listen_a)],
                false,
                vec![],
            ),
            keys_b.clone(),
            pq_b.clone(),
            tmp.join("b"),
            PathBuf::new(),
        )
        .await
        .expect("node B");

        let a_serve = {
            let n = node_a.clone();
            tokio::spawn(async move { n.serve().await })
        };
        let b_serve = {
            let n = node_b.clone();
            tokio::spawn(async move { n.serve().await })
        };
        // Give both listeners a moment to bind.
        tokio::time::sleep(Duration::from_millis(300)).await;

        Pair {
            node_a,
            node_b,
            pq_a,
            pq_b,
            tmp,
            a_serve,
            b_serve,
        }
    }

    async fn conn_b(&self) -> quinn::Connection {
        let peer = self
            .node_b
            .peers
            .read()
            .await
            .get(&self.pq_a.pq_id())
            .cloned()
            .expect("B knows A");
        let conn = peer.conn.read().await.clone();
        conn.expect("B has a live connection to A")
    }

    async fn conn_a(&self) -> Option<usize> {
        let peer = self
            .node_a
            .peers
            .read()
            .await
            .get(&self.pq_b.pq_id())
            .cloned()
            .expect("A knows B");
        let sid = peer.conn.read().await.as_ref().map(|c| c.stable_id());
        sid
    }

    fn stop(&self) {
        self.a_serve.abort();
        self.b_serve.abort();
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

/// Establish (and authenticate) the B -> A connection and return B's handle to it.
async fn warm_up(p: &Pair) -> quinn::Connection {
    let echo = tokio::time::timeout(
        Duration::from_secs(10),
        p.node_b
            .request_to(p.pq_a.pq_id(), "core.echo", b"warm".to_vec()),
    )
    .await
    .expect("warm-up timed out")
    .expect("warm-up failed");
    assert_eq!(echo, b"warm");
    p.conn_b().await
}

#[tokio::test(flavor = "multi_thread")]
async fn two_concurrent_streams_both_get_responses() {
    let p = Pair::start("parallel", "127.0.0.1:19520", "127.0.0.1:19521").await;
    let conn = warm_up(&p).await;

    // Hold one stream open WITHOUT finishing it. On the server side this stream
    // parks inside `read_to_end` until the read timeout (5s), so a serial accept
    // loop would be unable to pick up any other stream while it waits.
    let (mut slow_send, _slow_recv) = conn.open_bi().await.expect("open slow stream");
    slow_send
        .write_all(b"unterminated stream that blocks frame handling")
        .await
        .expect("write slow stream");
    // Let A accept the slow stream and start handling it.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // A second REQ stream must be served in parallel, well within the 5s read
    // timeout that the slow stream is burning.
    let fast = tokio::time::timeout(
        Duration::from_secs(3),
        p.node_b
            .request_to(p.pq_a.pq_id(), "core.echo", b"fast".to_vec()),
    )
    .await
    .expect("concurrent request was blocked behind the hung stream")
    .expect("concurrent request failed");
    assert_eq!(fast, b"fast");

    drop(slow_send);
    p.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn failing_stream_does_not_kill_connection() {
    let p = Pair::start("failing", "127.0.0.1:19530", "127.0.0.1:19531").await;
    let conn = warm_up(&p).await;
    // `stable_id()` is local to each endpoint, so record each side separately.
    let sid_b0 = conn.stable_id();
    let sid_a0 = p.conn_a().await.expect("warm-up conn not registered on A");

    // A malformed stream must fail ONLY that stream, not the connection.
    let (mut bad_send, _bad_recv) = conn.open_bi().await.expect("open bad stream");
    bad_send
        .write_all(b"this is not a valid infnode frame")
        .await
        .expect("write bad stream");
    let _ = bad_send.finish();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The connection on the server must still be the very same one.
    assert_eq!(
        p.conn_a().await,
        Some(sid_a0),
        "server dropped the connection after a single failing stream"
    );

    // And a subsequent stream is still served (no reconnect required).
    let after = tokio::time::timeout(
        Duration::from_secs(5),
        p.node_b
            .request_to(p.pq_a.pq_id(), "core.echo", b"after".to_vec()),
    )
    .await
    .expect("post-failure request timed out")
    .expect("post-failure request failed");
    assert_eq!(after, b"after");
    assert_eq!(
        p.conn_b().await.stable_id(),
        sid_b0,
        "a failing stream forced a reconnect"
    );

    p.stop();
}
