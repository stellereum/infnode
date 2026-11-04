//! Regression test for the one-way pubsub bug (the fix that unblocked the
//! two-node blockchain test).
//!
//! Before the fix, `connect_or_get` created an outbound connection but never
//! started a receive loop on it. A node that had only ever *dialled* a peer
//! could therefore send requests but never process the messages the peer pushed
//! back on that same connection. In the blockchain that showed up as: node A
//! received 66 consensus messages, node B received 0, and the chain sat at
//! height 1 forever with no error anywhere.
//!
//! Note on scope: this test pins the *guarantee* (delivery works both ways
//! between two real nodes), not the original race. The race needs the dialer to
//! lose a startup race with the reconnect loop, which is not deterministic to
//! force in a unit test. The reproduction that actually proved the bug was the
//! two-node blockchain on a real server: the same binary failed with A=66 / B=0
//! and passed on both directions once the receive loop was started on outbound
//! connections. This test locks the guarantee so that cannot regress silently.
//!
//! This test wires two real nodes over real QUIC and asserts delivery works in
//! BOTH directions — especially from the node that dialed.

use infnode::config::{NodeConfig, PeerConfig};
use infnode::keyring::NodeKeys;
use infnode::node::Node;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn cfg(name: &str, listen: &str, peers: Vec<PeerConfig>) -> NodeConfig {
    NodeConfig {
        name: name.to_string(),
        listen: listen.to_string(),
        client_listen: None,
        advertise: None,
        peers,
        allow_unknown: false,
        unknown_allow: vec![],
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

fn peer_of(name: &str, keys: &NodeKeys, listen: &str) -> PeerConfig {
    PeerConfig {
        name: name.to_string(),
        node_id: keys.id_hex(),
        ed_pub: hex::encode(keys.verifying.to_bytes()),
        x_pub: hex::encode(keys.e2e_pub.as_bytes()),
        pq_pub: None,
        endpoints: vec![listen.to_string()],
        allow: vec!["*".to_string()],
        rate_limit_per_sec: 0,
        role: None,
        storage_roles: vec![],
    }
}

/// Ask a peer to add us to its network-subscription table for `topic`.
async fn subscribe_at_peer(me: &Arc<Node>, peer_id: [u8; 20], topic: &str) {
    let payload = serde_json::json!({ "topic": topic })
        .to_string()
        .into_bytes();
    tokio::time::timeout(
        Duration::from_secs(5),
        me.request_to(peer_id, "pubsub.subscribe", payload),
    )
    .await
    .expect("pubsub.subscribe timed out")
    .expect("pubsub.subscribe failed");
}

async fn expect_payload(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    needle: &str,
    who: &str,
) {
    let got = tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{who} never received a message containing {needle}"))
        .unwrap_or_else(|| panic!("{who} subscription channel closed"));
    assert!(
        got.contains(needle),
        "{who} received the wrong payload: {got}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pubsub_delivers_in_both_directions() {
    let tmp = std::env::temp_dir().join(format!("infnode-bidir-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);

    let listen_a = "127.0.0.1:19410";
    let listen_b = "127.0.0.1:19411";

    // Both identities first, so each config can pin the other.
    let keys_a = NodeKeys::generate();
    let keys_b = NodeKeys::generate();

    let node_a = Node::new(
        cfg("A", listen_a, vec![peer_of("B", &keys_b, listen_b)]),
        keys_a.clone(),
        tmp.join("a"),
        PathBuf::new(),
    )
    .await
    .expect("node A");
    let node_b = Node::new(
        cfg("B", listen_b, vec![peer_of("A", &keys_a, listen_a)]),
        keys_b.clone(),
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

    let topic = "regression-bidir";
    let mut rx_a = node_a.register_app_sub(topic).await;
    let mut rx_b = node_b.register_app_sub(topic).await;

    // B is the one that will dial A below; this is the connection that used to
    // have no receive loop on B's side.
    subscribe_at_peer(&node_b, keys_a.id(), topic).await;
    subscribe_at_peer(&node_a, keys_b.id(), topic).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A -> B
    let p = serde_json::json!({ "topic": topic, "data": "a2b" })
        .to_string()
        .into_bytes();
    node_a
        .request_to(keys_b.id(), "pubsub.msg", p)
        .await
        .expect("A -> B request");
    expect_payload(&mut rx_b, "a2b", "B").await;

    // B -> A: the direction that used to be dead, because B is the dialer.
    let p = serde_json::json!({ "topic": topic, "data": "b2a" })
        .to_string()
        .into_bytes();
    node_b
        .request_to(keys_a.id(), "pubsub.msg", p)
        .await
        .expect("B -> A request");
    expect_payload(&mut rx_a, "b2a", "A").await;

    // Repeat, so a one-shot connection race cannot pass by luck.
    for i in 0..3 {
        let p = serde_json::json!({ "topic": topic, "data": format!("b2a-{i}") })
            .to_string()
            .into_bytes();
        node_b
            .request_to(keys_a.id(), "pubsub.msg", p)
            .await
            .expect("B -> A repeat request");
        expect_payload(&mut rx_a, &format!("b2a-{i}"), "A").await;
    }

    a_serve.abort();
    b_serve.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}
