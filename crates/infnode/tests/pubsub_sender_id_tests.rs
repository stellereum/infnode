//! The pubsub delivery must carry the SENDER's node id, and the
//! fire-and-forget send must deliver without waiting for the peer's `RESP`.
//!
//! Why `src` matters (audit P2P A): `pubsub.msg` delivered
//! `{topic, data, msg_id}` — NO sender. The consensus receiver derives its
//! inbound rate-limiter bucket key from that envelope, so without `src` every
//! validator's traffic landed in ONE shared token bucket and a single noisy
//! peer could exhaust everybody else's budget.
//!
//! Why fire-and-forget matters (audit P2P D): `request_to` is a full
//! request/response round trip — 300-1200 ms on a WAN link — paid on every
//! vote and proposal. `send_to` writes the frame and returns; the peer still
//! processes the message exactly the same way.

use infnode::config::{NodeConfig, PeerConfig};
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::node::Node;
use std::path::PathBuf;
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

async fn next_payload(rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>, who: &str) -> String {
    tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{who} never received a message"))
        .unwrap_or_else(|| panic!("{who} subscription channel closed"))
}

#[tokio::test(flavor = "multi_thread")]
async fn pubsub_delivery_carries_the_sender_id() {
    let tmp = std::env::temp_dir().join(format!("infnode-src-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::create_dir_all(&tmp);

    let listen_a = "127.0.0.1:19420";
    let listen_b = "127.0.0.1:19421";

    let keys_a = NodeKeys::generate();
    let pq_a = PqKeys::generate();
    let keys_b = NodeKeys::generate();
    let pq_b = PqKeys::generate();

    let node_a = Node::new(
        cfg("A", listen_a, vec![peer_of("B", &keys_b, &pq_b, listen_b)]),
        keys_a.clone(),
        pq_a.clone(),
        tmp.join("a"),
        PathBuf::new(),
    )
    .await
    .expect("node A");
    let node_b = Node::new(
        cfg("B", listen_b, vec![peer_of("A", &keys_a, &pq_a, listen_a)]),
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

    let topic = "sender-id-topic";
    let mut rx_b = node_b.register_app_sub(topic).await;

    // A -> B over the ordinary request path.
    let p = serde_json::json!({ "topic": topic, "data": "payload-1" })
        .to_string()
        .into_bytes();
    node_a
        .request_to(pq_b.pq_id(), "pubsub.msg", p)
        .await
        .expect("A -> B request");
    let got = next_payload(&mut rx_b, "B").await;
    let v: serde_json::Value = serde_json::from_str(&got).expect("delivery is JSON");
    assert_eq!(
        v["src"].as_str(),
        Some(hex::encode(pq_a.pq_id()).as_str()),
        "the delivery must name the SENDER (A), got {got}"
    );
    assert_eq!(v["data"].as_str(), Some("payload-1"));

    // A -> B over the FIRE-AND-FORGET path: same delivery, no `RESP` awaited.
    let p = serde_json::json!({ "topic": topic, "data": "payload-2" })
        .to_string()
        .into_bytes();
    node_a
        .send_to(pq_b.pq_id(), "pubsub.msg", p)
        .await
        .expect("A -> B fire-and-forget send");
    let got = next_payload(&mut rx_b, "B").await;
    let v: serde_json::Value = serde_json::from_str(&got).expect("delivery is JSON");
    assert_eq!(v["data"].as_str(), Some("payload-2"));
    assert_eq!(
        v["src"].as_str(),
        Some(hex::encode(pq_a.pq_id()).as_str()),
        "the fire-and-forget delivery must name the SENDER too, got {got}"
    );

    a_serve.abort();
    b_serve.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}
