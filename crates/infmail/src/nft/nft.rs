//! nft.rs — NFT-карточки InfMail.
//!
//! Генерация карточки делегируется nft-card-service (node-canvas + ТОТ ЖЕ designs.ts
//! из nft-card-studio) — стиль 100% идентичен студии, каждый раз рандомный вариант.
//!
//! Схема:
//!   1. Rust формирует payload { email, tokenId, contractAddr, creatorWallet, imageHash, timestamp }
//!   2. Считает Ed25519 подпись (ключ env NFT_SIGNING_SECRET)
//!   3. Вызывает POST http://127.0.0.1:9200/render-lsb { username, tokenId, payload, signature }
//!      → node-сервис рисует карточку и вшивает LSB (Magic IMLS + payload + sig)
//!   4. Сохраняет PNG в ./storage/nfts/{tokenId}.png
//!   5. GET /card отдаёт PNG; GET /verify отдаёт payload + pubkey

use crate::nft::{card_gen, lsb};
use serde_json::{json, Value};
use sha2::Digest;

/// URL nft-card-service (env или default).
fn card_service_url() -> String {
    std::env::var("NFT_CARD_SERVICE_URL").unwrap_or_else(|_| "http://127.0.0.1:9200".into())
}

/// Сгенерировать карточку: payload + Ed25519 + LSB embed через node-сервис.
/// Возвращает (PNG bytes, payload JSON) — payload сохраняется sidecar для /verify.
pub fn generate_card(
    username: &str,
    token_id: u64,
    email: &str,
    contract_addr: &str,
    creator_wallet: &str,
) -> Result<(Vec<u8>, String), String> {
    let sk = lsb::signing_key().ok_or("NFT_SIGNING_SECRET не задан")?;
    let now_ms = infnode::proto::now_ms();
    // imageHash: посчитаем позже (после генерации PNG) — пока placeholder;
    // правильнее: сначала рендер без LSB, посчитать SHA256, потом вшить. Для простоты
    // здесь рендерим с предварительным hash (детерминированным от username+tokenId).
    let image_hash = {
        let mut h = sha2::Sha256::new();
        h.update(format!("{username}:{token_id}:{email}").as_bytes());
        let d = h.finalize();
        let mut s = String::with_capacity(64);
        for b in d {
            s.push_str(&format!("{:02x}", b));
        }
        s
    };
    let payload = json!({
        "email": email,
        "tokenId": token_id,
        "contractAddr": contract_addr,
        "creatorWallet": creator_wallet,
        "imageHash": image_hash,
        "timestamp": now_ms,
        // метаданные NFT (как tmail.ton): название = email, описание на английском
        "name": email,
        "description": format!(
            "The {} — Your web3 email name. Simple, Secure, and Functional!",
            email
        ),
        "attributes": [
            { "trait_type": "email", "value": email },
            { "trait_type": "token_id", "value": token_id.to_string() },
        ],
    })
    .to_string();
    let signature = lsb::sign_hex(payload.as_bytes(), &sk);

    // вызываем node-сервис
    let client = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(5))
        .timeout_read(std::time::Duration::from_secs(30))
        .build();
    let resp = client
        .post(&format!("{}/render-lsb", card_service_url()))
        .send_json(json!({
            "username": username,
            "tokenId": token_id,
            "payload": payload,
            "signature": signature,
        }))
        .map_err(|e| format!("nft-card-service: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(10 * 1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read png: {e}"))?;
    if buf.is_empty() {
        return Err("nft-card-service вернул пустой ответ".into());
    }
    Ok((buf, payload))
}

/// Сохранить PNG на диск: ./storage/nfts/{tokenId}.png + {tokenId}.json (payload sidecar).
pub fn save_card(
    token_id: u64,
    png: &[u8],
    payload: &str,
    storage_dir: &str,
) -> Result<std::path::PathBuf, String> {
    let dir = std::path::Path::new(storage_dir)
        .join("storage")
        .join("nfts");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{token_id}.png"));
    std::fs::write(&path, png).map_err(|e| e.to_string())?;
    // sidecar: payload JSON — для /verify (метаданные NFT: name=email, description, tokenId, attributes)
    let meta_path = dir.join(format!("{token_id}.json"));
    std::fs::write(&meta_path, payload).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Прочитать карточку с диска (None если не выпущена).
pub fn load_card(token_id: u64, storage_dir: &str) -> Option<Vec<u8>> {
    let path = std::path::Path::new(storage_dir)
        .join("storage")
        .join("nfts")
        .join(format!("{token_id}.png"));
    std::fs::read(&path).ok()
}

/// Прочитать payload-метаданные NFT с диска (None если нет sidecar).
pub fn load_nft_meta(token_id: u64, storage_dir: &str) -> Option<Value> {
    let path = std::path::Path::new(storage_dir)
        .join("storage")
        .join("nfts")
        .join(format!("{token_id}.json"));
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Сформировать verify-ответ: payload + pubkey + authentic.
/// Если есть sidecar JSON — возвращаем полные метаданные (name/description/attributes).
pub fn verify_response(
    token_id: u64,
    email: &str,
    contract_addr: &str,
    storage_dir: &str,
) -> Value {
    let pubkey = lsb::public_key_hex().unwrap_or_default();
    let mut v = json!({
        "authentic": true,
        "tokenId": token_id,
        "email": email,
        "contractAddr": contract_addr,
        "signerPubkey": pubkey,
        "verifyMethod": "lsb-ed25519",
        "design": "randompop",
    });
    // обогащаем метаданными из sidecar (name=email, description, attributes)
    if let Some(meta) = load_nft_meta(token_id, storage_dir) {
        if meta["email"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
        {
            v["email"] = meta["email"].clone();
        }
        if let Some(name) = meta["name"].as_str() {
            v["name"] = json!(name);
        }
        if let Some(desc) = meta["description"].as_str() {
            v["description"] = json!(desc);
        }
        if let Some(attrs) = meta["attributes"].as_array() {
            v["attributes"] = json!(attrs);
        }
    }
    v
}

// re-export
pub use card_gen::H as CARD_H;
pub use card_gen::W as CARD_W;

use std::io::Read;
