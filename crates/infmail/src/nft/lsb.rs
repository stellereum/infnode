//! lsb.rs — LSB-стеганография для NFT-карточек InfMail.
//!
//! Встраивает в RGBA-пиксели скрытый payload (как в NFT_DEVELOPMENT_PLAN.md):
//!   Magic "IMLS" (4) + Version (1) + Len u16 BE (2) + Payload + Ed25519 Sig (64) + padding
//!
//! Payload: { email, tokenId, contractAddr, creatorWallet, imageHash, timestamp }
//! Подпись: Ed25519(SHA256(payload)) ключом из env NFT_SIGNING_SECRET.
//!
//! Верификация в dApp: Canvas getImageData → extract LSB → verify Ed25519.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"IMLS";
const VERSION: u8 = 1;
const SIG_LEN: usize = 64;
const PADDING: usize = 16;

/// Встроить байты в LSB-пространство пикселей, начиная с bit_offset.
fn write_bits(pixels: &mut [u8], start_bit: usize, data: &[u8]) {
    for (j, b) in data.iter().enumerate() {
        for i in 0..8 {
            let bit = (b >> (7 - i)) & 1;
            let idx = start_bit + j * 8 + i;
            pixels[idx] = (pixels[idx] & 0xFE) | bit;
        }
    }
}

/// Прочитать nbytes байтов из LSB-пространства, начиная с bit_offset.
fn read_bytes(pixels: &[u8], start_bit: usize, nbytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(nbytes);
    for j in 0..nbytes {
        let mut v: u8 = 0;
        for i in 0..8 {
            let bit = pixels[start_bit + j * 8 + i] & 1;
            v |= bit << (7 - i);
        }
        out.push(v);
    }
    out
}

/// Встроить payload + подпись в RGBA-пиксели.
pub fn embed(pixels: &mut [u8], payload: &[u8], signing_key: &SigningKey) -> Result<(), String> {
    let total = 4 + 1 + 2 + payload.len() + SIG_LEN + PADDING;
    let capacity = pixels.len() / 8;
    if total > capacity {
        return Err(format!("payload {total} > capacity {capacity}"));
    }
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    // подпись: Ed25519(SHA256(payload))
    let hash = Sha256::digest(payload);
    let sig: Signature = signing_key.sign(&hash);
    let sig_bytes = sig.to_bytes();

    write_bits(pixels, 0, &header);
    let payload_bit = (4 + 1 + 2) * 8;
    write_bits(pixels, payload_bit, payload);
    let sig_bit = (4 + 1 + 2 + payload.len()) * 8;
    write_bits(pixels, sig_bit, &sig_bytes);
    Ok(())
}

/// Извлечь payload + подпись из RGBA-пикселей. Ошибка если magic не найден.
pub fn extract(pixels: &[u8]) -> Result<(Vec<u8>, [u8; SIG_LEN]), String> {
    if pixels.len() < (4 + 1 + 2 + SIG_LEN) * 8 {
        return Err("картинка слишком мала для LSB".into());
    }
    let magic = read_bytes(pixels, 0, 4);
    if magic != MAGIC {
        return Err("magic IMLS не найден — картинка не от InfMail".into());
    }
    let ver = read_bytes(pixels, 32, 1)[0];
    if ver != VERSION {
        return Err(format!("неподдерживаемая версия {ver}"));
    }
    let lenb = read_bytes(pixels, 40, 2);
    let len = ((lenb[0] as usize) << 8) | lenb[1] as usize;
    let needed_bits = (4 + 1 + 2 + len + SIG_LEN).saturating_mul(8);
    if pixels.len() < needed_bits {
        return Err("картинка слишком мала для LSB payload".into());
    }
    let payload = read_bytes(pixels, 56, len);
    let sig_bytes = read_bytes(pixels, (4 + 1 + 2 + len) * 8, SIG_LEN);
    let mut sig = [0u8; SIG_LEN];
    sig.copy_from_slice(&sig_bytes[..SIG_LEN]);
    Ok((payload, sig))
}

/// Верифицировать подпись payload публичным ключом.
pub fn verify(payload: &[u8], sig: &[u8; SIG_LEN], pubkey_hex: &str) -> bool {
    let pk_bytes = match hex::decode(pubkey_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let Ok(pk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let hash = Sha256::digest(payload);
    let sig = Signature::from_bytes(sig);
    pk.verify(&hash, &sig).is_ok()
}

/// Публичный ключ (hex) из env NFT_SIGNING_SECRET (Ed25519 seed) — для /verify.
pub fn public_key_hex() -> Option<String> {
    let secret = std::env::var("NFT_SIGNING_SECRET").ok()?;
    let seed = decode_secret(&secret)?;
    let sk = SigningKey::from_bytes(&seed);
    Some(hex::encode(sk.verifying_key().to_bytes()))
}

/// Расшифровать NFT_SIGNING_SECRET: hex 64 символа (seed) или base64.
fn decode_secret(s: &str) -> Option<[u8; 32]> {
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let b = hex::decode(s).ok()?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&b[..32]);
        return Some(out);
    }
    let b = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[..32]);
    Some(out)
}

/// Загрузить подписывающий ключ из env (или None если не задан).
pub fn signing_key() -> Option<SigningKey> {
    let secret = std::env::var("NFT_SIGNING_SECRET").ok()?;
    let seed = decode_secret(&secret)?;
    Some(SigningKey::from_bytes(&seed))
}

/// Подписать payload и вернуть hex-подпись (для отладки/verify).
pub fn sign_hex(payload: &[u8], sk: &SigningKey) -> String {
    let hash = Sha256::digest(payload);
    hex::encode(sk.sign(&hash).to_bytes())
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// Честный verify end-to-end: вшить payload в пиксели -> закодировать PNG ->
    /// декодировать -> извлечь -> проверить подпись. Подделка (перевёрнутый бит)
    /// должна дать authentic=false.
    #[test]
    fn honest_verify_roundtrip_and_tamper() {
        let sk = test_key();
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        let payload = br#"{"email":"test@infmail.org","tokenId":0}"#;
        // 64x64 RGBA пикселей достаточно для payload+sig
        let mut pixels = vec![128u8; 64 * 64 * 4];
        embed(&mut pixels, payload, &sk).expect("embed");
        // кодируем PNG (как это делает pngjs на сервисе карточек)
        let mut png_bytes = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut png_bytes, 64, 64);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            let mut w = enc.write_header().unwrap();
            w.write_image_data(&pixels).unwrap();
        }
        // декодируем обратно (путь nft_verify -> decode_png_rgba)
        let decoder = png::Decoder::new(std::io::Cursor::new(&png_bytes));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0u8; reader.output_buffer_size()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(info.color_type, png::ColorType::Rgba);
        let rgba = buf[..64 * 64 * 4].to_vec();
        // извлекаем и проверяем — должно быть true
        let (out, sig) = extract(&rgba).expect("extract");
        assert_eq!(out, payload);
        assert!(verify(&out, &sig, &pubkey), "valid card must verify");
        // подделка: переворачиваем бит payload — подпись ломается
        let mut bad = rgba.clone();
        bad[100] ^= 1;
        let bad_res = extract(&bad)
            .map(|(p, s)| verify(&p, &s, &pubkey))
            .unwrap_or(false);
        assert!(!bad_res, "tampered card must NOT verify");
    }

    #[test]
    fn truncated_payload_length_returns_err_without_panic() {
        let mut pixels = vec![0u8; (4 + 1 + 2 + SIG_LEN) * 8];
        write_bits(&mut pixels, 0, MAGIC);
        write_bits(&mut pixels, 32, &[VERSION]);
        // Declare a payload length larger than the remaining pixels.
        write_bits(&mut pixels, 40, &u16::MAX.to_be_bytes());
        assert!(extract(&pixels).is_err());
    }
}
