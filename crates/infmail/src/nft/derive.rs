//! derive.rs — деривация ключей шифрования от кошелька владельца NFT (П.3).
//!
//! Идея: письма NFT-аккаунта шифруются ключом, детерминированно выведенным из
//! публичного ключа кошелька. Только владелец кошелька может вычислить приватный
//! ключ (через подпись), поэтому смена владельца меняет ключ → новый владелец
//! видит только письма за своё время.

use blake3::Hasher;
use ed25519_dalek::VerifyingKey;
use serde_json::json;

/// Домен деривации — не даёт пересекаться с другими ключами.
const DERIVE_DOMAIN: &str = "infmail-nft-key-v1";

/// Вывести ML-KEM-768 публичный ключ из ed25519-публичного ключа кошелька.
/// Детерминированно: blake3(domain + ed_pub) x2 → 64B seed → ML-KEM.
/// FULL-PQ: X25519 удалён (wipe).
///
/// ВНИМАНИЕ (безопасность): НЕ использовать как ключ ШИФРОВАНИЯ писем — wallet_ed_pub
/// публичен, значит соответствующий KEM-СИД вычислим любым, кто знает
/// wallet_ed_pub. Это сломало бы шифрование. Приватный ключ для расшифровки должен
/// выводиться из ПОДПИСИ кошелька (секрета) в браузере, не из публичного ключа.
/// Данная функция полезна только как СЛУЖЕБНАЯ (эпоха/метка владельца, тесты).
pub fn derive_x_pub(wallet_ed_pub_hex: &str) -> Result<String, String> {
    let ed_bytes =
        hex::decode(wallet_ed_pub_hex).map_err(|_| "wallet ed_pub: invalid hex".to_string())?;
    // валидируем ed25519 публичный ключ
    let vk = VerifyingKey::from_bytes(
        ed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "wallet ed_pub: must be 32 bytes".to_string())?,
    )
    .map_err(|e| format!("wallet ed_pub: {e}"))?;
    // 64B seed из blake3(domain || ed_pub) x2 (domain-separated halves).
    let mut h1 = Hasher::new();
    h1.update(DERIVE_DOMAIN.as_bytes());
    h1.update(b":1:");
    h1.update(vk.as_bytes());
    let half1 = h1.finalize();
    let mut h2 = Hasher::new();
    h2.update(DERIVE_DOMAIN.as_bytes());
    h2.update(b":2:");
    h2.update(vk.as_bytes());
    let half2 = h2.finalize();
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&half1.as_bytes()[..32]);
    seed[32..].copy_from_slice(&half2.as_bytes()[..32]);
    Ok(hex::encode(infnode::mailbox::kem_ek_from_seed(&seed)))
}

/// Вывести "эпоху" ключей: хэш, меняющийся при смене кошелька.
/// Используется для пометки писем: письмо читаемо только владельцем своего кошелька.
pub fn wallet_epoch(wallet_ed_pub_hex: &str) -> String {
    let mut h = Hasher::new();
    h.update(b"infmail-nft-epoch-v1:");
    h.update(wallet_ed_pub_hex.as_bytes());
    hex::encode(h.finalize().as_bytes())
}

/// Ответ для API: производный x_pub + эпоха владельца (служебный, из pub — НЕ для шифрования).
pub fn derive_response(wallet_ed_pub_hex: &str) -> serde_json::Value {
    match derive_x_pub(wallet_ed_pub_hex) {
        Ok(x_pub) => json!({
            "ok": true,
            "x_pub": x_pub,
            "epoch": wallet_epoch(wallet_ed_pub_hex),
            "method": "blake3(infmail-nft-key-v1 + wallet_ed_pub) -> x25519",
        }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

/// Домен деривации КЛЮЧЕЙ ШИФРОВАНИЯ из ПОДПИСИ (безопасная ветка П.3).
const SIG_DERIVE_DOMAIN: &str = "infmail-nft-keys-sig-v1";

/// Вывести ML-KEM-768 публичный ключ ШИФРОВАНИЯ из ПОДПИСИ кошелька (ed25519, 64 байта).
/// FULL-PQ: X25519 удалён (wipe).
///
/// Почему из подписи, а не из публичного ключа (см. derive_x_pub): подпись секретна —
/// её знает только владелец приватного ed25519 ключа кошелька. Поэтому из неё можно
/// безопасно вывести и KEM-СИД (для расшифровки) в браузере, и публичный
/// (для шифрования на бэкенде). Публичный ed_pub кошелька виден всем → выводить из него
/// приватный ключ нельзя (сломало бы шифрование).
///
/// Схема: владелец подписывает фиксированное сообщение "infmail-keys-v1:{email}".
///   master_seed = blake3(SIG_DERIVE_DOMAIN || подпись) x2 halves → 64B KEM seed
///   kem_ek = ML-KEM-768(master_seed)
/// Подпись детерминированна (тот же кошелёк + то же сообщение → та же подпись), значит
/// тот же владелец всегда выводит тот же ключ. Другой кошелёк → другая подпись → другой
/// ключ → смена владельца NFT делает старые письма нечитаемыми (эпоха).
pub fn derive_x_pub_from_signature(sig_hex: &str) -> Result<String, String> {
    let sig = hex::decode(sig_hex).map_err(|_| "signature: invalid hex".to_string())?;
    if sig.len() != 64 {
        return Err("signature: must be 64 bytes (ed25519)".to_string());
    }
    let mut h1 = Hasher::new();
    h1.update(SIG_DERIVE_DOMAIN.as_bytes());
    h1.update(b":1:");
    h1.update(&sig);
    let half1 = h1.finalize();
    let mut h2 = Hasher::new();
    h2.update(SIG_DERIVE_DOMAIN.as_bytes());
    h2.update(b":2:");
    h2.update(&sig);
    let half2 = h2.finalize();
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&half1.as_bytes()[..32]);
    seed[32..].copy_from_slice(&half2.as_bytes()[..32]);
    Ok(hex::encode(infnode::mailbox::kem_ek_from_seed(&seed)))
}

/// Эпоха ключей из подписи: меняется при смене кошелька владельца.
pub fn signature_epoch(sig_hex: &str) -> String {
    let mut h = Hasher::new();
    h.update(b"infmail-nft-sig-epoch-v1:");
    h.update(sig_hex.as_bytes());
    hex::encode(h.finalize().as_bytes())
}

/// Ответ для API: x_pub шифрования из подписи + эпоха.
pub fn derive_response_from_signature(sig_hex: &str) -> serde_json::Value {
    match derive_x_pub_from_signature(sig_hex) {
        Ok(x_pub) => json!({
            "ok": true,
            "x_pub": x_pub,
            "epoch": signature_epoch(sig_hex),
            "method": "blake3(infmail-nft-keys-sig-v1 + signature) -> x25519",
            "secure": true,
        }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_deterministic() {
        // ed_pub кошелька (32 байта, из тестового seed)
        let ed_pub = "3d695b8c3a5f70036fe49a7c03708330396d44e617ca4b6831a54985a8bdf95e";
        let x1 = derive_x_pub(ed_pub).unwrap();
        let x2 = derive_x_pub(ed_pub).unwrap();
        assert_eq!(x1, x2, "деривация должна быть детерминированной");
        assert_eq!(x1.len(), 2368, "ML-KEM-768 ek = 1184 байта hex");
        // другой кошелёк → другой ключ (смена владельца меняет ключ)
        let ed_pub2 = "136e8287057a8f121d897e83276542ea83ae036edf85ec8444a84d06baec548e";
        let x3 = derive_x_pub(ed_pub2).unwrap();
        assert_ne!(x1, x3, "разные кошельки → разные ключи");
        // эпохи
        assert_ne!(wallet_epoch(ed_pub), wallet_epoch(ed_pub2));
    }

    #[test]
    fn derive_rejects_bad_pub() {
        assert!(derive_x_pub("nothex").is_err());
        assert!(derive_x_pub("abcd").is_err()); // не 32 байта
    }

    #[test]
    fn derive_from_signature_deterministic() {
        // реальная подпись p3test (ed25519) сообщения "infmail-keys-v1:testp3@infmail.org"
        let sig = "f078a5a6ae9f9d2594342e57795ad26aa5c71d2eb5a1c901e15f2681fb0ee5f4d7b92bd81b2725157109e92113bc300a5a58a804f64f71e5168ceae13e269e03";
        let x1 = derive_x_pub_from_signature(sig).unwrap();
        let x2 = derive_x_pub_from_signature(sig).unwrap();
        assert_eq!(x1, x2, "деривация из подписи детерминированна");
        assert_eq!(x1.len(), 2368, "ML-KEM-768 ek = 1184 байта hex");
        // другая подпись (другой кошелёк) → другой ключ
        let sig2 = "0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000";
        let x3 = derive_x_pub_from_signature(sig2).unwrap();
        assert_ne!(x1, x3, "разные кошельки → разные ключи шифрования");
        assert_ne!(signature_epoch(sig), signature_epoch(sig2));
    }

    #[test]
    fn derive_from_signature_rejects_bad() {
        assert!(derive_x_pub_from_signature("nothex").is_err());
        assert!(derive_x_pub_from_signature("abcd").is_err()); // < 64 байт
    }

    /// E2E П.3: шифрование письма на KEM-ek (производный от подписи кошелька)
    /// → владелец кошелька расшифровывает (KEM-сид из той же подписи),
    /// другой кошелёк — НЕ может (эпоха/owner_changed).
    #[test]
    fn p3_e2e_encrypt_decrypt_via_signature() {
        // подпись p3test на "infmail-keys-v1:testp3@infmail.org"
        let sig = "f078a5a6ae9f9d2594342e57795ad26aa5c71d2eb5a1c901e15f2681fb0ee5f4d7b92bd81b2725157109e92113bc300a5a58a804f64f71e5168ceae13e269e03";
        let x_pub_hex = derive_x_pub_from_signature(sig).expect("derive");
        assert_eq!(x_pub_hex.len(), 2368);

        // KEM-сид владельца из той же подписи (та же схема halves, что derive).
        let sig_bytes = hex::decode(sig).unwrap();
        let mut h1 = Hasher::new();
        h1.update(SIG_DERIVE_DOMAIN.as_bytes());
        h1.update(b":1:");
        h1.update(&sig_bytes);
        let half1 = h1.finalize();
        let mut h2 = Hasher::new();
        h2.update(SIG_DERIVE_DOMAIN.as_bytes());
        h2.update(b":2:");
        h2.update(&sig_bytes);
        let half2 = h2.finalize();
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&half1.as_bytes()[..32]);
        seed[32..].copy_from_slice(&half2.as_bytes()[..32]);
        let owner_priv_hex = hex::encode(seed);

        let plain = "Здравствуйте, это секретное письмо для владельца NFT.";

        // 1) бэкенд шифрует письмо на x_pub производный от подписи кошелька
        let enc =
            infnode::node::proton_box_body(&x_pub_hex, plain).expect("proton_box_body encrypt");
        assert_ne!(enc, plain);
        assert!(enc.contains("infmail-box-v1"));

        // 2) владелец (тот же кошелёк → та же подпись → тот же приватный x25519) расшифровывает
        let dec =
            infnode::node::proton_unbox_body(&enc, &owner_priv_hex).expect("unbox with owner priv");
        assert_eq!(dec, plain, "владелец видит своё письмо");

        // 3) ДРУГОЙ кошелёк (другая подпись → другой KEM-сид) НЕ может расшифровать
        let other_sig = "0000000000000000000000000000000000000000000000000000000000000000\
                         0000000000000000000000000000000000000000000000000000000000000001";
        let other_sig_bytes = hex::decode(other_sig).unwrap();
        let mut oh1 = Hasher::new();
        oh1.update(SIG_DERIVE_DOMAIN.as_bytes());
        oh1.update(b":1:");
        oh1.update(&other_sig_bytes);
        let ohalf1 = oh1.finalize();
        let mut oh2 = Hasher::new();
        oh2.update(SIG_DERIVE_DOMAIN.as_bytes());
        oh2.update(b":2:");
        oh2.update(&other_sig_bytes);
        let ohalf2 = oh2.finalize();
        let mut other_seed = [0u8; 64];
        other_seed[..32].copy_from_slice(&ohalf1.as_bytes()[..32]);
        other_seed[32..].copy_from_slice(&ohalf2.as_bytes()[..32]);
        let other_priv_hex = hex::encode(other_seed);
        let dec_other = infnode::node::proton_unbox_body(&enc, &other_priv_hex);
        assert!(
            dec_other.is_none() || dec_other.as_deref() != Some(plain),
            "чужой кошелёк НЕ должен читать письма (эпоха/owner_changed)"
        );
    }
}
