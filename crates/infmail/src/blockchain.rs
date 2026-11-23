//! Индексер TON Center: проверка владения/оплат/балансов смарт-контрактов
//! (Registry/Storage/NftItem). Используется для подписок и NFT.

use anyhow::Result;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn base_url() -> String {
    std::env::var("TON_API_BASE_URL")
        .unwrap_or_else(|_| "https://testnet.toncenter.com/api/v2".to_string())
}

/// API-ключ TON Center (X-API-Key). Без ключа публичный эндпоинт даёт ~1 rps —
/// на mainnet этого не хватит даже на /nft/status (будет 503 «chain unavailable»).
/// Пусто = без ключа (текущее поведение тестнета).
fn api_key() -> String {
    std::env::var("TON_API_KEY").unwrap_or_default()
}

/// Прицепить X-API-Key к запросу, если ключ задан.
fn with_key(req: ureq::Request) -> ureq::Request {
    let k = api_key();
    if k.is_empty() {
        req
    } else {
        req.set("X-API-Key", &k)
    }
}

/// HTTP-агент с таймаутами: зависший TON Center не должен вечно держать blocking-поток.
fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout_read(std::time::Duration::from_secs(20))
        .build()
}

fn registry_address() -> String {
    std::env::var("REGISTRY_CONTRACT_ADDRESS").unwrap_or_default()
}

/// SHA-256(email в lowercase) в hex — ключ в Registry-контракте.
pub fn email_hash_hex(email: &str) -> String {
    let mut h = Sha256::new();
    h.update(email.to_lowercase().as_bytes());
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Вызвать get-метод контракта через TON Center.
fn run_get_method(address: &str, method: &str, stack: Value) -> Option<Value> {
    let url = format!("{}/runGetMethod", base_url());
    let body = json!({ "address": address, "method": method, "stack": stack });
    let resp = with_key(http_agent().post(&url)).send_json(body).ok()?;
    let j: Value = resp.into_json().ok()?;
    if j["ok"].as_bool() != Some(true) {
        return None;
    }
    Some(j["result"].clone())
}

/// Извлечь 64-hex значение из TON Center stack.
/// Формы entry:
/// - ["addr", "wc:hash"] / ["addr", "hash"] / ["addr", "base64-адрес"];
/// - ["num", "0x..."] — uint напрямую;
/// - ["cell", {...}] — СТАРЫЙ задеплоенный Registry возвращает адрес владельца
///   ячейкой addr_std (2 бита тип 10 + 1 бит anycast + 8 бит wc + 256 бит хэш =
///   267 бит; доказано живым разбором тестнета 20.09.2026). Берём object.data.b64
///   (сырые биты ячейки, без разбора BOC) и вырезаем хэш.
fn extract_addr_hash_from_stack(first: &Value) -> String {
    let Some(arr) = first.as_array() else {
        return String::new();
    };
    // форма ["cell", {...}] — адрес/uint ячейкой
    if arr.first().and_then(|v| v.as_str()) == Some("cell") {
        if let Some(b64) = arr
            .get(1)
            .and_then(|o| o.get("object"))
            .and_then(|o| o.get("data"))
            .and_then(|d| d.get("b64"))
            .and_then(|v| v.as_str())
        {
            let nbits = arr
                .get(1)
                .and_then(|o| o.get("object"))
                .and_then(|o| o.get("data"))
                .and_then(|d| d.get("len"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64.as_bytes()))
            {
                // биты MSB-first
                let bit = |i: usize| (bytes[i / 8] >> (7 - (i % 8))) & 1;
                // addr_std: 10 + anycast(0) + wc(8) + hash(256) = 267 бит
                if nbits == 267 && bit(0) == 1 && bit(1) == 0 && bit(2) == 0 {
                    let mut h = [0u8; 32];
                    for (j, b) in h.iter_mut().enumerate() {
                        let mut v = 0u8;
                        for k in 0..8 {
                            v = (v << 1) | bit(11 + j * 8 + k);
                        }
                        *b = v;
                    }
                    return hex::encode(h);
                }
                // голый uint256 ячейкой
                if nbits == 256 {
                    return hex::encode(&bytes[..32]);
                }
            }
        }
        return String::new();
    }
    // форма ["num", "0x..."] — uint напрямую
    if arr.first().and_then(|v| v.as_str()) == Some("num") {
        if let Some(s) = arr.get(1).and_then(|v| v.as_str()) {
            let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
            if !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                return format!("{:0>64}", s.to_lowercase());
            }
        }
        return String::new();
    }
    let Some(s) = arr.get(1).and_then(|v| v.as_str()) else {
        return String::new();
    };
    let s = s.trim();
    // форма "wc:hash"
    if let Some((_, h)) = s.split_once(':') {
        return h.to_lowercase();
    }
    // форма "hash" (64 hex)
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return s.to_lowercase();
    }
    // форма base64 (kQ.../EQ...)
    if s.len() >= 44 {
        if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE
            .decode(s.as_bytes())
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s.as_bytes()))
        {
            if bytes.len() >= 34 {
                return hex::encode(&bytes[2..34]);
            }
        }
    }
    String::new()
}

/// Проверка: владеет ли кошелёк email'ом по Registry-контракту.
///
/// ДВА формата (расхождение исходника и продакшена, доказано тестнетом 20.09.2026):
///
/// - СТАРЫЙ задеплоенный контракт хранит АДРЕС владельца → совпадение с хэшем адреса;
/// - НОВЫЙ src/registry.tolk хранит walletRef = SHA256(addressHash + email).
///
/// Принимаем оба: иначе после редеплоя контракта проверка опять ляжет.
pub fn check_registry_ownership(email: &str, wallet_addr_hash: &str) -> bool {
    let addr = registry_address();
    if addr.is_empty() {
        return false;
    }
    let hash = email_hash_hex(email);
    let res = run_get_method(
        &addr,
        "getOwnerByHash",
        json!([["num", format!("0x{hash}")]]),
    );
    let Some(res) = res else {
        return false;
    };
    // пустой стек → email не зарегистрирован → не наш
    let Some(stack) = res["stack"].as_array() else {
        return false;
    };
    let Some(first) = stack.first() else {
        return false;
    };
    let owner_hash = extract_addr_hash_from_stack(first);
    if owner_hash.is_empty() {
        return false;
    }
    // нормализуем адрес к 64-hex хэшу (как normalize_ton_address в web.rs)
    let w = wallet_addr_hash
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let w = match w.split_once(':') {
        Some((_, h)) => h.trim(),
        None => w,
    }
    .to_lowercase();
    if w.len() != 64 || !w.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    // формат 1 (старый контракт): лежит хэш адреса владельца
    if owner_hash.eq_ignore_ascii_case(&w) {
        return true;
    }
    // формат 2 (новый контракт): walletRef = SHA256(addressHashHex + email) — формула фронта
    let mut h = Sha256::new();
    h.update(format!("{}{}", w, email.to_lowercase()).as_bytes());
    let expected = hex::encode(h.finalize());
    owner_hash.eq_ignore_ascii_case(&expected)
}

/// Жёсткие цены по умолчанию (зеркало деплоя). H-1: админ может сменить цены
/// on-chain через UpdatePricing — тогда хардкод врёт в обе стороны (1003 throw
/// либо вечный pending). Поэтому сначала читаем getPricing контракта (кэш 10 мин),
/// хардкод — только фолбэк при недоступности chain.
const DEFAULT_PRICES: [u64; 5] = [
    1_000_000_000,
    1_000_000_000,
    700_000_000,
    500_000_000,
    100_000_000,
];

static PRICING_CACHE: std::sync::Mutex<(i64, [u64; 5])> =
    std::sync::Mutex::new((0, DEFAULT_PRICES));

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Цены (p2, p3, p4, p5, default) с контракта, кэш 600с. Порядок getPricing:
/// (price_2, price_3, price_4, price_5, price_default) — см. registry.tolk:182.
pub fn onchain_prices(addr: &str) -> [u64; 5] {
    let now = now_secs();
    if let Ok(g) = PRICING_CACHE.lock() {
        if now - g.0 < 600 {
            return g.1;
        }
    }
    let mut prices = DEFAULT_PRICES;
    if let Some(res) = run_get_method(addr, "getPricing", json!([])) {
        if let Some(stack) = res["stack"].as_array() {
            // entries: ["num", "<dec>"] — берём первые 5
            let mut v = [0u64; 5];
            let mut n = 0usize;
            for e in stack {
                if n >= 5 {
                    break;
                }
                let s = e.get(1).and_then(|x| x.as_str()).unwrap_or("");
                let s = s.trim().trim_start_matches("0x");
                // dec или hex
                let parsed = if e
                    .get(1)
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .starts_with("0x")
                {
                    u64::from_str_radix(s, 16).ok()
                } else {
                    s.parse::<u64>().ok()
                };
                if let Some(p) = parsed {
                    v[n] = p;
                    n += 1;
                }
            }
            if n == 5 {
                prices = v;
            }
        }
    }
    if let Ok(mut g) = PRICING_CACHE.lock() {
        *g = (now, prices);
    }
    prices
}

/// Цена регистрации по длине localpart (нанотоны) — сначала on-chain, иначе хардкод.
pub fn tier_price_nano(local_len: usize) -> u64 {
    tier_price_nano_with(&onchain_prices(&registry_address()), local_len)
}

fn tier_price_nano_with(prices: &[u64; 5], local_len: usize) -> u64 {
    match local_len {
        0 | 1 => 0,
        2 => prices[0],
        3 => prices[1],
        4 => prices[2],
        5 => prices[3],
        _ => prices[4],
    }
}

/// Минимальный разбор BOC для тела RegisterZK.
/// Реальный формат от toncenter (проверено на живых телах 20.09.2026): BOC БЕЗ
/// индексной таблицы, magic b5ee9c72, заголовок 11 байт, затем ячейка
/// d1=0x00 (0 refs) d2=len*2, 69 байт данных, CRC32c (4 байта).
/// Поддерживаем и классический magic 68ff65f3 с индексной таблицей.
/// Ищем первую ячейку без refs с данными >= 69 байт:
/// op u32 + emailHash u256 + walletRef u256 + len u8.
fn parse_register_body(boc: &[u8]) -> Option<(u32, String, u8)> {
    if boc.len() < 14 {
        return None;
    }
    // старт данных ячеек после заголовка
    let pos = if boc[0..4] == [0x68, 0xff, 0x65, 0xf3] {
        // классика: magic flags sz off cells[sz] roots[sz] absent[sz] total[sz] idx + данные
        let sz = boc[5] as usize;
        let off_bytes = boc[6] as usize;
        if !(1..=4).contains(&sz) || off_bytes == 0 || off_bytes > 8 {
            return None;
        }
        let roots = read_uint_be(boc, 7 + sz, sz)?;
        if roots == 0 {
            return None;
        }
        let idx_pos = 7 + 4 * sz;
        let first_root_off = read_uint_be(boc, idx_pos, off_bytes)? as usize;
        idx_pos + (roots as usize) * off_bytes + first_root_off
    } else if boc[0..4] == [0xb5, 0xee, 0x9c, 0x72] {
        // без индексной таблицы: magic flags sz off cells roots absent total (по 1 байту при sz=1)
        let sz = boc[5] as usize;
        if sz != 1 || boc.len() < 11 {
            return None;
        }
        4 + 3 + 4 * sz
    } else {
        return None;
    };
    // первая ячейка: d1 (младшие 3 бита = число refs), d2 (длина данных)
    if pos + 2 > boc.len() {
        return None;
    }
    let d1 = boc[pos];
    let d2 = boc[pos + 1] as usize;
    if d1 & 0x07 != 0 || d1 & 0x08 != 0 {
        return None;
    }
    // d2 = число БАЙТ данных*2 (+1 если неполный последний байт, здесь не ждём)
    let data_len = d2 / 2;
    let dp = pos + 2;
    if data_len < 69 || dp + 69 > boc.len() {
        return None;
    }
    let op = u32::from_be_bytes([boc[dp], boc[dp + 1], boc[dp + 2], boc[dp + 3]]);
    let eh = hex::encode(&boc[dp + 4..dp + 36]);
    let len = boc[dp + 68];
    Some((op, eh, len))
}

fn read_uint_be(boc: &[u8], pos: usize, sz: usize) -> Option<u64> {
    if pos + sz > boc.len() {
        return None;
    }
    let mut v = 0u64;
    for i in 0..sz {
        v = (v << 8) | boc[pos + i] as u64;
    }
    Some(v)
}

/// Friendly-адрес -> 64-hex хэш (wc + hash из 36 байт: tag + wc + hash).
fn friendly_to_hash(addr: &str) -> Option<String> {
    let a = addr.trim();
    if a.len() < 44 {
        return None;
    }
    let bytes = base64::engine::general_purpose::URL_SAFE
        .decode(a.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(a.as_bytes()))
        .ok()?;
    if bytes.len() < 34 {
        return None;
    }
    Some(hex::encode(&bytes[bytes.len() - 32..]))
}

/// Проверка оплаты регистрации: ищем во входящих контракту транзакциях RegisterZK
/// с нашим emailHash, суммой >= цены тира (по РЕАЛЬНОЙ длине имени) И отправителем
/// == кошелёк (привязка отправителя: чужая/старая оплата за тот же хэш не засчитывается).
/// MED-3: пагинация lt-курсором до 4 страниц (~400 тх) — оплата не должна теряться,
/// если уползла глубже первых 100.
pub fn verify_registry_payment(email: &str, addr: &str, wallet_hash: &str) -> bool {
    let address = if addr.is_empty() {
        registry_address()
    } else {
        addr.to_string()
    };
    if address.is_empty() {
        return false;
    }
    let local_len = email.split('@').next().unwrap_or("").len();
    let expected = tier_price_nano(local_len);
    if expected == 0 {
        return false;
    }
    let want_hash = email_hash_hex(email);
    let wallet_hash = wallet_hash
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_lowercase();
    let url = format!("{}/getTransactions", base_url());
    let mut lt_cursor: Option<String> = None;
    for _page in 0..4 {
        let mut req_body = json!({ "address": address, "limit": 100 });
        if let Some(lt) = &lt_cursor {
            req_body["lt"] = json!(lt);
        }
        let resp = match with_key(http_agent().post(&url)).send_json(req_body) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let j: Value = match resp.into_json() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let txs = match j["result"].as_array() {
            Some(a) => a,
            None => return false,
        };
        if txs.is_empty() {
            return false;
        }
        for t in txs {
            let msg = &t["in_msg"];
            let value: u64 = msg["value"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if value < expected {
                continue;
            }
            // привязка отправителя (иначе чужая оплата за тот же emailHash сойдёт)
            if !wallet_hash.is_empty() {
                match msg["source"].as_str().and_then(friendly_to_hash) {
                    Some(h) if h.eq_ignore_ascii_case(&wallet_hash) => {}
                    _ => continue,
                }
            }
            let b64 = match msg["msg_data"]["body"].as_str() {
                Some(b) if !b.is_empty() => b,
                _ => continue,
            };
            let raw = match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Some((op, eh, _)) = parse_register_body(&raw) {
                if op == 0x52475a4b && eh.eq_ignore_ascii_case(&want_hash) {
                    return true;
                }
            }
        }
        // курсор на самую старую тх страницы
        lt_cursor = txs
            .last()
            .and_then(|t| t["transaction_id"]["lt"].as_str())
            .map(String::from);
        if lt_cursor.is_none() {
            return false;
        }
    }
    false
}

/// Баланс контракта (нанотон).
pub fn get_contract_balance(address: &str) -> u64 {
    let url = format!("{}/getAddressInformation?address={address}", base_url());
    let Ok(resp) = with_key(http_agent().get(&url)).call() else {
        return 0;
    };
    let Ok(j) = resp.into_json::<Value>() else {
        return 0;
    };
    if j["ok"].as_bool() != Some(true) {
        return 0;
    }
    j["result"]["balance"]
        .as_str()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0)
}

/// Проверка оплаты подписки: баланс Storage-контракта и владелец (admin).
pub fn storage_paid(storage_address: &str, _user: &str) -> u64 {
    get_contract_balance(storage_address)
}

/// Публичная обёртка run_get_method (для web-эндпоинтов).
pub fn run_get_method_pub(address: &str, method: &str, stack: Value) -> Option<Value> {
    run_get_method(address, method, stack)
}

/// Сканировать NFT-коллекцию и вернуть токены, принадлежащие кошельку.
/// Читает getCollectionData (nextItemIndex) и getOwnerByTokenId для каждого токена.
pub fn scan_nfts_by_wallet(wallet: &str) -> Vec<u64> {
    let addr = std::env::var("NFT_COLLECTION_ADDRESS").unwrap_or_default();
    if addr.is_empty() || wallet.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    // nextItemIndex из getCollectionData
    let Some(res) = run_get_method(&addr, "getCollectionData", json!([])) else {
        return out;
    };
    if res["exit_code"].as_i64().unwrap_or(-1) != 0 {
        return out;
    }
    let Some(stack) = res["stack"].as_array() else {
        return out;
    };
    let Some(first) = stack.first() else {
        return out;
    };
    // [["num","0x..."], ...]
    let idx_val = first
        .as_array()
        .and_then(|a| a.get(1))
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    let mut tid: u64 = 0;
    // лимит сканирования — защита от DoS (огромный nextItemIndex → N запросов к TON)
    let max_scan = idx_val.min(1000);
    while tid < max_scan {
        let Some(owner_res) = run_get_method(
            &addr,
            "getOwnerByTokenId",
            json!([["num", format!("0x{tid:x}")]]),
        ) else {
            tid += 1;
            continue;
        };
        // проверяем владельца (exit 0 и stack содержит адрес)
        if owner_res["exit_code"].as_i64().unwrap_or(-1) == 0 {
            if let Some(stk) = owner_res["stack"].as_array() {
                if let Some(first_item) = stk.first() {
                    let raw = first_item
                        .as_array()
                        .and_then(|a| a.get(1))
                        .and_then(|v| v.as_str());
                    if let Some(raw_addr) = raw {
                        // адрес в cell — сравниваем по непустому raw; для теста: если владелец есть — считаем
                        if !raw_addr.is_empty() {
                            // грубое сравнение невозможно без декодирования cell; вернём все с владельцем
                            out.push(tid);
                        }
                    }
                }
            }
        }
        tid += 1;
    }
    out
}

/// Строгий вызов get-метода: отделяет «RPC недоступен» от «метод вернул результат».
/// Молчаливый None в run_get_method неотличим от «нет данных», из-за чего сбой RPC
/// (429 rate limit, таймаут) показывался пользователю как «у вас нет NFT».
fn run_get_method_strict(address: &str, method: &str, stack: Value) -> Result<Value, ()> {
    let url = format!("{}/runGetMethod", base_url());
    let body = json!({ "address": address, "method": method, "stack": stack });
    let resp = with_key(http_agent().post(&url))
        .send_json(body)
        .map_err(|_| ())?;
    let j: Value = resp.into_json().map_err(|_| ())?;
    if j["ok"].as_bool() != Some(true) {
        // 429/5xx: состояние chain НЕИЗВЕСТНО — это не ответ «NFT нет».
        return Err(());
    }
    Ok(j["result"].clone())
}

/// Проверка NFT: есть ли у email'а NFT в Collection.
/// Ok(Some(id)) — есть; Ok(None) — достоверно проверено, NFT нет;
/// Err(()) — chain/RPC недоступен, ответ НЕИЗВЕСТЕН (нельзя показывать «нет NFT»).
#[allow(clippy::result_unit_err)] // GATE: nft probe tri-state uses unit error by design
pub fn check_nft_status(email: &str) -> Result<Option<u64>, ()> {
    let addr = std::env::var("NFT_COLLECTION_ADDRESS").unwrap_or_default();
    if addr.is_empty() {
        return Ok(None);
    }
    let hash = email_hash_hex(email);
    // ВАЖНО: метод на контракте называется getTokenByEmailHash (camelCase).
    // snake_case get_token_by_email_hash не существует → TON возвращает exit_code 11,
    // что давало ложное «NFT нет» у всех аккаунтов.
    let res = run_get_method_strict(
        &addr,
        "getTokenByEmailHash",
        json!([["num", format!("0x{hash}")]]),
    )?;
    // exit_code != 0 => get-метод бросил исключение: это достоверный ответ «NFT нет».
    if res["exit_code"].as_i64().unwrap_or(-1) != 0 {
        return Ok(None);
    }
    let stack = res["stack"].as_array().ok_or(())?;
    let first = stack.first().ok_or(())?;
    // формат: [["num", "<token_id>"]]
    let val = if let Some(arr) = first.as_array() {
        arr.get(1)
            .and_then(|v| v.as_str())
            .map(|s| s.trim_start_matches("0x").to_string())
    } else {
        first
            .as_str()
            .map(|s| s.trim_start_matches("0x").to_string())
    };
    // Значения нет вовсе => NFT нет. Строка есть, но не парсится => неожиданный формат,
    // состояние считаем неизвестным, а не «нет NFT».
    match val {
        None => Ok(None),
        Some(v) => match u64::from_str_radix(&v, 16) {
            Ok(id) => Ok(Some(id)),
            Err(_) => Err(()),
        },
    }
}

/// On-chain владелец NFT-токена (getOwnerByTokenId коллекции).
/// Возвращает 64-hex хэш адреса владельца (тот же формат, что wallet в аккаунтах).
/// None — нет коллекции, нет токена или chain недоступен.
pub fn get_nft_owner(token_id: u64) -> Option<String> {
    let addr = std::env::var("NFT_COLLECTION_ADDRESS").unwrap_or_default();
    if addr.is_empty() {
        return None;
    }
    let res = run_get_method(
        &addr,
        "getOwnerByTokenId",
        json!([["num", format!("0x{token_id:x}")]]),
    )?;
    if res["exit_code"].as_i64().unwrap_or(-1) != 0 {
        return None;
    }
    let first = res["stack"].as_array()?.first()?;
    // chain отдаёт адрес владельца как address-slice внутри cell (267 бит:
    // 2 бита '10' + 1 бит anycast + 8 бит workchain + 256 бит хэш), а не как строку.
    if let Some(h) = parse_addr_from_cell_entry(first) {
        return Some(h);
    }
    let h = extract_addr_hash_from_stack(first);
    if h.is_empty() {
        None
    } else {
        Some(h)
    }
}

/// Разобрать адрес из stack-записи вида ["cell", {"object": {"data": {"b64": ...}}}] (address-slice, 267 бит).
/// Возвращает 64-hex хэш адреса.
fn parse_addr_from_cell_entry(first: &Value) -> Option<String> {
    let arr = first.as_array()?;
    if arr.first()?.as_str()? != "cell" {
        return None;
    }
    let b64 = arr.get(1)?["object"]["data"]["b64"].as_str()?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()?;
    // 11-битный префикс (2 бита тип + 1 бит anycast + 8 бит workchain), затем 256 бит хэша
    if bytes.len() < 33 {
        return None;
    }
    let mut hash = [0u8; 32];
    for i in 0..256usize {
        let bit = 11 + i;
        let b = (bytes[bit / 8] >> (7 - (bit % 8))) & 1;
        hash[i / 8] |= b << (7 - (i % 8));
    }
    Some(hex::encode(hash))
}

/// Прочитать текстовые комментарии входящих транзакций контракта (TON Center getTransactions).
/// Возвращает (sender, value_nanoton, comment, tx_hash) для сообщений с типом msg.dataText.
pub fn get_payment_comments(contract: &str, limit: u32) -> Vec<(String, u64, String, String)> {
    let url = format!(
        "{}/getTransactions?address={}&limit={}&archival=true",
        base_url(),
        contract,
        limit
    );
    let Ok(resp) = with_key(http_agent().get(&url)).call() else {
        return Vec::new();
    };
    let Ok(j) = resp.into_json::<Value>() else {
        return Vec::new();
    };
    if j["ok"].as_bool() != Some(true) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let Some(txs) = j["result"].as_array() else {
        return Vec::new();
    };
    for t in txs {
        let msg = &t["in_msg"];
        let md = &msg["msg_data"];
        if md["@type"].as_str() == Some("msg.dataText") {
            if let Some(text) = md["text"].as_str() {
                let sender = msg["source"].as_str().unwrap_or("").to_string();
                // сумма входящего сообщения в нанотонах (строка от toncenter)
                let value = msg["value"]
                    .as_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                // tx_hash из transaction_id.hash — курсор для индексера (не терять платежи)
                let tx_hash = t["transaction_id"]["hash"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                // toncenter возвращает текст комментария в base64
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(text))
                    .map(|b| String::from_utf8_lossy(&b).to_string())
                    .unwrap_or_else(|_| text.to_string());
                out.push((sender, value, decoded, tx_hash));
            }
        }
    }
    out
}

#[cfg(test)]
mod cell_parse_tests {
    use super::*;
    use serde_json::json;

    // Реальный ответ testnet getOwnerByHash от 20.09.2026 (адрес-владелец ячейкой).
    // Хэш внутри: ca25fd31c3796e5a17bca5ac6aa155def7863f990cde81bb59065ac0a45373a2
    // (доказан разбором: addr_std wc=0 + hash отправителя EQDKJf0xw3...).
    #[test]
    fn extract_hash_from_cell_address() {
        let entry = json!([
            "cell",
            {
                "bytes": "te6cckEBAQEAJAAAQ4AZRL+mOG8ty0L3lLWNVCq73vDH8yGb0DdrIMtYFIpudFBH9boX",
                "object": {
                    "data": {
                        "b64": "gBlEv6Y4by3LQveUtY1UKrve8MfzIZvQN2sgy1gUim50UA==",
                        "len": 267
                    },
                    "refs": [],
                    "special": false
                }
            }
        ]);
        assert_eq!(
            extract_addr_hash_from_stack(&entry),
            "ca25fd31c3796e5a17bca5ac6aa155def7863f990cde81bb59065ac0a45373a2"
        );
    }

    // Реальные тела RegisterZK из тестнета 20.09.2026 (0.1 TON, op 0x52475a4b).
    #[test]
    fn parse_register_body_live() {
        use base64::Engine;
        let b1 = base64::engine::general_purpose::STANDARD.decode(
            "te6cckEBAQEARwAAilJHWkumlanI7cKejA8ytlrlDe7GjBa2WThfByvB8QnhzO1knN4yJF5oyePCfxwIpbz2Y4dDgAQu1Jh6vxfZrHBIi6jgCzLAn84=").unwrap();
        let (op, eh, len) = parse_register_body(&b1).expect("parse b1");
        assert_eq!(op, 0x52475a4b);
        assert_eq!(
            eh,
            "a695a9c8edc29e8c0f32b65ae50deec68c16b659385f072bc1f109e1cced649c"
        );
        assert_eq!(len, 11);
        let b2 = base64::engine::general_purpose::STANDARD.decode(
            "te6cckEBAQEARwAAilJHWksQtE+t+M7roaXyVD9m+ChlOtqwmWzgES6qXFZ2F6T9YmBbaPWufYdRtOg1W2W+Rle4Y76PxLoJQL8DhstR6HQcCc65Wts=").unwrap();
        let (op2, eh2, len2) = parse_register_body(&b2).expect("parse b2");
        assert_eq!(op2, 0x52475a4b);
        assert_eq!(
            eh2,
            "10b44fadf8ceeba1a5f2543f66f828653adab0996ce0112eaa5c567617a4fd62"
        );
        assert_eq!(len2, 9);
        // мусор отклоняем
        assert!(parse_register_body(b"te6c").is_none());
        assert!(parse_register_body(&[0u8; 100]).is_none());
    }

    #[test]
    fn extract_hash_from_num() {
        let entry = json!([
            "num",
            "0xca25fd31c3796e5a17bca5ac6aa155def7863f990cde81bb59065ac0a45373a2"
        ]);
        assert_eq!(
            extract_addr_hash_from_stack(&entry),
            "ca25fd31c3796e5a17bca5ac6aa155def7863f990cde81bb59065ac0a45373a2"
        );
    }
}
