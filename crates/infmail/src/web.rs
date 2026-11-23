//! Валидатор InfMail: HTTP API webmail на infnode.
//!
//! Авторизация — JWT (HS256, ключ от identity ноды). Аккаунты — accounts.json.
//! Письма — E2E от браузера: сервер хранит только шифротекст в storage.*
//! (репликация по сети), индекс ящика и реестр ключей — в DHT-KV.

use anyhow::{anyhow, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::Path;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

use infnode::node::Node;
use infnode::proto;

type HmacSha256 = Hmac<Sha256>;

pub const MAIL_DOMAIN: &str = "infmail.org";
const DEFAULT_QUOTA: u64 = 1073741824; // 1 ГБ free

#[derive(Clone)]
pub struct WebState {
    pub node: Arc<Node>,
    pub db: Arc<Mutex<AccountsDb>>,
    pub db_path: PathBuf,
    pub jwt_secret: [u8; 32],
    /// rate-limit: key -> (кол-во, начало окна мс)
    pub login_guard: Arc<Mutex<HashMap<String, (u32, i64)>>>,
    pub reg_guard: Arc<Mutex<HashMap<String, (u32, i64)>>>,
    pub relay_guard: Arc<Mutex<HashMap<String, (u32, i64)>>>,
    pub recovery_guard: Arc<Mutex<HashMap<String, (u32, i64)>>>,
    pub nft_guard: Arc<Mutex<HashMap<String, (u32, i64)>>>,
    /// сериализация чтения-записи индексов ящика (против гонки параллельных отправок)
    pub index_lock: Arc<Mutex<()>>,
    /// ин-флайт IMAP-синк по аккаунтам (защита от двойного инжекта UNSEEN и двойного учёта квоты)
    pub sync_inflight: Arc<Mutex<HashSet<String>>>,
    /// время последнего успешного IMAP-синка аккаунта (ms) — для on-demand «а если свежий — не ждём»
    pub sync_last: Arc<Mutex<HashMap<String, i64>>>,
    /// Кэш статуса NFT: email -> (время записи в ms, ответ).
    /// Публичный TON RPC жёстко лимитирует (429), а /nft/status дёргается на каждом
    /// открытии дашборда. Кэш экономит квоту и позволяет отдать последний известный
    /// ответ вместо 503, когда chain недоступен.
    pub nft_status_cache: Arc<Mutex<HashMap<String, (i64, Value)>>>,
}

/// Текущее время в мс (для кэша статуса NFT).
fn nft_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Сколько мс считать кэш статуса NFT свежим (в chain не ходим).
const NFT_STATUS_TTL_MS: i64 = 90_000;

/// Проверить/инкремент rate-limit. Возвращает true, если лимит превышен (429).
async fn rate_limit(
    guard: &Arc<Mutex<HashMap<String, (u32, i64)>>>,
    key: &str,
    max: u32,
    window_ms: i64,
) -> bool {
    let mut g = guard.lock().await;
    let now = proto::now_ms();
    // prune: если карта разрослась, чистим истёкшие окна (защита от роста памяти при
    // большом числе уникальных IP / подделанных X-Real-IP на прямом доступе)
    if g.len() > 10_000 {
        g.retain(|_, (_, start)| now - *start <= window_ms);
    }
    let (count, start) = g.get(key).cloned().unwrap_or((0, now));
    if now - start > window_ms {
        g.insert(key.to_string(), (1, now));
        return false;
    }
    let c = count + 1;
    g.insert(key.to_string(), (c, start));
    c > max
}

/// IP клиента (x-forwarded-for от nginx/Next, иначе 0.0.0.0).
fn client_ip(headers: &HeaderMap) -> String {
    // Приоритет X-Real-IP (ставит наш nginx/Next-прокси, надёжный). XFF используем только
    // если X-Real-IP нет (например прямой доступ к loopback-бэкенду). Это не даёт клиенту
    // подделывать IP в обход rate-limit: через прокси XFF перезаписывается реальным IP.
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty() && s != "unknown")
                .unwrap_or_else(|| "0.0.0.0".into())
        })
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct AccountsDb {
    pub accounts: HashMap<String, Account>,
    /// обработанные платёжные комментарии (INFMAIL_SUB:<email>:<nonce>) — анти-дубль
    #[serde(default)]
    pub processed_payments: Vec<String>,
    /// курсор индексера: последний обработанный tx_hash (TON Center) — чтобы не терять
    /// платежи, когда между раундами приходит >100 транзакций
    #[serde(default)]
    pub last_payment_tx: Option<String>,
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct Account {
    pub pw_hash: String,
    pub created_ms: i64,
    pub quota_limit: u64,
    #[serde(default)]
    pub bytes_used: u64,
    /// X25519 публичный (hex), от браузера
    #[serde(default)]
    pub x_pub: Option<String>,
    /// Ed25519 публичный (hex), от браузера (подпись отправителя)
    #[serde(default)]
    pub ed_pub: Option<String>,
    /// зашифрованный приватный ключ браузера (JSON, для кросс-девайс)
    #[serde(default)]
    pub enc_priv: Option<String>,
    /// алиасы (локальные части @infmail.org), доставляются в этот ящик
    #[serde(default)]
    pub aliases: Vec<String>,
    /// квота файлового хранилища (0 = файлы недоступны до платного тарифа)
    #[serde(default)]
    pub file_quota_limit: u64,
    /// занято в файловом хранилище (байт)
    #[serde(default)]
    pub files_used: u64,
    /// пароль SMTP-ящика (для relay во внешнюю почту), генерится при регистрации
    #[serde(default)]
    pub smtp_pass: Option<String>,
    /// TON-кошелёк (для web3-аккаунтов), канонический raw-хэш
    #[serde(default)]
    pub wallet: Option<String>,
    /// публичный ключ кошелька (Ed25519 hex), подтверждённый при регистрации web3.
    /// Используется для проверки владения: при логине proof должен быть подписан этим ключом.
    #[serde(default)]
    pub wallet_pub: Option<String>,
    /// секрет для web3-ключей браузера (per-account)
    #[serde(default)]
    pub e2e_secret: Option<String>,
    /// Per-account Files key seed (32 bytes hex), generated on first use.
    ///
    /// Files blobs are sealed to a KEM key derived from THIS account-scoped
    /// secret, never from the node's KEM seed: a node re-key / restore no
    /// longer changes every account's Files key, and two accounts on one node
    /// do not share a key family. The value is server-side (like `pw_hash`):
    /// the web tier can open Files (server-side at-rest sealing, NOT E2E) and
    /// this field is deliberately NOT replicated in `account_public_profile`.
    #[serde(default)]
    pub files_key_secret: Option<String>,
    /// план: "free" | "paid" (подписка через Storage-контракт)
    #[serde(default)]
    pub plan: String,
    /// до когда оплачена подписка (мс)
    #[serde(default)]
    pub paid_until_ms: i64,
    // ── 2FA (TOTP) ──
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub totp_enabled: bool,
    /// SHA256-хеши бэкап-кодов (для входа)
    #[serde(default)]
    pub backup_codes: Vec<String>,
    /// бэкап-коды XOR с blake3(password) — для показа при Reveal
    #[serde(default)]
    pub backup_codes_enc: Vec<String>,
    #[serde(default)]
    pub trusted_email: Option<String>,
    #[serde(default)]
    pub pending_email: Option<String>,
    /// активные сессии (id, устройство, ip, создана/последний вход)
    #[serde(default)]
    pub sessions: Vec<SessionInfo>,
    /// эпоха сессий: revoke-all инкрементит → старые JWT невалидны
    #[serde(default)]
    pub session_epoch: u32,
    /// подпись письма (append к телу при compose)
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct SessionInfo {
    pub id: String,
    pub device: String,
    pub ip: String,
    pub created_ms: i64,
    pub last_seen_ms: i64,
    pub is_current: bool,
}

/// Лимиты по плану.
fn plan_limits(plan: &str) -> (u64, u64, usize) {
    match plan {
        "paid" => (3 * 1024 * 1024 * 1024, 6 * 1024 * 1024 * 1024, 15),
        _ => (DEFAULT_QUOTA, 0, FREE_ALIAS_LIMIT),
    }
}

fn effective_mail_quota(a: &Account) -> u64 {
    if a.paid_until_ms > proto::now_ms() {
        plan_limits("paid").0
    } else {
        // free: не наследуем лимит от истёкшей подписки (subscribe мог поднять quota_limit до 3ГБ)
        a.quota_limit.min(DEFAULT_QUOTA)
    }
}

fn effective_file_quota(a: &Account) -> u64 {
    if a.paid_until_ms > proto::now_ms() {
        plan_limits("paid").1
    } else {
        // free: файловое хранилище недоступно даже если прошлая подписка подняла file_quota_limit
        a.file_quota_limit.min(default_file_quota())
    }
}

fn default_file_quota() -> u64 {
    std::env::var("INFNODE_WEB_FILE_QUOTA")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Лимит алиасов: free = 5, paid = 15 (тарифы пока не введены — все free).
pub const FREE_ALIAS_LIMIT: usize = 5;

/// Вернуть владельца адреса: сам адрес (если это аккаунт) или main-аккаунт алиаса.
fn resolve_db_email(db: &AccountsDb, email: &str) -> Option<String> {
    if db.accounts.contains_key(email) {
        return Some(email.to_string());
    }
    for (owner, acc) in &db.accounts {
        if acc
            .aliases
            .iter()
            .any(|a| format!("{a}@{MAIL_DOMAIN}") == email)
        {
            return Some(owner.clone());
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────
// Запуск
// ─────────────────────────────────────────────────────────────

pub async fn run(node: Arc<Node>, listen: &str, _static_dir: Option<PathBuf>) -> Result<()> {
    let jwt_secret = derive_jwt_secret(&node);
    let db_path = node.data_dir.join("web").join("accounts.json");
    let db = Arc::new(Mutex::new(load_db(&db_path).await));
    // ин-флайт IMAP-синк по аккаунтам + время последнего успешного синка (для on-demand)
    let sync_inflight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let sync_last: Arc<Mutex<HashMap<String, i64>>> = Arc::new(Mutex::new(HashMap::new()));
    // входящий SMTP-мост: периодически тянем новые письма из MTA (IMAP) в webmail
    if std::env::var("INFNODE_IMAP_HOST").is_ok() {
        let node_cu = node.clone();
        let db_cu = db.clone();
        let db_cu_path = db_path.clone();
        let sync_inflight_cu = sync_inflight.clone();
        let sync_last_cu = sync_last.clone();
        // backoff для аккаунтов со стабильными ошибками IMAP-логина (stale-ящики)
        let sync_failures: Arc<Mutex<HashMap<String, (usize, i64)>>> =
            Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(async move {
            loop {
                let now0 = proto::now_ms();
                let mut snapshot = db_cu.lock().await.clone();
                // не трогаем аккаунты, которые прямо сейчас синкаются on-demand
                // (иначе двойной инжект UNSEEN и двойной учёт квоты)
                let inflight_now: HashSet<String> = sync_inflight_cu.lock().await.clone();
                if !inflight_now.is_empty() {
                    snapshot
                        .accounts
                        .retain(|email, _| !inflight_now.contains(email));
                }
                // пропускаем аккаунты в backoff (3+ неудачи, таймаут 10 мин)
                let fm = sync_failures.lock().await;
                if !fm.is_empty() {
                    snapshot.accounts.retain(|email, _| {
                        fm.get(email).map(|(_, next)| *next <= now0).unwrap_or(true)
                    });
                }
                drop(fm);
                // не тянем почту от ВСЕХ ящиков сразу — лимит 50 за цикл (ротация),
                // иначе 1000+ аккаунтов каждые 60с грузят SMTP-мост и тормозят всё.
                {
                    let keys: Vec<String> = snapshot.accounts.keys().cloned().collect();
                    let take = keys.len().min(50);
                    let slice: Vec<String> = keys.into_iter().take(take).collect();
                    snapshot.accounts.retain(|email, _| slice.contains(email));
                }
                if let Ok((results, failed)) =
                    crate::inbound::inbound_sync_all(&node_cu, &snapshot).await
                {
                    let now = proto::now_ms();
                    {
                        let mut last_map = sync_last_cu.lock().await;
                        for (email, _) in results.iter() {
                            last_map.insert(email.clone(), now);
                        }
                        if last_map.len() > 5000 {
                            last_map.retain(|_, ts| *ts > now - 24 * 3600 * 1000);
                        }
                    }
                    {
                        let mut fail_map = sync_failures.lock().await;
                        for email in &failed {
                            let (count, _) = fail_map.get(email).copied().unwrap_or((0, 0));
                            if count + 1 >= 3 {
                                // 3 неудачи подряд — backoff 10 минут (игнорируем stale-аккаунты)
                                fail_map.insert(email.clone(), (count + 1, now + 10 * 60 * 1000));
                            } else {
                                fail_map.insert(email.clone(), (count + 1, 0));
                            }
                        }
                    }
                    // Parity-защита от админа stalwart: если IMAP-логин фейлится 3+ раз подряд —
                    // возвращаем пароль ящика на smtp_pass из accounts.json (админ не мог его
                    // сменить и «украсть» ящик; юзеру не мешает — recovery меняет pw_hash, не smtp_pass).
                    for email in &failed {
                        let need_restore = {
                            let fm = sync_failures.lock().await;
                            fm.get(email).map(|(c, _)| *c >= 3).unwrap_or(false)
                        };
                        if need_restore {
                            let sp = {
                                let db = db_cu.lock().await;
                                db.accounts.get(email).and_then(|a| a.smtp_pass.clone())
                            };
                            if let Some(sp) = sp {
                                if restore_stalwart_password(email, &sp).await {
                                    // сбрасываем счётчик — следующий синк попробует снова
                                    sync_failures.lock().await.remove(email);
                                }
                            }
                        }
                    }
                    if !results.is_empty() {
                        let mut db = db_cu.lock().await;
                        for (email, bytes) in results {
                            if let Some(a) = db.accounts.get_mut(&email) {
                                a.bytes_used = a.bytes_used.saturating_add(bytes);
                            }
                        }
                        let path = db_cu_path.clone();
                        save_db(&path, &db).await;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
        println!("inbound SMTP bridge enabled (IMAP, 60s)");
    }
    // индексер платежей: проверяем Storage-контракт на оплаты подписок
    if std::env::var("STORAGE_CONTRACT_ADDRESS").is_ok() {
        let node_p = node.clone();
        let db_p = db.clone();
        let path_p = db_path.clone();
        tokio::spawn(async move {
            loop {
                let _ = check_subscription_payments(&node_p, &db_p, &path_p).await;
                tokio::time::sleep(std::time::Duration::from_secs(45)).await;
            }
        });
        println!("subscription payment indexer enabled (Storage contract)");
    }
    // Разовая нейтрализация старых ключей acct:{email} (профиль лежал под именем
    // самого адреса): перезаписываем пустым значением в DHT (реплика), затем
    // убираем локально. Реплицируемого удаления в DHT нет, поэтому tombstone.
    {
        let node_r = node.clone();
        let _db_r = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(25)).await;
            // берём ВСЕ локальные acct:*-ключи (в т.ч. удалённых аккаунтов),
            // а не только записи текущей базы
            let keys = node_r.kv_manifest_keys("acct:").await;
            let mut n = 0usize;
            for k in keys {
                if k.contains('@') {
                    let _ = kv_set(&node_r, &k, "").await;
                    node_r.kv_remove_local(&k).await;
                    n += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
            if n > 0 {
                eprintln!("[web] neutralized {n} legacy acct:{{email}} keys");
            }
        });
    }
    // Разовая затирка ранее выложенного открытого списка адресов (acct-index):
    // реплика могла остаться на других нодах — перезаписываем пустым списком,
    // чтобы абонентская база не лежала в сети открытым текстом.
    {
        let node_r = node.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            let n = kv_set(&node_r, "acct-index", "[]").await;
            eprintln!("[web] acct-index scrubbed (replicas: {n})");
        });
    }
    // fail-open по ролям хранения: пустой storage_roles = нода хранит ВСЕ бакеты.
    // Не меняем семантику (на этом стоит прод), но громко предупреждаем в лог.
    if node.cfg.storage_roles.is_empty() {
        eprintln!("[web] WARN: storage_roles not set -> node stores ALL buckets (mail+files). Set INFNODE_STORAGE_ROLES to restrict.");
    }
    // репликация профилей аккаунтов в DHT (отказоустойчивость: восстановление при потере валидатора)
    {
        let node_r = node.clone();
        let db_r = db.clone();
        tokio::spawn(async move {
            replicate_accounts_loop(&node_r, &db_r).await;
        });
        println!("account replication to DHT enabled (5m)");
    }
    let state = WebState {
        node: node.clone(),
        db: db.clone(),
        db_path,
        jwt_secret,
        login_guard: Arc::new(Mutex::new(HashMap::new())),
        reg_guard: Arc::new(Mutex::new(HashMap::new())),
        relay_guard: Arc::new(Mutex::new(HashMap::new())),
        recovery_guard: Arc::new(Mutex::new(HashMap::new())),
        nft_guard: Arc::new(Mutex::new(HashMap::new())),
        index_lock: Arc::new(Mutex::new(())),
        sync_inflight: Arc::new(Mutex::new(HashSet::new())),
        sync_last: Arc::new(Mutex::new(HashMap::new())),
        nft_status_cache: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| anyhow!("web listen {listen}: {e}"))?;
    println!("web API listening on {listen}");
    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow!("axum: {e}"))
}

fn router(state: WebState) -> Router {
    use tower_http::cors::{AllowOrigin, CorsLayer};
    // Фронт ходит на /api/v1 relative через Next.js proxy (same-origin) — CORS нужен
    // только для прямых обращений. Разрешаем явный allowlist из env (прод) + dev-localhost.
    let mut allowed: Vec<String> = std::env::var("INFNODE_WEB_CORS_ORIGINS")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_else(|_| {
            vec![
                "http://localhost:3000".into(),
                "http://127.0.0.1:3000".into(),
                "http://localhost:3001".into(),
            ]
        });
    // Пустой allowlist НЕ делает CORS открытым: откатываемся на локальный дефолт
    // (никогда не CorsLayer::permissive без явного env INFNODE_WEB_CORS_PERMISSIVE=1).
    if allowed.is_empty() {
        allowed = vec![
            "http://localhost:3000".into(),
            "http://127.0.0.1:3000".into(),
            "http://localhost:3001".into(),
        ];
    }
    let cors = if std::env::var("INFNODE_WEB_CORS_PERMISSIVE").as_deref() == Ok("1") {
        CorsLayer::permissive()
    } else {
        let list: Vec<axum::http::HeaderValue> = allowed
            .iter()
            .filter_map(|o| axum::http::HeaderValue::from_str(o).ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(list))
            .allow_credentials(true)
    };
    Router::new()
        .route("/api/v1/auth/pow-challenge", get(pow_challenge))
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/auth/renew-cookie", post(renew_cookie))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/verify-2fa", post(verify_2fa))
        .route("/api/v1/auth/register-web3", post(register_web3))
        .route(
            "/api/v1/web3/generate-payload",
            get(web3_generate_payload).post(web3_generate_payload),
        )
        .route("/api/v1/web3/login", post(web3_login))
        .route("/api/v1/web3/select-account", post(web3_select_account))
        .route("/api/v1/web3/save-intent", post(web3_save_intent))
        .route("/api/v1/web3/poll-activation", get(web3_poll_activation))
        .route("/api/v1/web3/recover-email", post(web3_recover_email))
        .route("/api/v1/web3/wallet-nfts", get(web3_wallet_nfts))
        .route("/api/v1/web3/derive-keys", post(web3_derive_keys))
        .route("/api/v1/web3/save-keys", post(web3_save_keys))
        .route("/api/v1/auth/recovery/request", post(recovery_request))
        .route("/api/v1/auth/recovery/reset-password", post(recovery_reset))
        .route("/api/v1/auth/recovery/methods", post(recovery_2fa_hint))
        .route("/api/v1/pricing", get(pricing))
        .route("/api/v1/admin/username/{user}/check", get(username_check))
        .route("/api/v1/keys/save", post(keys_save))
        .route("/api/v1/keys/me", get(keys_me))
        .route("/api/v1/keys/e2e-secret", get(keys_e2e_secret))
        .route("/api/v1/keys/e2e-secret/purge", post(keys_e2e_secret_purge))
        .route("/api/v1/keys/{email}", get(keys_get))
        .route("/api/v1/mail/inbox", get(mail_inbox))
        .route("/api/v1/mail/counts", get(mail_counts))
        .route("/api/v1/mail/{id}/attachment/{idx}", get(mail_attachment))
        .route(
            "/api/v1/mail/{id}/attachment/{idx}/save-to-files",
            post(mail_attachment_save),
        )
        // Лимит тела 40 МБ: вложения разрешены до 25 МБ, base64 даёт +33% плюс
        // JSON-конверт. Без явного лимита действует дефолт axum 2 МБ — письма
        // с файлами от ~1.5 МБ падали с 413 и невнятной ошибкой на фронте
        // (жалоба: файл 949 КБ не отправился).
        .route(
            "/api/v1/mail/send",
            post(mail_send).layer(axum::extract::DefaultBodyLimit::max(40 * 1024 * 1024)),
        )
        .route(
            "/api/v1/mail/draft",
            post(mail_draft).layer(axum::extract::DefaultBodyLimit::max(40 * 1024 * 1024)),
        )
        .route("/api/v1/mail/action", post(mail_action))
        .route("/api/v1/mail/blacklist", post(mail_blacklist))
        .route("/api/v1/mail/blacklist", get(mail_blacklist_list))
        .route("/api/v1/mail/unblock-sender", post(mail_unblock))
        .route("/api/v1/settings/quota", get(settings_quota))
        .route("/api/v1/settings/plan", get(settings_plan))
        .route("/api/v1/settings/subscribe", post(settings_subscribe))
        .route(
            "/api/v1/settings/subscribe-nonce",
            get(settings_subscribe_nonce),
        )
        .route(
            "/api/v1/settings/change-password",
            post(settings_change_password),
        )
        .route(
            "/api/v1/settings/account/delete",
            post(settings_account_delete),
        )
        .route("/api/v1/settings/2fa/status", get(settings_2fa_status))
        .route("/api/v1/settings/2fa/setup", get(settings_2fa_setup))
        .route("/api/v1/settings/2fa/enable", post(settings_2fa_enable))
        .route("/api/v1/settings/2fa/disable", post(settings_2fa_disable))
        .route(
            "/api/v1/settings/2fa/backup-codes",
            post(settings_2fa_backup_codes),
        )
        .route(
            "/api/v1/settings/2fa/regenerate-codes",
            post(settings_2fa_backup_codes),
        )
        .route(
            "/api/v1/settings/trusted-email",
            post(settings_trusted_email),
        )
        .route("/api/v1/settings/signature", get(settings_signature_get))
        .route("/api/v1/settings/signature", post(settings_signature_set))
        .route("/api/v1/settings/sessions", get(settings_sessions))
        .route(
            "/api/v1/settings/sessions/revoke",
            post(settings_sessions_revoke),
        )
        .route(
            "/api/v1/settings/sessions/set-primary",
            post(settings_sessions_set_primary),
        )
        .route(
            "/api/v1/settings/sessions/revoke-all",
            post(settings_sessions_revoke_all),
        )
        .route(
            "/api/v1/settings/contract-balance",
            get(settings_contract_balance),
        )
        .route("/api/v1/settings/aliases", get(settings_aliases_list))
        .route("/api/v1/settings/aliases", post(settings_aliases_add))
        .route(
            "/api/v1/settings/aliases/delete",
            post(settings_aliases_delete),
        )
        .route("/api/v1/files", get(files_list))
        .route(
            "/api/v1/files",
            post(files_upload).layer(axum::extract::DefaultBodyLimit::max(90 * 1024 * 1024)),
        )
        .route("/api/v1/files/review", get(files_review))
        .route("/api/v1/files/{name}", get(files_download))
        .route("/api/v1/files/{name}", delete(files_delete))
        .route("/api/v1/files/{name}/share", post(files_share_create))
        .route("/api/v1/files/share/{token}", get(files_share_download))
        .route(
            "/api/v1/files/share/{token}/revoke",
            post(files_share_revoke),
        )
        .route("/api/v1/files/shares", get(files_shares_list))
        .route("/api/v1/nft/status/{email}", get(nft_status))
        .route("/api/v1/nft/{token_id}/verify", get(nft_verify))
        .route("/api/v1/nft/{token_id}/card", get(nft_card))
        .route("/api/v1/nft/{token_id}/meta", get(nft_meta))
        // АЛИАС: контракт коллекции хранит content-path "https://infmail.org/api/v1/nft/meta/"
        // и TEP-64 дописывает index -> .../nft/meta/<index>. Без этого роута любой
        // индексер (GetGems) получал 404, т.е. NFT не отображался.
        .route("/api/v1/nft/meta/{token_id}", get(nft_meta))
        .route("/api/v1/nft/upgrade", post(nft_upgrade))
        .layer(cors)
        .with_state(state)
}

// ─────────────────────────────────────────────────────────────
// JWT / учётка
// ─────────────────────────────────────────────────────────────

fn derive_jwt_secret(node: &Node) -> [u8; 32] {
    // FULL-PQ: the node has no Ed25519 secret any more; derive the web
    // session secret from the long-term KEM seed (persisted, node-unique).
    let mut h = blake3::Hasher::new();
    h.update(b"infnode-web-jwt-v1");
    h.update(&node.keys.kem_seed);
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.finalize().as_bytes()[..32]);
    k
}

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[allow(dead_code)] // GATE: HS256 helpers retained for operator tooling
fn jwt_sign(secret: &[u8; 32], sub: &str, ttl_secs: i64) -> String {
    jwt_sign_full(secret, sub, ttl_secs, None, None)
}

fn jwt_sign_full(
    secret: &[u8; 32],
    sub: &str,
    ttl_secs: i64,
    sid: Option<&str>,
    epoch: Option<u32>,
) -> String {
    let iat = proto::now_ms() / 1000;
    let exp = iat + ttl_secs;
    let header = b64url(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    let mut claims = json!({"sub": sub, "iat": iat, "exp": exp, "typ": "session"});
    if let Some(s) = sid {
        claims["sid"] = json!(s);
    }
    if let Some(v) = epoch {
        claims["v"] = json!(v);
    }
    let claims = b64url(claims.to_string().as_bytes());
    let data = format!("{header}.{claims}");
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac");
    mac.update(data.as_bytes());
    let sig = b64url(&mac.finalize().into_bytes());
    format!("{data}.{sig}")
}

/// Временный токен ВТОРОГО ШАГА 2FA (выдаётся логином до ввода кода).
/// Это НЕ сессия: `typ`="2fa" и нет `sid`, поэтому auth_email_sid его отвергает.
/// Годится исключительно для /auth/verify-2fa — иначе знание одного пароля
/// давало бы полный доступ в обход второго фактора.
fn jwt_sign_2fa(secret: &[u8; 32], sub: &str) -> String {
    let iat = proto::now_ms() / 1000;
    let exp = iat + 300;
    let header = b64url(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    let claims = b64url(
        json!({"sub": sub, "iat": iat, "exp": exp, "typ": "2fa"})
            .to_string()
            .as_bytes(),
    );
    let data = format!("{header}.{claims}");
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac");
    mac.update(data.as_bytes());
    let sig = b64url(&mac.finalize().into_bytes());
    format!("{data}.{sig}")
}

/// Верифицировать JWT и вернуть (sub, sid, v, typ).
#[allow(clippy::type_complexity)] // GATE: JWT claims tuple is the standard claims shape
fn jwt_verify_full(
    secret: &[u8; 32],
    token: &str,
) -> Option<(String, Option<String>, Option<u32>, Option<String>)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let data = format!("{}.{}", parts[0], parts[1]);
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(data.as_bytes());
    let expect = b64url(&mac.finalize().into_bytes());
    if expect != parts[2] {
        return None;
    }
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .ok()?,
    )
    .ok()?;
    let exp = claims["exp"].as_i64()?;
    if exp < proto::now_ms() / 1000 {
        return None;
    }
    let sub = claims["sub"].as_str()?.to_string();
    let sid = claims["sid"].as_str().map(String::from);
    let v = claims["v"].as_u64().map(|x| x as u32);
    let typ = claims["typ"].as_str().map(String::from);
    Some((sub, sid, v, typ))
}

#[allow(dead_code)] // GATE: HS256 helpers retained for operator tooling
fn jwt_verify(secret: &[u8; 32], token: &str) -> Option<String> {
    jwt_verify_full(secret, token).map(|(s, _, _, _)| s)
}

/// JWT с доп. claim "pk" (публичный ключ кошелька) — для temp-токенов web3.
/// Возвращает (sub, pk, verified). verified=true только если владение адресом было
/// доказано криптографическим proof (pk криптографически привязан к адресу).
fn jwt_verify_pk(secret: &[u8; 32], token: &str) -> Option<(String, Option<String>, bool)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let data = format!("{}.{}", parts[0], parts[1]);
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(data.as_bytes());
    let expect = b64url(&mac.finalize().into_bytes());
    if expect != parts[2] {
        return None;
    }
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .ok()?,
    )
    .ok()?;
    let exp = claims["exp"].as_i64()?;
    if exp < proto::now_ms() / 1000 {
        return None;
    }
    let verified = claims["v"].as_i64().unwrap_or(0) == 1;
    Some((
        claims["sub"].as_str()?.to_string(),
        claims["pk"].as_str().map(String::from),
        verified,
    ))
}

fn jwt_sign_web3(secret: &[u8; 32], sub: &str, pk: &str, verified: bool, ttl_secs: i64) -> String {
    let iat = proto::now_ms() / 1000;
    let exp = iat + ttl_secs;
    let header = b64url(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    let claims = b64url(
        json!({"sub": sub, "pk": pk, "v": if verified { 1 } else { 0 }, "iat": iat, "exp": exp})
            .to_string()
            .as_bytes(),
    );
    let data = format!("{header}.{claims}");
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac");
    mac.update(data.as_bytes());
    let sig = b64url(&mac.finalize().into_bytes());
    format!("{data}.{sig}")
}

fn bearer_token(headers: &HeaderMap) -> &str {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|a| a.strip_prefix("Bearer "))
        .unwrap_or("")
}

/// Имя httpOnly-cookie сессии.
const SESSION_COOKIE: &str = "infmail_session";

/// Прочитать токен из Cookie-заголовка (httpOnly-сессия, ставится при входе).
fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookies.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == SESSION_COOKIE {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// HTTP-ответ с Set-Cookie: httpOnly, SameSite=Lax, Path=/api (не светится скриптам).
fn ok_with_session(body: serde_json::Value, token: &str, max_age_secs: i64) -> Response {
    let mut resp = ok_json(body);
    let cookie_val = format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Secure; Path=/api; Max-Age={max_age_secs}"
    );
    if let Ok(v) = header::HeaderValue::from_str(&cookie_val) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

async fn auth_email(st: &WebState, headers: &HeaderMap) -> Result<String, Response> {
    auth_email_sid(st, headers).await.map(|(e, _)| e)
}

/// Авторизация ВТОРОГО ШАГА 2FA (только для /auth/verify-2fa).
/// Принимает временный токен (typ="2fa"), выданный логином до ввода кода.
/// Для всех остальных ручек такой токен бесполезен: auth_email_sid его отвергает.
async fn auth_email_2fa(st: &WebState, headers: &HeaderMap) -> Result<String, Response> {
    let token = if !bearer_token(headers).is_empty() {
        bearer_token(headers).to_string()
    } else {
        cookie_token(headers).ok_or_else(|| err_unauth("authentication required"))?
    };
    let (sub, _sid, _v, typ) =
        jwt_verify_full(&st.jwt_secret, &token).ok_or_else(|| err_unauth("token expired"))?;
    match typ.as_deref() {
        // временный токен шага 2FA — ровно то, что нужно
        Some("2fa") => Ok(sub),
        // уже вошедший пользователь тоже может подтвердить код
        Some("session") => Ok(sub),
        _ => Err(err_unauth("verification token required")),
    }
}

/// Проверка авторизации с валидацией сессии (sid + session_epoch).
/// Возвращает (email, sid).
/// Является ли разобранный токен СЕССИЕЙ.
/// Сессия — это `typ`="session" И непустой `sid`.
/// Токен без sid (например, временный токен второго шага 2FA) сессией НЕ является:
/// иначе знание одного пароля давало бы полный доступ в обход 2FA.
/// Обратная совместимость: ранее выданные сессии содержат sid и не содержат `typ`.
fn is_session_token(typ: Option<&str>, sid: Option<&str>) -> bool {
    match typ {
        Some("session") => sid.is_some(),
        Some(_) => false,
        None => sid.is_some(),
    }
}

#[cfg(test)]
mod auth_token_tests {
    use super::{is_session_token, jwt_sign_2fa, jwt_sign_full, jwt_verify_full};

    const SECRET: [u8; 32] = [7u8; 32];

    #[test]
    fn session_token_carries_sid_and_session_type() {
        let t = jwt_sign_full(&SECRET, "q1@infmail.org", 60, Some("sid-1"), Some(0));
        let (sub, sid, _v, typ) = jwt_verify_full(&SECRET, &t).expect("session token must verify");
        assert_eq!(sub, "q1@infmail.org");
        assert_eq!(sid.as_deref(), Some("sid-1"));
        assert_eq!(typ.as_deref(), Some("session"));
        assert!(is_session_token(typ.as_deref(), sid.as_deref()));
    }

    /// ГЛАВНЫЙ РЕГРЕСС-ТЕСТ: временный токен второго шага 2FA не должен
    /// приниматься как сессия, иначе знание одного пароля даёт полный доступ
    /// в обход 2FA (выключение 2FA, чтение почты, смена пароля).
    #[test]
    fn twofa_temp_token_is_not_a_session() {
        let t = jwt_sign_2fa(&SECRET, "q1@infmail.org");
        let (sub, sid, _v, typ) = jwt_verify_full(&SECRET, &t).expect("2fa token must verify");
        assert_eq!(sub, "q1@infmail.org");
        assert!(sid.is_none(), "у временного токена 2FA не должно быть sid");
        assert_eq!(typ.as_deref(), Some("2fa"));
        assert!(
            !is_session_token(typ.as_deref(), sid.as_deref()),
            "токен 2FA принят как сессия — обход 2FA вернулся"
        );
    }

    #[test]
    fn session_decision_matrix() {
        // токен без sid и без typ — это ровно тот баг, что был: НЕ сессия
        assert!(!is_session_token(None, None));
        // сессия без sid — не сессия
        assert!(!is_session_token(Some("session"), None));
        // неизвестный тип отвергается, даже если sid подложен
        assert!(!is_session_token(Some("2fa"), Some("sid-1")));
        assert!(!is_session_token(Some(""), Some("sid-1")));
        // обратная совместимость: ранее выданная сессия (sid есть, typ нет)
        assert!(is_session_token(None, Some("sid-1")));
    }

    #[test]
    fn tampered_token_rejected() {
        let t = jwt_sign_full(&SECRET, "q1@infmail.org", 60, Some("sid-1"), None);
        // подменяем последний символ подписи
        let mut bad = t.clone();
        bad.pop();
        bad.push(if t.ends_with('A') { 'B' } else { 'A' });
        assert!(
            jwt_verify_full(&SECRET, &bad).is_none(),
            "подделанная подпись принята"
        );
        // подпись другим секретом
        let other = jwt_sign_full(&[9u8; 32], "q1@infmail.org", 60, Some("sid-1"), None);
        assert!(jwt_verify_full(&SECRET, &other).is_none());
    }
}

async fn auth_email_sid(
    st: &WebState,
    headers: &HeaderMap,
) -> Result<(String, Option<String>), Response> {
    // Bearer (локальный/мульти-аккаунт) ИЛИ httpOnly-cookie (основная сессия) — любой источник.
    let token = if !bearer_token(headers).is_empty() {
        bearer_token(headers).to_string()
    } else {
        cookie_token(headers).ok_or_else(|| err_unauth("authentication required"))?
    };
    let (sub, sid, v, typ) =
        jwt_verify_full(&st.jwt_secret, &token).ok_or_else(|| err_unauth("session expired"))?;
    // СЕССИЕЙ считается только токен с typ="session" И непустым sid.
    // Токен без sid (например, временный токен второго шага 2FA) ОТВЕРГАЕМ:
    // иначе знание одного пароля давало бы полный доступ в обход 2FA.
    // Обратная совместимость: ранее выданные сессии содержат sid и не содержат typ.
    let sid = match (is_session_token(typ.as_deref(), sid.as_deref()), sid) {
        (true, Some(s)) => s,
        _ => return Err(err_unauth("session required")),
    };
    {
        let db = st.db.lock().await;
        let acc = db
            .accounts
            .get(&sub)
            .ok_or_else(|| err_unauth("account not found"))?;
        if let Some(expected) = v {
            if acc.session_epoch != expected {
                return Err(err_unauth("session revoked"));
            }
        }
        let alive = acc.sessions.iter().any(|s| s.id == sid);
        drop(db);
        if !alive {
            return Err(err_unauth("session revoked"));
        }
    }
    Ok((sub, Some(sid)))
}

/// Выдать сессию: создаёт/обновляет запись в аккаунте и возвращает JWT с sid.
/// Если sid уже активен — обновляем last_seen; иначе создаём новую сессию.
async fn issue_session(st: &WebState, email: &str, device: &str, ip: &str) -> String {
    use rand::Rng;
    let sid: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let now = proto::now_ms();
    {
        let mut db = st.db.lock().await;
        if let Some(acc) = db.accounts.get_mut(email) {
            acc.sessions
                .retain(|s| now - s.last_seen_ms < 90 * 24 * 3600 * 1000);
            acc.sessions.push(SessionInfo {
                id: sid.clone(),
                device: device.to_string(),
                ip: ip.to_string(),
                created_ms: now,
                last_seen_ms: now,
                is_current: true,
            });
        }
        save_db(&st.db_path, &db).await;
    }
    jwt_sign_full(&st.jwt_secret, email, 7 * 86400, Some(&sid), None)
}

fn err_json(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

fn err_unauth(msg: &str) -> Response {
    err_json(StatusCode::UNAUTHORIZED, msg)
}

fn ok_json(v: Value) -> Response {
    (StatusCode::OK, Json(v)).into_response()
}

fn norm_email(e: &str) -> String {
    let t = e.trim().to_lowercase();
    if t.contains('@') {
        t
    } else {
        format!("{t}@{MAIL_DOMAIN}")
    }
}

fn valid_email(e: &str) -> bool {
    let local = e.strip_suffix(&format!("@{MAIL_DOMAIN}")).unwrap_or("");
    !local.is_empty()
        && local.len() <= 64
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        && !local.contains("..")
        && !local.starts_with('.')
        && !local.ends_with('.')
}

/// Защита от катастрофической потери базы: сколько аккаунтов было в последнем
/// успешном чтении/записи, и удалось ли вообще прочитать файл при старте.
static DB_GUARD_COUNT: AtomicUsize = AtomicUsize::new(0);
static DB_LOAD_OK: AtomicBool = AtomicBool::new(true);

/// Свежий ротационный бэкап accounts.json (страховка от потери базы).
async fn write_rotating_backup(path: &std::path::Path, data: &[u8]) {
    let Some(dir) = path.parent() else { return };
    let ts = proto::now_ms();
    let bak = dir.join(format!("accounts.json.bak-{ts}"));
    let _ = tokio::fs::write(&bak, data).await;
    let _ = set_private_perms(&bak).await;
    // оставляем 8 самых свежих
    if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
        // Сортируем по ВРЕМЕНИ изменения, а не по имени, и трогаем только файлы
        // ротации (accounts.json.bak-<число>). Ручные копии вроде
        // accounts.json.bak-web3 лексикографически «новее» любого bak-<ms> —
        // из-за этого ротация съедала не те файлы, а восстановление подставляло
        // старый бэкап (проверено: выбирался бэкап от 15 августа при 8 свежих).
        let mut baks: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        while let Ok(Some(e)) = rd.next_entry().await {
            let n = e.file_name().to_string_lossy().to_string();
            let is_rot = n
                .strip_prefix("accounts.json.bak-")
                .map(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false);
            if is_rot {
                if let Ok(md) = e.metadata().await {
                    if let Ok(mt) = md.modified() {
                        baks.push((mt, e.path()));
                    }
                }
            }
        }
        baks.sort_by(|a, b| b.0.cmp(&a.0)); // свежие сначала
        while baks.len() > 8 {
            if let Some((_, old)) = baks.pop() {
                let _ = tokio::fs::remove_file(old).await;
            }
        }
    }
}

/// Новейший бэкап, в котором реально есть аккаунты (для авто-восстановления).
async fn newest_backup_with_accounts(path: &std::path::Path) -> Option<(PathBuf, AccountsDb)> {
    let dir = path.parent()?;
    let mut rd = tokio::fs::read_dir(dir).await.ok()?;
    // Свежесть определяем по ВРЕМЕНИ ФАЙЛА. Раньше шла лексикографическая
    // сортировка: 'accounts.json.bak-web3' больше любого 'accounts.json.bak-<ms>',
    // поэтому авто-восстановление брало ручной бэкап от 15 августа вместо
    // сегодняшних — потеря 10 аккаунтов и 36 суток изменений.
    let mut baks: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    while let Ok(Some(e)) = rd.next_entry().await {
        let n = e.file_name().to_string_lossy().to_string();
        if n.starts_with("accounts.json.bak-") {
            if let Ok(md) = e.metadata().await {
                if let Ok(mt) = md.modified() {
                    baks.push((mt, e.path()));
                }
            }
        }
    }
    baks.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, b) in baks.into_iter() {
        if let Ok(data) = tokio::fs::read(&b).await {
            if let Ok(d) = serde_json::from_slice::<AccountsDb>(&data) {
                if !d.accounts.is_empty() {
                    return Some((b, d));
                }
            }
        }
    }
    None
}

/// Ключ шифрования секретов at-rest (smtp_pass): отдельный файл 0600 рядом с базой,
/// чтобы пароль ящика не лежал в accounts.json открытым текстом.
async fn secrets_key(path: &std::path::Path) -> Option<[u8; 32]> {
    let dir = path.parent()?;
    let kp = dir.join("secrets.key");
    if let Ok(d) = tokio::fs::read(&kp).await {
        if d.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&d);
            return Some(k);
        }
    }
    let mut k = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
    if tokio::fs::write(&kp, k).await.is_err() {
        return None;
    }
    set_private_perms(&kp).await;
    Some(k)
}

fn enc_secret(key: &[u8; 32], plain: &str) -> String {
    let (ct, nonce) = infnode::node::e2e_encrypt(key, plain.as_bytes());
    format!(
        "enc1:{}:{}",
        base64::engine::general_purpose::STANDARD.encode(nonce),
        base64::engine::general_purpose::STANDARD.encode(ct)
    )
}

fn dec_secret(key: &[u8; 32], stored: &str) -> Option<String> {
    let rest = stored.strip_prefix("enc1:")?;
    let mut it = rest.splitn(2, ':');
    let n = base64::engine::general_purpose::STANDARD
        .decode(it.next()?)
        .ok()?;
    let c = base64::engine::general_purpose::STANDARD
        .decode(it.next()?)
        .ok()?;
    let p = infnode::node::e2e_decrypt(key, &n, &c).ok()?;
    String::from_utf8(p).ok()
}

/// Расшифровать секреты аккаунтов, загруженных из файла (значения с префиксом enc1:).
async fn decrypt_secrets(path: &std::path::Path, db: &mut AccountsDb) {
    let Some(key) = secrets_key(path).await else {
        return;
    };
    for (email, a) in db.accounts.iter_mut() {
        if let Some(sp) = a.smtp_pass.clone() {
            if sp.starts_with("enc1:") {
                a.smtp_pass = dec_secret(&key, &sp);
                if a.smtp_pass.is_none() {
                    eprintln!(
                        "[web] WARN: smtp_pass не расшифрован ({email}) — пароль ящика недоступен, \
                         почтовый мост для аккаунта работать не будет"
                    );
                }
            }
        }
    }
}

async fn load_db(path: &PathBuf) -> AccountsDb {
    match tokio::fs::read(path).await {
        Ok(data) => {
            if data.is_empty() {
                if let Some(d) = recover_if_empty(path).await {
                    return d;
                }
                DB_GUARD_COUNT.store(0, Ordering::SeqCst);
                return AccountsDb::default();
            }
            match serde_json::from_slice::<AccountsDb>(&data) {
                Ok(mut d) => {
                    if d.accounts.is_empty() {
                        if let Some(mut rec) = recover_if_empty(path).await {
                            decrypt_secrets(path, &mut rec).await;
                            DB_GUARD_COUNT.store(rec.accounts.len(), Ordering::SeqCst);
                            return rec;
                        }
                    }
                    decrypt_secrets(path, &mut d).await;
                    DB_GUARD_COUNT.store(d.accounts.len(), Ordering::SeqCst);
                    d
                }
                Err(e) => {
                    // РАНЬШЕ: unwrap_or_default() -> пустая база -> первый же save_db
                    // ЗАТИРАЛ файл (потеря всех аккаунтов). Теперь: громко логируем,
                    // запись ОТКЛЮЧАЕМ, файл не трогаем.
                    let n = serde_json::from_slice::<serde_json::Value>(&data)
                        .ok()
                        .and_then(|v| {
                            v.get("accounts")
                                .and_then(|a| a.as_object().map(|o| o.len()))
                        })
                        .unwrap_or(0);
                    eprintln!(
                        "[web] CRITICAL: accounts.json не распарсился ({e}); аккаунтов в файле ~{n}. \
                         Запись ОТКЛЮЧЕНА, файл не тронут (защита от потери базы)."
                    );
                    DB_LOAD_OK.store(false, Ordering::SeqCst);
                    DB_GUARD_COUNT.store(n, Ordering::SeqCst);
                    AccountsDb::default()
                }
            }
        }
        Err(_) => {
            // файла нет/не читается — пробуем поднять из ротационного бэкапа
            if let Some((bak, mut d)) = newest_backup_with_accounts(path).await {
                eprintln!(
                    "[web] CRITICAL: accounts.json отсутствует/пуст — восстановлен из {} ({} акк.)",
                    bak.display(),
                    d.accounts.len()
                );
                decrypt_secrets(path, &mut d).await;
                DB_GUARD_COUNT.store(d.accounts.len(), Ordering::SeqCst);
                return d;
            }
            DB_GUARD_COUNT.store(0, Ordering::SeqCst);
            AccountsDb::default()
        }
    }
}

/// Если основная база пустая, а бэкап содержит данные — поднимаем из бэкапа.
async fn recover_if_empty(path: &PathBuf) -> Option<AccountsDb> {
    if let Some((bak, d)) = newest_backup_with_accounts(path).await {
        eprintln!(
            "[web] CRITICAL: основная база пуста — восстановлена из {} ({} акк.)",
            bak.display(),
            d.accounts.len()
        );
        DB_LOAD_OK.store(true, Ordering::SeqCst);
        DB_GUARD_COUNT.store(d.accounts.len(), Ordering::SeqCst);
        save_db(path, &d).await;
        return Some(d);
    }
    None
}

async fn save_db(path: &PathBuf, db: &AccountsDb) {
    // ЗАЩИТНЫЕ ВОРОТА: не даём затереть непустую базу пустой/резко усечённой.
    let new_n = db.accounts.len();
    let last = DB_GUARD_COUNT.load(Ordering::SeqCst);
    if !DB_LOAD_OK.load(Ordering::SeqCst) {
        eprintln!("[web] CRITICAL: save_db отклонён — исходное чтение базы было неудачным; accounts.json не тронут");
        return;
    }
    if new_n == 0 && last > 0 {
        eprintln!("[web] CRITICAL: save_db отклонён — попытка записать ПУСТУЮ базу поверх {last} аккаунтов");
        return;
    }
    if last > 100 && new_n * 2 < last {
        eprintln!(
            "[web] CRITICAL: save_db отклонён — подозрительное усыхание базы {last} -> {new_n}"
        );
        return;
    }
    // ШИФР AT-REST: smtp_pass пишем в файл только в зашифрованном виде.
    let out_db = match secrets_key(path).await {
        Some(k) => {
            let mut c = db.clone();
            for a in c.accounts.values_mut() {
                if let Some(sp) = a.smtp_pass.clone() {
                    if !sp.starts_with("enc1:") {
                        a.smtp_pass = Some(enc_secret(&k, &sp));
                    }
                }
            }
            c
        }
        None => db.clone(),
    };
    if let Ok(json) = serde_json::to_vec_pretty(&out_db) {
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        // страховка: перед перезаписью сохраняем текущее содержимое файла (ротация 8)
        if let Ok(cur) = tokio::fs::read(path).await {
            if !cur.is_empty() {
                write_rotating_backup(path, &cur).await;
            }
        }
        // атомарная запись: temp + rename, чтобы обрыв в момент записи не усекал файл
        let tmp = path.with_extension("tmp");
        let _ = tokio::fs::write(&tmp, json).await;
        // ПРАВА: файл содержит pw_hash, smtp_pass, totp_secret, enc_priv, backup_codes.
        // Ставим 0600 ДО rename, иначе файл существует с правами по umask (было 0644 —
        // читаемо всем, включая smtp_pass открытым текстом).
        set_private_perms(&tmp).await;
        let _ = tokio::fs::rename(&tmp, path).await;
        set_private_perms(path).await;
        DB_GUARD_COUNT.store(new_n, Ordering::SeqCst);
    }
}

/// Выставить 0600 (только владелец) на файл с секретами. No-op вне Unix.
async fn set_private_perms(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Репликация аккаунтов в DHT-хранилище (профили БЕЗ секретов: pw_hash, smtp_pass,
/// e2e_secret, backup_codes не реплицируются). Ключ `acct:{email}` доступен по сети —
/// позволяет восстановить профили/квоты/подписки при потере валидатора.
fn account_public_profile(a: &Account) -> serde_json::Value {
    json!({
        "email_exists": true,
        "created_ms": a.created_ms,
        "aliases": a.aliases,
        "quota_limit": a.quota_limit,
        "bytes_used": a.bytes_used,
        "file_quota_limit": a.file_quota_limit,
        "files_used": a.files_used,
        "plan": a.plan,
        "paid_until_ms": a.paid_until_ms,
        "wallet": a.wallet,
        "x_pub": a.x_pub,
        "ed_pub": a.ed_pub,
        "totp_enabled": a.totp_enabled,
        "session_epoch": a.session_epoch,
    })
}

/// DHT-ключ профиля: непрозрачный (blake3 от email). Адрес НЕ светится в имени
/// ключа, разложенного по сети — иначе любой узел собрал бы список всех абонентов.
pub fn acct_dht_key(email: &str) -> String {
    format!(
        "acct:{}",
        hex::encode(blake3::hash(email.to_lowercase().as_bytes()).as_bytes())
    )
}

/// Фоновый цикл: раз в 5 минут пишет публичные профили всех аккаунтов в DHT
/// (непрозрачный ключ acct:{blake3(email)}). Списка адресов в сети НЕТ — иначе
/// это была бы раздача всей абонентской базы; восстановление идёт ПО ЗАПРОСУ.
pub async fn replicate_accounts_loop(node: &Arc<infnode::node::Node>, db: &Arc<Mutex<AccountsDb>>) {
    // первый прогон — сразу после старта (не ждём 5 минут), затем раз в 5 минут
    let mut first = true;
    loop {
        if !first {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        }
        first = false;
        let snapshot = db.lock().await.clone();
        let mut ok = 0usize;
        for (email, acc) in snapshot.accounts.iter() {
            let profile = account_public_profile(acc).to_string();
            if kv_set(node, &acct_dht_key(email), &profile).await > 0 {
                ok += 1;
            }
        }
        eprintln!(
            "[web] account profiles replicated to DHT: {ok}/{}",
            snapshot.accounts.len()
        );
    }
}

/// Восстановление ОДНОГО профиля из DHT по запросу (когда пользователь
/// обратился, а локально записи нет — узел потерял базу). Адрес знает сам
/// пользователь, поэтому перебора «всех ключей» не требуется и список
/// абонентов сеть не хранит. Восстанавливаются только несекретные поля:
/// pw_hash/секреты — нет, поэтому парольный вход для восстановленной записи
/// невозможен (вход остаётся кошельком/восстановлением).
pub async fn restore_account_on_demand(
    node: &Arc<infnode::node::Node>,
    db: &Arc<Mutex<AccountsDb>>,
    db_path: &PathBuf,
    email: &str,
) -> bool {
    let email = email.to_lowercase();
    if db.lock().await.accounts.contains_key(&email) {
        return true;
    }
    let raw = match kv_get(node, &acct_dht_key(&email)).await {
        Some(v) => v,
        None => return false,
    };
    let p: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if p["email_exists"].as_bool() != Some(true) {
        return false;
    }
    let mut acc = Account {
        pw_hash: String::new(),
        ..Account::default()
    };
    acc.created_ms = p["created_ms"].as_i64().unwrap_or(0);
    acc.quota_limit = p["quota_limit"].as_u64().unwrap_or(0);
    acc.bytes_used = p["bytes_used"].as_u64().unwrap_or(0);
    acc.file_quota_limit = p["file_quota_limit"].as_u64().unwrap_or(0);
    acc.files_used = p["files_used"].as_u64().unwrap_or(0);
    acc.plan = p["plan"].as_str().unwrap_or("free").to_string();
    acc.paid_until_ms = p["paid_until_ms"].as_i64().unwrap_or(0);
    acc.wallet = p["wallet"].as_str().map(String::from);
    acc.x_pub = p["x_pub"].as_str().map(String::from);
    acc.ed_pub = p["ed_pub"].as_str().map(String::from);
    acc.totp_enabled = p["totp_enabled"].as_bool().unwrap_or(false);
    acc.session_epoch = p["session_epoch"].as_u64().unwrap_or(0) as u32;
    acc.aliases = p["aliases"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    db.lock().await.accounts.insert(email.clone(), acc);
    let snap = db.lock().await.clone();
    save_db(db_path, &snap).await;
    eprintln!("[web] restored account {email} from DHT (on-demand)");
    true
}
// ─────────────────────────────────────────────────────────────
// DHT-KV / storage помощники
// ─────────────────────────────────────────────────────────────

/// Локальный KV-гет (без сетевого поиска) — для индексов/данных, авторитетных на этой ноде.
async fn kv_get_local(node: &Arc<Node>, key: &str) -> Option<String> {
    node.get_local_kv(key).await
}

async fn kv_get(node: &Arc<Node>, key: &str) -> Option<String> {
    if let Some(v) = node.get_local_kv(key).await {
        return Some(v);
    }
    // СЕТЕВАЯ ВЕТКА ОГРАНИЧЕНА ПО ВРЕМЕНИ. Без этого поиск ОТСУТСТВУЮЩЕГО ключа
    // в DHT мог не возвращаться никогда: страница настроек вечно ждала
    // GET /mail/blacklist (пустой чёрный список у свежего аккаунта) — наблюдалось
    // вручную в браузере как зависший запрос (HTTP 000 / 500 в консоли).
    let n2 = node.clone();
    let k2 = key.to_string();
    tokio::time::timeout(std::time::Duration::from_millis(3000), kv_get_net(&n2, &k2))
        .await
        .ok()
        .flatten()
}

/// Сетевая часть kv_get (без таймаута). Вызывать только через kv_get.
async fn kv_get_net(node: &Arc<Node>, key: &str) -> Option<String> {
    let h = blake3::hash(key.as_bytes());
    let mut target = [0u8; proto::NODEID_LEN];
    target.copy_from_slice(&h.as_bytes()[..proto::NODEID_LEN]);
    let closest = node.dht_find_node(&target).await;
    let q = json!({ "key": key }).to_string().into_bytes();
    for info in closest {
        if node.ensure_dht_peer(&info).await.is_ok() {
            if let Ok(resp) = node.request_to(info.id, "dht.find_value", q.clone()).await {
                if let Ok(v) = serde_json::from_slice::<Value>(&resp) {
                    if v["found"].as_bool().unwrap_or(false) {
                        return v["value"].as_str().map(String::from);
                    }
                }
            }
        }
    }
    None
}

/// Быстрая проверка наличия ключа: локально + сеть с коротким таймаутом.
async fn kv_get_quick(node: &Arc<Node>, key: &str, timeout_ms: u64) -> Option<String> {
    let node = node.clone();
    let key = key.to_string();
    tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        kv_get(&node, &key),
    )
    .await
    .ok()
    .flatten()
}

async fn kv_set(node: &Arc<Node>, key: &str, value: &str) -> usize {
    // самодостаточность: запись всегда остаётся и локально (валидатор = нода DHT)
    node.kv_store_local(key, value).await;
    // удалённая репликация — фоновая (best-effort, не блокирует API)
    let node = node.clone();
    let key = key.to_string();
    let value = value.to_string();
    tokio::spawn(async move {
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(8000),
            async {
                let h = blake3::hash(key.as_bytes());
                let mut target = [0u8; proto::NODEID_LEN];
                target.copy_from_slice(&h.as_bytes()[..proto::NODEID_LEN]);
                let closest = node.dht_find_node(&target).await;
                // тот же TTL, что и локально (30 дней): реплика на ноде не должна
                // протухать раньше оригинала (иначе DHT-fallback вернёт пустоту)
                let payload = json!({ "key": key, "value": value, "ttl": 30 * 24 * 3600, "stored_at": proto::now_ms() }).to_string().into_bytes();
                for info in closest {
                    if node.ensure_dht_peer(&info).await.is_ok() {
                        let _ = node.request_to(info.id, "dht.store", payload.clone()).await;
                    }
                }
            },
        )
        .await;
    });
    1
}

async fn registry_get(node: &Arc<Node>, email: &str) -> Option<Value> {
    // Вызывается при авторизации КАЖДОГО запроса: длинный сетевой таймаут здесь
    // тормозил весь интерфейс (2.5с на запрос). Локально запись есть почти всегда.
    let v = kv_get_quick(node, &format!("user:{email}"), 400).await?;
    serde_json::from_str(&v).ok()
}

async fn registry_set(node: &Arc<Node>, email: &str, x_hex: &str, ed_hex: &str) {
    kv_set(
        node,
        &format!("user:{email}"),
        &json!({ "x_pub": x_hex, "ed_pub": ed_hex }).to_string(),
    )
    .await;
}

async fn index_list(node: &Arc<Node>, key: &str) -> Vec<String> {
    // Индекс ящика: сначала локальный KV (быстрая, основная ветка), при промахе — с ближайших
    // нод (DHT-fallback). Это делает ноды реальными держателями «каталога» писем: ящик
    // восстанавливается из сети при потере kv.json валидатора.
    if let Some(s) = node.get_local_kv(key).await {
        let ids: Vec<String> = serde_json::from_str(&s).unwrap_or_default();
        return apply_tombs_filter(node, key, ids).await;
    }
    // ЖЁСТКИЙ таймаут на всю сетевую ветку: kv_get_quick может не отвечать
    // (битый стрим пира), и тогда index_list вешал вызывающий HTTP-запрос навсегда.
    // Наблюдалось на черновиках: у свежего аккаунта индекса нет локально -> всегда
    // шли в сеть -> POST /mail/draft висел (HTTP 000), тогда как блокировка/удаление
    // (локальный key-hit) работали.
    // Локальный путь основной. Сетевой фолбэк нужен редко, но раньше он ждал
    // 2.5с НА КАЖДЫЙ запрос (наблюдалось: /mail/inbox, /mail/counts, /mail/sent —
    // ровно 2.5с каждый), из-за чего почта грузилась очень долго.
    let ids: Vec<String> = match tokio::time::timeout(
        std::time::Duration::from_millis(1100),
        kv_get_quick(node, key, 1000),
    )
    .await
    {
        Ok(Some(s)) => serde_json::from_str(&s).unwrap_or_default(),
        Ok(None) => Vec::new(),
        Err(_) => {
            eprintln!("[web] WARN: index_list({key}) DHT lookup timed out - treating as empty");
            Vec::new()
        }
    };
    apply_tombs_filter(node, key, ids).await
}

async fn index_add(node: &Arc<Node>, key: &str, id: &str) {
    let mut ids = index_list(node, key).await;
    if !ids.iter().any(|x| x == id) {
        ids.push(id.to_string());
    }
    // повторное добавление (восстановление из trash) снимает tombstone, иначе
    // слияние со старой репликой его не воскресит, а чтение отфильтрует как удалённое
    tomb_remove(node, key, id).await;
    kv_set(
        node,
        key,
        &serde_json::to_string(&ids).unwrap_or("[]".into()),
    )
    .await;
}

async fn index_remove(node: &Arc<Node>, key: &str, id: &str) {
    let mut ids = index_list(node, key).await;
    ids.retain(|x| x != id);
    // tombstone для OR-set слияния: union старых реплик не должен воскрешать удалённое
    tomb_add(node, key, id).await;
    kv_set(
        node,
        key,
        &serde_json::to_string(&ids).unwrap_or("[]".into()),
    )
    .await;
}

/// Ключ tombstones индексного ключа: "{index}:tombs" -> {id: ts_ms}.
fn tombs_key(key: &str) -> String {
    format!("{key}:tombs")
}

async fn tombs_get(node: &Arc<Node>, key: &str) -> std::collections::HashMap<String, i64> {
    let tkey = tombs_key(key);
    if let Some(s) = node.get_local_kv(&tkey).await {
        return serde_json::from_str(&s).unwrap_or_default();
    }
    Default::default()
}

async fn tomb_add(node: &Arc<Node>, key: &str, id: &str) {
    let mut tombs = tombs_get(node, key).await;
    tombs.insert(id.to_string(), proto::now_ms());
    kv_set(
        node,
        &tombs_key(key),
        &serde_json::to_string(&tombs).unwrap_or("{}".into()),
    )
    .await;
}

async fn tomb_remove(node: &Arc<Node>, key: &str, id: &str) {
    let mut tombs = tombs_get(node, key).await;
    if tombs.remove(id).is_some() {
        kv_set(
            node,
            &tombs_key(key),
            &serde_json::to_string(&tombs).unwrap_or("{}".into()),
        )
        .await;
    }
}

/// Фильтр tombstones для чтения индекса (защита от воскрешения удалённого
/// при union-слиянии со старыми репликами). Ключи без tombstones не меняются.
async fn apply_tombs_filter(node: &Arc<Node>, key: &str, ids: Vec<String>) -> Vec<String> {
    if ids.is_empty() || !key.ends_with("index") {
        return ids;
    }
    let tombs = tombs_get(node, key).await;
    if tombs.is_empty() {
        return ids;
    }
    ids.into_iter().filter(|x| !tombs.contains_key(x)).collect()
}

/// Конверт хранения (zero-trust ноды): контент шифруется случайным DEK
/// (XSalsa20-Poly1305, совместим с tweetnacl secretbox), DEK — box'ом на x_pub
/// каждой стороны (raw-DH, как box_wrap_key). Сервер/ноды видят только мета
/// (sender/to/subject/имена вложений), тела и файлы — шифротекст.
/// Формат строкой (чтобы не ломать строковые поля API): "s1.<noncehex>.<b64ct>".
/// DEK-конверт объектом в поле "dek": {"nonce": hex, "boxes": {label: box}}.
/// Фронт открывает своим приватным ключом (scalarMult + secretbox.open).
fn storage_box_dek(pubs: &[(String, String)]) -> Option<([u8; 32], Value)> {
    let mut dek = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut dek);
    let mut boxes = serde_json::Map::new();
    for (label, pub_hex) in pubs {
        match infnode::node::box_wrap_key(pub_hex, &dek) {
            Some(b) => {
                boxes.insert(label.clone(), b);
            }
            None => return None,
        }
    }
    Some((dek, Value::Object(boxes)))
}

/// Зашифровать поле DEK'ом в строку "s1.<noncehex>.<b64ct>".
/// Строго XSalsa20 (xsalsa_encrypt): e2e_encrypt — XChaCha, его tweetnacl не открывает.
fn storage_seal(dek: &[u8; 32], plain: &[u8]) -> String {
    let (ct, nonce) = infnode::node::xsalsa_encrypt(dek, plain);
    format!(
        "s1.{}.{}",
        hex::encode(&nonce),
        base64::engine::general_purpose::STANDARD.encode(&ct)
    )
}

/// fetch_mail с таймаутом: сетевой меш не должен вешать HTTP-запрос (Inbox/открытие письма).
async fn fetch_mail_to(node: &Arc<Node>, name: &str, ms: u64) -> Option<Vec<u8>> {
    match tokio::time::timeout(std::time::Duration::from_millis(ms), node.fetch_mail(name)).await {
        Ok(b) => b,
        Err(_) => {
            eprintln!("[web] WARN: fetch {name} timed out ({ms}ms)");
            None
        }
    }
}

fn iso_date(ms: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(ms / 1000) {
        Ok(t) => t
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| ms.to_string()),
        Err(_) => ms.to_string(),
    }
}

// ─────────────────────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────────────────────

async fn pow_challenge() -> Response {
    let salt = hex::encode(rand::random::<[u8; 8]>());
    let ts = proto::now_ms();
    // фронт читает challengeData.salt / challengeData.difficulty НА ВЕРХНЕМ уровне
    ok_json(json!({
        "salt": salt,
        "difficulty": 3,
        "timestamp": ts,
        "signature": "infmail-pow-v1",
        "challenge": { "salt": salt, "difficulty": 3, "timestamp": ts, "signature": "infmail-pow-v1" },
    }))
}

/// Проверка PoW-решения: sha256(salt + nonce) должен начинаться с difficulty нулей,
/// а соль должна быть свежей (не старше POW_MAX_AGE_MS). Защита от ботов через прямой API.
fn verify_pow(solution: &Value) -> bool {
    let salt = solution["challenge"]["salt"].as_str().unwrap_or("");
    let difficulty = solution["challenge"]["difficulty"].as_u64().unwrap_or(0);
    let ts = solution["challenge"]["timestamp"].as_i64().unwrap_or(0);
    let nonce = solution["nonce"].as_u64().unwrap_or(0);
    // сервер НЕ доверяет клиентскому difficulty ниже минимума: клиент может занизить его,
    // чтобы обойти анти-бот. Минимум фиксирован (как выдаёт pow_challenge).
    const MIN_POW_DIFFICULTY: u64 = 3;
    if !(MIN_POW_DIFFICULTY..=32).contains(&difficulty) {
        return false;
    }
    // соль: ожидаем hex (8 случайных байт = 16 hex-символов), как выдаёт сервер
    if salt.len() != 16 || !salt.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    // соль свежая: не старше 10 минут и не из будущего (с допуском 60с)
    let now = proto::now_ms();
    if ts <= 0 || (now - ts).abs() > 10 * 60 * 1000 {
        return false;
    }
    let data = format!("{salt}{nonce}");
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    let hex = hex::encode(h.finalize());
    hex.starts_with(&"0".repeat(difficulty as usize))
}

#[derive(Deserialize)]
struct RegisterReq {
    email: String,
    password: String,
    solution: Option<Value>,
}

async fn register(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<RegisterReq>,
) -> Response {
    // анти-бот: не более 100 регистраций с IP за 10 мин
    let ip = client_ip(&headers);
    if rate_limit(&st.reg_guard, &ip, 100, 10 * 60 * 1000).await {
        return err_json(
            StatusCode::TOO_MANY_REQUESTS,
            "too many registrations, wait",
        );
    }
    let email = norm_email(&req.email);
    if !valid_email(&email) {
        return err_json(StatusCode::BAD_REQUEST, "invalid email (only @infmail.org)");
    }
    if req.password.len() < 8 {
        return err_json(
            StatusCode::BAD_REQUEST,
            "password is shorter than 8 characters",
        );
    }
    // PoW-проверка: обязательна, если не отключена env INFNODE_POW_DISABLED=1
    if std::env::var("INFNODE_POW_DISABLED").as_deref() != Ok("1") {
        match &req.solution {
            Some(sol) => {
                if !verify_pow(sol) {
                    return err_json(StatusCode::BAD_REQUEST, "PoW verification failed");
                }
                // Одноразовость решения: иначе один решённый PoW переигрывается
                // 10 минут на N регистраций (соль не привязана к выдаче).
                let pow_id = format!(
                    "pow:{}:{}",
                    sol["challenge"]["salt"].as_str().unwrap_or(""),
                    sol["nonce"].as_u64().unwrap_or(0)
                );
                if rate_limit(&st.reg_guard, &pow_id, 1, 10 * 60 * 1000).await {
                    return err_json(StatusCode::BAD_REQUEST, "PoW solution already used");
                }
            }
            None => {
                return err_json(StatusCode::BAD_REQUEST, "PoW solution required");
            }
        }
    }
    let mut db = st.db.lock().await;
    if db.accounts.contains_key(&email) {
        return err_json(StatusCode::CONFLICT, "this address is already registered");
    }
    if let Some(owner) = resolve_db_email(&db, &email) {
        if owner != email {
            return err_json(
                StatusCode::CONFLICT,
                "this address is an alias of another account",
            );
        }
    }
    // защита от захвата: email уже занят в DHT-реестре (зарегистрирован через CLI/иную ноду)
    if registry_get(&st.node, &email).await.is_some() {
        return err_json(
            StatusCode::CONFLICT,
            "this address is already registered on the network",
        );
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(req.password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_default();
    // SMTP-пароль для relay во внешнюю почту (генерится; ящик в MTA создаётся фоном)
    let smtp_pass = if std::env::var("INFNODE_SMTP_HOST").is_ok() {
        Some(gen_smtp_pass())
    } else {
        None
    };
    let acc = Account {
        pw_hash: hash,
        created_ms: proto::now_ms(),
        quota_limit: DEFAULT_QUOTA,
        bytes_used: 0,
        x_pub: None,
        ed_pub: None,
        enc_priv: None,
        aliases: Vec::new(),
        file_quota_limit: default_file_quota(),
        files_used: 0,
        smtp_pass: smtp_pass.clone(),
        wallet: None,
        wallet_pub: None,
        e2e_secret: None,
        files_key_secret: None,
        plan: "free".into(),
        paid_until_ms: 0,
        totp_secret: None,
        totp_enabled: false,
        backup_codes: Vec::new(),
        backup_codes_enc: Vec::new(),
        trusted_email: None,
        pending_email: None,
        sessions: Vec::new(),
        session_epoch: 0,
        signature: None,
    };
    db.accounts.insert(email.clone(), acc.clone());
    send_welcome_mail(&st, &email).await;
    save_db(&st.db_path, &db).await;
    drop(db);
    // профиль для DHT-репликации сразу (не ждём 5-минутный цикл — иначе свежий
    // аккаунт не восстановить, пока не отработает replicate_accounts_loop)
    {
        let node = st.node.clone();
        let email_c = email.clone();
        let profile_json = account_public_profile(&acc).to_string();
        tokio::spawn(async move {
            let _ = kv_set(&node, &acct_dht_key(&email_c), &profile_json).await;
        });
    }
    // фоном создаём ящик в MTA (stalwart) для исходящей почты
    if let Some(sp) = smtp_pass {
        let email2 = email.clone();
        tokio::spawn(async move {
            provision_stalwart_mailbox(&email2, &sp).await;
        });
    }
    let device = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .chars()
        .take(64)
        .collect::<String>();
    let token = issue_session(&st, &email, &device, &ip).await;
    ok_json(json!({ "token": token, "email": email }))
}

fn gen_smtp_pass() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#"
        .chars()
        .collect();
    (0..16)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

/// Создание ящика в MTA (stalwart) для исходящей SMTP-почты.
/// CLI: INFNODE_SMTP_CLI, STALWART_URL/USER/PASSWORD, INFNODE_SMTP_DOMAIN_ID.
async fn provision_stalwart_mailbox(email: &str, smtp_pass: &str) {
    let cli = std::env::var("INFNODE_SMTP_CLI").unwrap_or_else(|_| "stalwart-cli".into());
    let url = std::env::var("STALWART_URL").unwrap_or_else(|_| "http://localhost:8080".into());
    let user = std::env::var("STALWART_USER").unwrap_or_default();
    let pass = std::env::var("STALWART_PASSWORD").unwrap_or_default();
    let domain_id = std::env::var("INFNODE_SMTP_DOMAIN_ID").unwrap_or_else(|_| "b".into());
    let local = email.split('@').next().unwrap_or(email);
    let creds = json!({ "0": { "@type": "Password", "secret": smtp_pass } }).to_string();
    let out = tokio::process::Command::new(&cli)
        .env("STALWART_URL", &url)
        .env("STALWART_USER", &user)
        .env("STALWART_PASSWORD", &pass)
        .arg("create")
        .arg("account/user")
        .arg("--field")
        .arg(format!("name={local}"))
        .arg("--field")
        .arg(format!("domainId={domain_id}"))
        .arg("--field")
        .arg(format!("credentials={creds}"))
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {
            eprintln!("[web] stalwart mailbox created for {email}");
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains("already exists") || err.contains("primaryKeyViolation") {
                eprintln!("[web] stalwart mailbox for {email} already exists");
            } else {
                eprintln!("[web] stalwart provisioning failed for {email}: {err}");
            }
        }
        Err(e) => eprintln!("[web] stalwart cli launch failed: {e}"),
    }
}

/// Parity-восстановление пароля ящика: если админ/кто-то сменил пароль в stalwart-панели,
/// возвращаем его на smtp_pass из accounts.json (админ не может «украсть» ящик надолго,
/// юзер не теряет IMAP-доступ). Использует update account/user с credentials.
async fn restore_stalwart_password(email: &str, smtp_pass: &str) -> bool {
    let cli = std::env::var("INFNODE_SMTP_CLI").unwrap_or_else(|_| "stalwart-cli".into());
    let url = std::env::var("STALWART_URL").unwrap_or_else(|_| "http://localhost:8080".into());
    let user = std::env::var("STALWART_USER").unwrap_or_default();
    let pass = std::env::var("STALWART_PASSWORD").unwrap_or_default();
    let local = email.split('@').next().unwrap_or(email);
    let creds = json!({ "0": { "@type": "Password", "secret": smtp_pass } }).to_string();
    let out = tokio::process::Command::new(&cli)
        .env("STALWART_URL", &url)
        .env("STALWART_USER", &user)
        .env("STALWART_PASSWORD", &pass)
        .arg("update")
        .arg("account")
        .arg("--user")
        .arg(&user)
        .arg("--password")
        .arg(&pass)
        .arg("--url")
        .arg(&url)
        .arg("Account")
        .arg(local)
        .arg("--json")
        .arg(format!("{{\"credentials\":{creds}}}"))
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {
            eprintln!("[web] stalwart mailbox password {email} restored (parity)");
            true
        }
        Ok(o) => {
            eprintln!(
                "[web] stalwart parity restore failed {email}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            false
        }
        Err(e) => {
            eprintln!("[web] stalwart cli parity launch failed: {e}");
            false
        }
    }
}

#[derive(Deserialize)]
struct LoginReq {
    email: String,
    password: String,
}

async fn login(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Response {
    let email = norm_email(&req.email);
    let ip = client_ip(&headers);
    // если записи нет локально — возможно, узел потерял базу: пробуем поднять
    // профиль из DHT (по непрозрачному ключу; список абонентов сеть не хранит)
    if !st.db.lock().await.accounts.contains_key(&email) {
        let _ = restore_account_on_demand(&st.node, &st.db, &st.db_path, &email).await;
    }
    let db = st.db.lock().await;
    let acc = match db.accounts.get(&email) {
        Some(a) => a,
        None => {
            drop(db);
            // брутфорс-защита: считаем ТОЛЬКО неудачные попытки с IP за 15 мин
            if rate_limit(&st.login_guard, &ip, 10, 15 * 60 * 1000).await {
                return err_json(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many login attempts, wait",
                );
            }
            return err_json(StatusCode::UNAUTHORIZED, "invalid email or password");
        }
    };
    // хэш копируем и ОТПУСКАЕМ мьютекс до тяжёлого Argon2 (раньше verify держал
    // глобальный lock БД ~100-500мс: N параллельных логинов вешали весь API)
    let pw_hash = acc.pw_hash.clone();
    let need_2fa_early = acc.totp_enabled;
    drop(db);
    let ok = PasswordHash::new(&pw_hash)
        .map(|h| {
            Argon2::default()
                .verify_password(req.password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false);
    if !ok {
        if rate_limit(&st.login_guard, &ip, 10, 15 * 60 * 1000).await {
            return err_json(
                StatusCode::TOO_MANY_REQUESTS,
                "too many login attempts, wait",
            );
        }
        return err_json(StatusCode::UNAUTHORIZED, "invalid email or password");
    }
    // успешный вход — сбрасываем счётчик попыток для IP
    st.login_guard.lock().await.remove(&ip);
    // если включена 2FA — требуем код аутентификатора (temp-токен на 5 мин)
    let need_2fa = need_2fa_early;
    if need_2fa {
        return ok_json(json!({
            "status": "require_2fa",
            "temp_2fa_token": jwt_sign_2fa(&st.jwt_secret, &email),
        }));
    }
    let device = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .chars()
        .take(64)
        .collect::<String>();
    let token = issue_session(&st, &email, &device, &ip).await;
    ok_with_session(
        json!({ "token": token.clone(), "email": email }),
        &token,
        7 * 24 * 3600,
    )
}

async fn me(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let db = st.db.lock().await;
    let acc = db.accounts.get(&email);
    match acc {
        Some(a) => {
            // П3-индикатор для UI: привязаны ли письма к кошельку (x_pub из подписи),
            // эпоха владельца (маркер из save-keys; виден только владельцу сессии).
            let p3_bound = a.x_pub.is_some();
            let p3_epoch: Option<String> = if p3_bound { a.e2e_secret.clone() } else { None };
            ok_json(json!({
                "email": email, "type": "classic",
                "name": email.split('@').next().unwrap_or(""),
                "created_ms": a.created_ms,
                "p3_bound": p3_bound,
                "p3_epoch": p3_epoch,
            }))
        }
        None => err_json(StatusCode::UNAUTHORIZED, "account not found"),
    }
}

async fn renew_cookie(State(st): State<WebState>, headers: HeaderMap) -> Response {
    match auth_email_sid(&st, &headers).await {
        Ok((e, _old_sid)) => {
            // Ротация: выдаём НОВУЮ сессию (новый sid) вместо переиспользования старого,
            // чтобы перехваченный cookie нельзя было продлевать бесконечно.
            let device = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .chars()
                .take(64)
                .collect::<String>();
            let token = issue_session(&st, &e, &device, &client_ip(&headers)).await;
            ok_with_session(json!({ "token": token.clone() }), &token, 7 * 24 * 3600)
        }
        Err(r) => r,
    }
}

/// Выход: сбрасывает httpOnly-cookie и (опционально) отзывает текущую сессию.
async fn logout(State(st): State<WebState>, headers: HeaderMap) -> Response {
    if let Ok((email, Some(sid))) = auth_email_sid(&st, &headers).await {
        let mut db = st.db.lock().await;
        if let Some(acc) = db.accounts.get_mut(&email) {
            acc.sessions.retain(|s| s.id != sid);
        }
        save_db(&st.db_path, &db).await;
    }
    // сброс cookie (Max-Age=0) — даже если токен невалиден
    let cookie_val =
        format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Secure; Path=/api; Max-Age=0");
    let mut resp = ok_json(json!({ "ok": true }));
    if let Ok(v) = header::HeaderValue::from_str(&cookie_val) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// Доставить системное письмо от system@infmail.org в inbox юзера (внутреннее, без SMTP наружу).
async fn deliver_system_mail(st: &WebState, to_email: &str, subject: &str, body: &str) {
    let at = proto::now_ms();
    let id = hex::encode(
        blake3::hash(format!("sys:{to_email}:{at}:{}", rand::random::<u64>()).as_bytes())
            .as_bytes(),
    );
    let envelope = json!({
        "sender": "system@infmail.org", "to": to_email, "at": at,
        "subject": subject, "body": body, "attachments": [],
    })
    .to_string()
    .into_bytes();
    let _ = st.node.store_mail(&format!("mail:{id}"), &envelope).await;
    index_add(&st.node, &mail_index_key(to_email, "Inbox"), &id).await;
}

#[derive(Deserialize)]
struct RecoveryReq {
    email: String,
    new_pass: Option<String>,
    code: Option<String>,
    old_pass: Option<String>,
    /// TOTP/бэкап-код: обязателен при включённой 2FA (иначе сброс пароля
    /// по коду из inbox обходил второй фактор).
    totp_code: Option<String>,
}

async fn recovery_request(State(st): State<WebState>, Json(req): Json<RecoveryReq>) -> Response {
    let email = norm_email(&req.email);
    if !valid_email(&email) {
        return err_json(StatusCode::BAD_REQUEST, "invalid email");
    }
    // анти-флуд: не чаще 3 запросов/час с одного email
    if rate_limit(&st.recovery_guard, &email, 3, 3600 * 1000).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "too many recovery requests");
    }
    let db = st.db.lock().await;
    let exists = db.accounts.contains_key(&email);
    drop(db);
    if !exists {
        // не раскрываем существование аккаунта
        return ok_json(
            json!({ "ok": true, "message": "if the account exists — the code has been sent" }),
        );
    }
    use rand::Rng;
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    let code = code.to_ascii_uppercase();
    // код живёт 15 минут
    let rec = json!({ "code": code, "exp": proto::now_ms() + 15 * 60 * 1000 }).to_string();
    kv_set(&st.node, &format!("recovery:{email}"), &rec).await;
    // доставляем код внутренним письмом в inbox (без внешнего SMTP)
    deliver_system_mail(&st, &email, "InfMail password recovery", &format!(
        "Your recovery code: {code}\nThe code is valid for 15 minutes.\nIf this is not you, ignore this email."
    )).await;
    // методы восстановления для UI. ВАЖНО (oracle M1): для существующего адреса
    // раньше отдавались methods + trusted_email_masked, для несуществующего —
    // generic. Ответы унифицированы: methods всегда ["email"], маска — null.
    // Фронт узнаёт про 2FA-метод только после ввода валидного inbox-кода
    // (шаг reset вернёт require_2fa при включённой 2FA — см. recovery_2fa_hint),
    // а не из request.
    ok_json(json!({
        "ok": true,
        "message": "recovery code sent to your mailbox",
        "methods": ["email"],
        "trusted_email_masked": Value::Null,
    }))
}

/// Подсказка методов ВТОРОГО шага: вызывается с валидным inbox-кодом (или
/// доказанным владением) — здесь oracle уже не страшен, код знает только владелец.
async fn recovery_2fa_hint(State(st): State<WebState>, Json(req): Json<Value>) -> Response {
    let email = norm_email(req["email"].as_str().unwrap_or(""));
    let code = req["code"].as_str().unwrap_or("").to_ascii_uppercase();
    if !valid_email(&email) || code.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "invalid request");
    }
    let ok = match kv_get(&st.node, &format!("recovery:{email}")).await {
        Some(raw) => serde_json::from_str::<Value>(&raw)
            .ok()
            .map(|v| {
                v["code"].as_str() == Some(code.as_str())
                    && v["exp"].as_i64().unwrap_or(0) > proto::now_ms()
            })
            .unwrap_or(false),
        None => false,
    };
    if !ok {
        // намеренно та же ошибка, что и на неверный код в reset (без oracle)
        return err_json(
            StatusCode::FORBIDDEN,
            "invalid current password or recovery code",
        );
    }
    let db = st.db.lock().await;
    let needs_2fa = db
        .accounts
        .get(&email)
        .map(|a| a.totp_enabled)
        .unwrap_or(false);
    drop(db);
    ok_json(json!({ "ok": true, "needs_2fa": needs_2fa }))
}

async fn recovery_reset(State(st): State<WebState>, Json(req): Json<RecoveryReq>) -> Response {
    let email = norm_email(&req.email);
    // защита от брутфорса кода восстановления: 5 попыток на email в час
    if rate_limit(
        &st.recovery_guard,
        &format!("reset:{email}"),
        5,
        3600 * 1000,
    )
    .await
    {
        return err_json(
            StatusCode::TOO_MANY_REQUESTS,
            "too many recovery attempts, wait",
        );
    }
    let new_pass = match &req.new_pass {
        Some(p) if p.len() >= 8 => p.clone(),
        _ => {
            return err_json(
                StatusCode::BAD_REQUEST,
                "new password is shorter than 8 characters",
            )
        }
    };
    // Снапшот без удержания мьютекса: дальше сеть (kv) и Argon2 — под lock нельзя (H1-класс)
    struct ResetSnap {
        pw_hash: String,
        totp_enabled: bool,
        totp_secret: Option<String>,
        backup_codes: Vec<String>,
    }
    let snap = {
        let db = st.db.lock().await;
        match db.accounts.get(&email) {
            Some(a) => ResetSnap {
                pw_hash: a.pw_hash.clone(),
                totp_enabled: a.totp_enabled,
                totp_secret: a.totp_secret.clone(),
                backup_codes: a.backup_codes.clone(),
            },
            None => return err_json(StatusCode::BAD_REQUEST, "account not found"),
        }
    };
    // путь 1: если знаешь текущий пароль — просто меняем
    let old_ok = req
        .old_pass
        .as_ref()
        .map(|op| {
            PasswordHash::new(&snap.pw_hash)
                .map(|h| Argon2::default().verify_password(op.as_bytes(), &h).is_ok())
                .unwrap_or(false)
        })
        .unwrap_or(false);
    // путь 2: код восстановления из KV
    let code_key = format!("recovery:{email}");
    let code_valid = match req.code {
        Some(c) => {
            let stored = kv_get(&st.node, &code_key)
                .await
                .and_then(|s| serde_json::from_str::<Value>(&s).ok());
            match stored {
                Some(v) => {
                    let valid = v["code"].as_str() == Some(c.trim().to_ascii_uppercase().as_str())
                        && v["exp"].as_i64().unwrap_or(0) > proto::now_ms();
                    if valid {
                        kv_set(&st.node, &code_key, "").await;
                    }
                    valid
                }
                None => false,
            }
        }
        None => false,
    };
    if !old_ok && !code_valid {
        return err_json(
            StatusCode::FORBIDDEN,
            "invalid current password or recovery code",
        );
    }
    // H2: сброс через inbox-код не должен обходить 2FA — требуем второй фактор
    let mut burn_backup: Option<String> = None;
    if snap.totp_enabled {
        let now = proto::now_ms();
        let tcode = req.totp_code.as_deref().unwrap_or("");
        let totp_ok = snap
            .totp_secret
            .as_deref()
            .map(|s| infnode::totp::verify_totp(s, tcode, now))
            .unwrap_or(false);
        let backup_ok = {
            let h = sha256_hex(tcode);
            snap.backup_codes.iter().any(|c| c == &h)
        };
        if !totp_ok && !backup_ok {
            return err_json(
                StatusCode::FORBIDDEN,
                "two-factor code required for password reset",
            );
        }
        // бэкап-код одноразовый — сжигаем при записи (как в verify_2fa)
        if backup_ok && !totp_ok {
            burn_backup = Some(sha256_hex(tcode));
        }
    }
    let salt = argon2::password_hash::SaltString::generate(&mut rand::rngs::OsRng);
    let hash = Argon2::default()
        .hash_password(new_pass.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_else(|_| snap.pw_hash.clone());
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::BAD_REQUEST, "account not found"),
    };
    acc.pw_hash = hash;
    if let Some(h) = burn_backup {
        acc.backup_codes.retain(|c| c != &h);
    }
    // сброс через код (без старого пароля): enc-vault бэкап-кодов не перешифровать —
    // чистим, иначе Reveal отдавал бы мусор; коды перегенерируются в настройках 2FA
    if code_valid && !old_ok {
        acc.backup_codes_enc = Vec::new();
    }
    // сброс всех сессий после смены пароля
    acc.sessions.clear();
    acc.session_epoch = acc.session_epoch.wrapping_add(1);
    save_db(&st.db_path, &db).await;
    drop(db);
    ok_json(json!({ "ok": true, "message": "password updated" }))
}

async fn pricing() -> Response {
    // Цены регистрации web3-юзернеймов по числу букв (в нанотонах).
    // Совпадают с Registry-контрактом: 2-3 буквы дорого, 6+ — дёшево.
    ok_json(json!({
        "price_2_letters": 1_000_000_000,
        "price_3_letters": 1_000_000_000,
        "price_4_letters": 700_000_000,
        "price_5_letters": 500_000_000,
        "price_default": 100_000_000,
    }))
}

async fn username_check(
    State(st): State<WebState>,
    headers: HeaderMap,
    Path(user): Path<String>,
) -> Response {
    // Rate-limit по IP: защита от массового перечисления занятых имён (enumeration).
    // Не ломает регистрацию — юзеру хватает ~60 проверок за 10 минут.
    let ip = client_ip(&headers);
    if rate_limit(&st.reg_guard, &format!("chk:{ip}"), 60, 10 * 60 * 1000).await {
        return err_json(
            StatusCode::TOO_MANY_REQUESTS,
            "too many availability checks",
        );
    }
    // реальная проверка занятости: локальная часть email (username@infmail.org)
    let username = user.to_lowercase();
    let email = format!("{username}@{MAIL_DOMAIN}");
    let mut taken = false;
    {
        let db = st.db.lock().await;
        if db.accounts.contains_key(&email) {
            taken = true;
        } else {
            // алиасы: username может быть занят как алиас другого аккаунта
            for a in db.accounts.values() {
                if a.aliases
                    .iter()
                    .any(|al| format!("{al}@{MAIL_DOMAIN}") == email)
                {
                    taken = true;
                    break;
                }
            }
        }
    }
    ok_json(json!({ "available": !taken, "username": user }))
}

// ─────────────────────────────────────────────────────────────
// KEYS
// ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct KeysSaveReq {
    public_key: String,
    encrypted_private_key: String,
}

async fn keys_save(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<KeysSaveReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // публичный X25519 от браузера — base64; в реестре храним hex
    let pub_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return err_json(StatusCode::BAD_REQUEST, "invalid public_key"),
    };
    let x_hex = hex::encode(&pub_bytes);
    // реестр требует ed_pub — возьмём из зашифрованного ключа? нет; храним x_pub, ed_pub узнаем при подписи.
    // для CLI-совместимости сохраняем ed_pub, если прислали ранее; иначе 32 нулевых байта.
    let mut db = st.db.lock().await;
    let ed_hex = db
        .accounts
        .get(&email)
        .and_then(|a| a.ed_pub.clone())
        .unwrap_or_else(|| "00".repeat(32));
    if let Some(a) = db.accounts.get_mut(&email) {
        a.x_pub = Some(x_hex.clone());
        a.enc_priv = Some(req.encrypted_private_key.clone());
    }
    save_db(&st.db_path, &db).await;
    drop(db);
    registry_set(&st.node, &email, &x_hex, &ed_hex).await;
    ok_json(json!({ "ok": true }))
}

async fn keys_me(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let db = st.db.lock().await;
    match db.accounts.get(&email).and_then(|a| a.enc_priv.clone()) {
        Some(enc) => ok_json(json!({ "encrypted_private_key": enc })),
        None => err_json(StatusCode::NOT_FOUND, "keys not saved"),
    }
}

async fn keys_e2e_secret(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let db = st.db.lock().await;
    match db.accounts.get(&email).and_then(|a| a.e2e_secret.clone()) {
        Some(sec) => ok_json(json!({ "e2e_secret": sec })),
        None => err_json(
            StatusCode::NOT_FOUND,
            "e2e_secret not configured for this account",
        ),
    }
}

/// POST /api/v1/keys/e2e-secret/purge — удалить серверную копию e2e_secret
/// после миграции на локальный секрет (ревью: сервер хранил секрет старых
/// web3-аккаунтов и мог расшифровать их vault). Только свой аккаунт, только сессия.
/// Безвозвратно: убедитесь, что локальный vault расшифровывается, до вызова.
async fn keys_e2e_secret_purge(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    if acc.e2e_secret.is_none() {
        return ok_json(json!({ "ok": true, "already_purged": true }));
    }
    acc.e2e_secret = None;
    save_db(&st.db_path, &db).await;
    ok_json(json!({ "ok": true, "purged": true }))
}

async fn keys_get(State(st): State<WebState>, Path(email): Path<String>) -> Response {
    let email = norm_email(&email);
    let db = st.db.lock().await;
    let owner = resolve_db_email(&db, &email);
    let acc = owner.as_ref().and_then(|o| db.accounts.get(o)).cloned();
    drop(db);
    // ВАЖНО (безопасность): НЕ выводим ключ шифрования из wallet_pub — он публичен,
    // значит приватный x25519 был бы вычислим любым (сломал бы шифрование писем).
    // Расшифровка писем web3-аккаунта требует ПОДПИСИ кошелька (секрет), из которой
    // браузер выводит seed → приватный ключ. Бэкенд хранит только браузерный x_pub.
    let x_hex = match acc.as_ref().and_then(|a| a.x_pub.clone()) {
        Some(x) => x,
        None => match registry_get(&st.node, &email).await {
            Some(v) => v["x_pub"].as_str().unwrap_or("").to_string(),
            None => return err_json(StatusCode::NOT_FOUND, "user not found"),
        },
    };
    if x_hex.is_empty() {
        return err_json(StatusCode::NOT_FOUND, "user not found");
    }
    let pub_bytes = match hex::decode(&x_hex) {
        Ok(b) => b,
        Err(_) => return err_json(StatusCode::NOT_FOUND, "invalid key"),
    };
    let public_key = base64::engine::general_purpose::STANDARD.encode(&pub_bytes);
    ok_json(json!({ "public_key": public_key }))
}

// ─────────────────────────────────────────────────────────────
// MAIL
// ─────────────────────────────────────────────────────────────

fn mail_index_key(email: &str, folder: &str) -> String {
    match folder {
        "Sent" => format!("mail:{email}:sent-index"),
        "Drafts" => format!("mail:{email}:draft-index"),
        "Spam" => format!("mail:{email}:spam-index"),
        "Trash" => format!("mail:{email}:trash-index"),
        "Archive" => format!("mail:{email}:archive-index"),
        _ => format!("mail:{email}:index"),
    }
}

async fn mail_inbox(
    State(st): State<WebState>,
    headers: HeaderMap,
    query: axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let folder = query
        .get("folder")
        .cloned()
        .unwrap_or_else(|| "Inbox".into());
    // On-demand доставка входящих: при открытии Inbox/Spam сразу тянем свежие письма из MTA
    // (если последний синк >10с назад и синк этого аккаунта не идёт прямо сейчас).
    // Защита от двойного инжекта UNSEEN / двойного учёта квоты — общий sync_inflight
    // (см. фоновый цикл выше): одна аккаунтовая синхронизация в момент времени.
    if folder == "Inbox" || folder == "Spam" {
        let now = proto::now_ms();
        let fresh = st.sync_last.lock().await.get(&email).copied().unwrap_or(0);
        if now - fresh > 10_000 {
            let mut inflight = st.sync_inflight.lock().await;
            let already = inflight.contains(&email);
            inflight.insert(email.clone());
            drop(inflight);
            if !already {
                let (_injected, injected_bytes) = {
                    let db = st.db.lock().await;
                    let acc = db.accounts.get(&email).cloned();
                    drop(db);
                    match acc {
                        Some(a) => {
                            if let Some(sp) = a.smtp_pass.clone() {
                                let paid = a.paid_until_ms > now;
                                let quota = if paid {
                                    3 * 1024 * 1024 * 1024
                                } else {
                                    a.quota_limit.min(1024 * 1024 * 1024)
                                };
                                let free = quota.saturating_sub(a.bytes_used);
                                crate::inbound::inbound_sync_one(
                                    &st.node,
                                    &email,
                                    &sp,
                                    free,
                                    a.x_pub.clone(),
                                )
                                .await
                            } else {
                                (0, 0)
                            }
                        }
                        None => (0, 0),
                    }
                };
                // учёт квоты ровно один раз (фонЛОП этот аккаунт в этот момент пропустил)
                if injected_bytes > 0 {
                    let mut db = st.db.lock().await;
                    if let Some(a) = db.accounts.get_mut(&email) {
                        a.bytes_used = a.bytes_used.saturating_add(injected_bytes);
                    }
                    save_db(&st.db_path, &db).await;
                }
                let mut inflight = st.sync_inflight.lock().await;
                inflight.remove(&email);
                // синк отработал (даже если новых писем 0) — не гонять IMAP при каждом открытии
                st.sync_last
                    .lock()
                    .await
                    .insert(email.clone(), proto::now_ms());
            }
        }
    }
    // Три чтения индексов идут ПАРАЛЛЕЛЬНО: раньше они шли друг за другом и
    // каждое платило сетевой фолбэк при промахе — список грузился секундами.
    let folder_key = mail_index_key(&email, &folder);
    let read_key = format!("mail:{email}:read");
    let del_key = format!("mail:{email}:deleted");
    let (ids, read_vec, del_vec) = tokio::join!(
        index_list(&st.node, &folder_key),
        index_list(&st.node, &read_key),
        index_list(&st.node, &del_key),
    );
    // "my addresses": основной email + алиасы (письма на алиас показываются владельцу в Inbox)
    let my_addresses: HashSet<String> = {
        let db = st.db.lock().await;
        let mut set = HashSet::new();
        set.insert(email.clone());
        if let Some(a) = db.accounts.get(&email) {
            for al in &a.aliases {
                set.insert(format!("{al}@{MAIL_DOMAIN}"));
            }
        }
        drop(db);
        set
    };
    let read_set: HashSet<String> = read_vec.into_iter().collect();
    let del_set: HashSet<String> = del_vec.into_iter().collect();
    // blacklist отправителей (скрываем письма из чёрного списка, кроме Spam/Trash)
    let blacklist: HashSet<String> = if folder == "Inbox" || folder == "Archive" {
        kv_get_local(&st.node, &format!("blacklist:{email}"))
            .await
            .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
            .unwrap_or_default()
            .into_iter()
            .collect()
    } else {
        HashSet::new()
    };
    let search = query.get("q").cloned().unwrap_or_default().to_lowercase();
    let limit = query
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200)
        .min(1000);
    let offset = query
        .get("offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    // Параллельная загрузка блобов писем (каждый fetch_mail может ходить в сеть/DHT-fallback).
    // JoinSet + Semaphore: bounded concurrency (не блокирует, не превышает лимит одновременных).
    let sem = Arc::new(tokio::sync::Semaphore::new(32));
    let mut set: tokio::task::JoinSet<(String, Option<Value>)> = tokio::task::JoinSet::new();
    for id in ids {
        if del_set.contains(&id) {
            continue;
        }
        let node = st.node.clone();
        let name = format!("mail:{id}");
        let id_c = id.clone();
        // превью-индекс: если метаданные письма есть в KV (без сети) — берём их, полное тело не тянем.
        let meta_key = if folder == "Sent" || folder == "Drafts" {
            format!("mail:{email}:sentmeta:{id}")
        } else {
            format!("mail:{email}:meta:{id}")
        };
        let meta = st.node.get_local_kv(&meta_key).await;
        let folder_c = folder.clone();
        let email_c = email.clone();
        let id_c2 = id_c.clone();
        let permit = sem.clone().acquire_owned().await;
        set.spawn(async move {
            // Используем meta-кэш ТОЛЬКО если он полон (содержит body). Неполные meta-кэши
            // со старого формата (только sender/to/subject/preview) игнорируем и перечитываем
            // полный конверт — иначе письма отдаются с пустым телом/вложениями.
            let parsed_meta = meta
                .as_ref()
                .and_then(|m| serde_json::from_str::<Value>(m).ok());
            let mut env = match &parsed_meta {
                Some(p) if p["body"].as_str().is_some() => Some(p.clone()),
                _ => None,
            };
            if env.is_none() {
                // ТАЙМАУТ: тянуть тело из сети можно долго при несходившемся меше — список
                // писем не должен из-за этого виснуть. По истечении — показываем превью из meta.
                let blob = match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    node.fetch_mail(&name),
                )
                .await
                {
                    Ok(b) => b,
                    Err(_) => {
                        eprintln!(
                            "[web] WARN: fetch {name} timed out (5s) — listing without full body"
                        );
                        None
                    }
                };
                env = blob.and_then(|b| serde_json::from_slice::<Value>(&b).ok());
                if env.is_none() {
                    // фолбэк: хотя бы мета-превью, чтобы письмо не пропало из списка
                    env = parsed_meta.clone();
                }
                // добираем dek из блоба для s1-тел, если мета его не несёт (старые
                // меты без dek — иначе фронт видит шифротекст без ключа)
                let need_dek = env
                    .as_ref()
                    .and_then(|e| e["body"].as_str())
                    .map(|b| b.starts_with("s1."))
                    .unwrap_or(false)
                    && env
                        .as_ref()
                        .and_then(|e| e.get("dek"))
                        .map(|d| d.is_null())
                        .unwrap_or(true);
                if need_dek {
                    if let Ok(Some(b)) = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        node.fetch_mail(&name),
                    )
                    .await
                    {
                        if let Ok(v) = serde_json::from_slice::<Value>(&b) {
                            if let Some(e) = env.as_mut() {
                                e["dek"] = v.get("dek").cloned().unwrap_or(Value::Null);
                            }
                        }
                    }
                }
            }
            // миграция: если мета не было, но письмо прочитано — кэшируем мета (следующие разы быстро).
            // ВАЖНО: meta должна быть ПОЛНЫМ конвертом (включая body/html/attachments), иначе
            // список/чтение отдаёт пустые тело/вложения (баг: письма не читались).
            if let Some(e) = &env {
                if e["body"].as_str().is_some() {
                    let raw_body = e["body"].as_str().unwrap_or("");
                    let preview = if raw_body.starts_with("s1.") {
                        "🔒 Encrypted message".to_string()
                    } else {
                        raw_body.trim().chars().take(200).collect::<String>()
                    };
                    let meta_json = json!({
                        "sender": e["sender"], "to": e["to"], "at": e["at"],
                        "subject": e["subject"], "preview": preview,
                        "body": e["body"], "dek": e.get("dek").cloned().unwrap_or(Value::Null),
                        "html": e["html"], "attachments": e["attachments"],
                    })
                    .to_string();
                    let mk = if folder_c == "Sent" || folder_c == "Drafts" {
                        format!("mail:{email_c}:sentmeta:{id_c2}")
                    } else {
                        format!("mail:{email_c}:meta:{id_c2}")
                    };
                    node.kv_store_local(&mk, &meta_json).await;
                }
            }
            drop(permit);
            (id_c, env)
        });
    }
    let mut items: Vec<Value> = Vec::new();
    while let Some(res) = set.join_next().await {
        let (id, env) = match res {
            Ok(r) => r,
            Err(_) => continue,
        };
        let Some(env) = env else { continue };
        // владение: письмо должно быть адресовано юзеру (или его алиасу) или отправлено им.
        // (иначе злонамеренный пир может добавить чужой mail_id в свой индекс и прочитать тело)
        let is_to_me = env["to"]
            .as_str()
            .map(|t| my_addresses.contains(t))
            .unwrap_or(false);
        let is_from_me = env["sender"].as_str() == Some(email.as_str());
        if !is_to_me && !is_from_me {
            continue;
        }
        let body = env["body"].as_str().unwrap_or("").to_string();
        // dek из меты; у старых мет его нет — для s1-тел добираем из блоба,
        // иначе фронт не сможет расшифровать (наблюдалось: s1 есть, dek нет)
        let dek_val = env.get("dek").cloned().unwrap_or(Value::Null);
        let subject = env["subject"].as_str().unwrap_or("").to_string();
        let sender = env["sender"].as_str().unwrap_or("").to_string();
        let at = env["at"].as_i64().unwrap_or(0);
        // черный список: скрываем, если отправитель в blacklist (кроме Spam/Trash папок)
        if blacklist.contains(&sender.to_lowercase()) {
            continue;
        }
        // серверный поиск по отправителю/теме/телу
        if !search.is_empty() {
            let hay = format!("{sender} {subject} {body}").to_lowercase();
            if !hay.contains(&search) {
                continue;
            }
        }
        // Proton-модель: тело зашифровано — в списке показываем заглушку, не JSON-мусор.
        // s1. = конверт хранения (DEK), настоящее превью считает фронт после расшифровки.
        let preview =
            if body.starts_with("{\"proto\":\"infmail-box-v1\"") || body.starts_with("s1.") {
                "🔒 Encrypted message".to_string()
            } else if body.len() > 120 {
                let mut end = 120;
                while end > 0 && !body.is_char_boundary(end) {
                    end -= 1;
                }
                body[..end].to_string()
            } else {
                body.clone()
            };
        items.push(json!({
            "id": id,
            "sender": sender,
            "to": env["to"].as_str().unwrap_or(""),
            "subject": subject,
            "preview": preview,
            "body": body,
            "dek": dek_val,
            "html_body": env["html"].as_str().unwrap_or(""),
            "date": iso_date(at),
            "_at": at,
            "unread": !read_set.contains(&id),
            "attachments": env["attachments"].as_array().cloned().unwrap_or_default(),
        }));
    }
    // Детерминированный порядок: newest-first по времени (раньше случайный — JoinSet).
    items.sort_by(|a, b| {
        let at_a = a["_at"].as_i64().unwrap_or(0);
        let at_b = b["_at"].as_i64().unwrap_or(0);
        at_b.cmp(&at_a)
    });
    // пагинация: если limit явно задан — возвращаем {items, total}, иначе массив (обратная совместимость)
    if query.contains_key("limit") {
        let total = items.len();
        let page: Vec<Value> = items.into_iter().skip(offset).take(limit).collect();
        ok_json(json!({ "items": page, "total": total }))
    } else {
        ok_json(json!(items))
    }
}

/// Счётчики по папкам: { folder: { total, unread } } для баджей в sidebar.
/// Читает только индексы и read-set — быстрый, без загрузки тел писем.
async fn mail_counts(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // Параллельно собираем индексы всех папок + read/deleted (раньше 7 сетевых вызовов
    // шли ПОСЛЕДОВАТЕЛЬНО → mail/counts занимал ~1.3с при промахах в DHT-fallback).
    // Используем tokio::spawn с owned-ключами, чтобы избежать lifetime-проблем ссылок.
    let folders = ["Inbox", "Sent", "Drafts", "Spam", "Archive", "Trash"];
    let mut folder_tasks: Vec<tokio::task::JoinHandle<Vec<String>>> = Vec::with_capacity(6);
    for folder in folders.iter() {
        let node = st.node.clone();
        let key = mail_index_key(&email, folder);
        folder_tasks.push(tokio::spawn(async move { index_list(&node, &key).await }));
    }
    let read_node = st.node.clone();
    let read_key = format!("mail:{email}:read");
    let del_node = st.node.clone();
    let del_key = format!("mail:{email}:deleted");
    let read_task = tokio::spawn(async move { index_list(&read_node, &read_key).await });
    let del_task = tokio::spawn(async move { index_list(&del_node, &del_key).await });
    let read_vec = read_task.await.unwrap_or_default();
    let del_vec = del_task.await.unwrap_or_default();
    let read_set: HashSet<String> = read_vec.into_iter().collect();
    let del_set: HashSet<String> = del_vec.into_iter().collect();
    let mut out = serde_json::Map::new();
    for (idx, task) in folder_tasks.into_iter().enumerate() {
        let ids = task.await.unwrap_or_default();
        let folder = folders[idx];
        let total = ids.len();
        let unread = ids
            .iter()
            .filter(|id| !del_set.contains(*id) && !read_set.contains(*id))
            .count();
        out.insert(
            folder.to_string(),
            json!({ "total": total, "unread": unread }),
        );
    }
    ok_json(json!(out))
}

#[derive(Deserialize)]
struct MailAttachmentReq {
    name: String,
    data: String, // base64
    mime: Option<String>,
}

#[derive(Deserialize)]
struct MailSendReq {
    to: String,
    subject: String,
    body: String,
    #[allow(dead_code)] // GATE: forward-compat account flag persisted in accounts.json
    encrypted: Option<bool>,
    encrypted_payload: Option<Value>,
    attachments: Option<Vec<MailAttachmentReq>>,
}

/// Скачать вложение письма. Вложение хранится отдельным блобом mail:{id}:att:{idx}
/// (манифест m:mail:{id}:att:{idx}), метаданные — в конверте письма.
async fn mail_attachment(
    State(st): State<WebState>,
    headers: HeaderMap,
    Path((id, idx)): Path<(String, usize)>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // id письма — hex-хэш blake3 (64 символа); защита от мусора в URL
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return err_json(StatusCode::BAD_REQUEST, "invalid mail id");
    }
    let Some(blob) = fetch_mail_to(&st.node, &format!("mail:{id}"), 8000).await else {
        return err_json(StatusCode::NOT_FOUND, "mail not found");
    };
    let Ok(env) = serde_json::from_slice::<Value>(&blob) else {
        return err_json(StatusCode::NOT_FOUND, "mail not found");
    };
    // доступ: только получатель или отправитель
    let is_owner = env["to"].as_str() == Some(email.as_str())
        || env["sender"].as_str() == Some(email.as_str());
    if !is_owner {
        return err_json(StatusCode::FORBIDDEN, "no access to this email");
    }
    let atts = env["attachments"].as_array();
    let meta = match atts.and_then(|a| a.get(idx)) {
        Some(m) => m,
        None => return err_json(StatusCode::NOT_FOUND, "attachment not found"),
    };
    let Some(data) = st
        .node
        .fetch_blob("mail", &format!("mail:{id}:att:{idx}"))
        .await
    else {
        return err_json(StatusCode::NOT_FOUND, "attachment not found");
    };
    ok_json(json!({
        "name": meta["name"].as_str().unwrap_or("attachment"),
        "mime": meta["mime"].as_str().unwrap_or("application/octet-stream"),
        "size": data.len(),
        "data": base64::engine::general_purpose::STANDARD.encode(&data),
    }))
}

/// Скопировать вложение письма в файловое хранилище пользователя (кнопка «Сохранить в Files»).
/// Вложение остаётся в письме; в Files попадает копия. Проверяется файловая квота.
async fn mail_attachment_save(
    State(st): State<WebState>,
    headers: HeaderMap,
    Path((id, idx)): Path<(String, usize)>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return err_json(StatusCode::BAD_REQUEST, "invalid mail id");
    }
    let Some(blob) = fetch_mail_to(&st.node, &format!("mail:{id}"), 8000).await else {
        return err_json(StatusCode::NOT_FOUND, "mail not found");
    };
    let Ok(env) = serde_json::from_slice::<Value>(&blob) else {
        return err_json(StatusCode::NOT_FOUND, "mail not found");
    };
    // доступ: получатель или отправитель (как при скачивании вложения)
    let is_owner = env["to"].as_str() == Some(email.as_str())
        || env["sender"].as_str() == Some(email.as_str());
    if !is_owner {
        return err_json(StatusCode::FORBIDDEN, "no access to this email");
    }
    let atts = env["attachments"].as_array();
    let meta = match atts.and_then(|a| a.get(idx)) {
        Some(m) => m,
        None => return err_json(StatusCode::NOT_FOUND, "attachment not found"),
    };
    let Some(data) = st
        .node
        .fetch_blob("mail", &format!("mail:{id}:att:{idx}"))
        .await
    else {
        return err_json(StatusCode::NOT_FOUND, "attachment not found");
    };
    if data.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "attachment is empty");
    }
    // безопасное имя для файлового хранилища (ascii_graphic, без путей)
    let raw = meta["name"].as_str().unwrap_or("attachment");
    let mut name = crate::inbound::sanitize_filename(raw)
        .unwrap_or_else(|| format!("attachment_{idx}"))
        .chars()
        .filter(|c| c.is_ascii_graphic() && *c != '/' && *c != '\\')
        .collect::<String>();
    if name.is_empty() {
        name = format!("attachment_{idx}");
    }
    // защита от XSS через активные типы (html/svg/xml): если контент похож на скрипт —
    // отклоняем сохранение в файловое хранилище (риск открытия из Files-предпросмотра)
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if matches!(ext.as_str(), "html" | "htm" | "svg" | "xml" | "xhtml") {
        let head = &data[..data.len().min(2048)];
        let head_lower: Vec<u8> = head.iter().map(|b| b.to_ascii_lowercase()).collect();
        let suspicious = head_lower.windows(8).any(|w| w == b"<script>")
            || head_lower.windows(10).any(|w| w == b"javascript:")
            || head_lower.windows(8).any(|w| w == b"onerror=")
            || head_lower.windows(7).any(|w| w == b"<iframe");
        if suspicious {
            return err_json(
                StatusCode::UNPROCESSABLE_ENTITY,
                "saving to Files: active content (script/html) is forbidden",
            );
        }
    }
    // квота файлов + дедуп имени
    let ikey = file_index_key(&email);
    let mut list = files_index(&st.node, &email).await;
    {
        let mut db = st.db.lock().await;
        let acc = match db.accounts.get_mut(&email) {
            Some(a) => a,
            None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
        };
        let fq = effective_file_quota(acc);
        if fq == 0 {
            return err_json(
                StatusCode::PAYMENT_REQUIRED,
                "file storage is available by subscription",
            );
        }
        let new_total = acc.files_used + data.len() as u64;
        if new_total > fq {
            return err_json(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("file storage limit: {} bytes", fq),
            );
        }
        acc.files_used = new_total;
        save_db(&st.db_path, &db).await;
    }
    // если имя занято — добавляем суффикс (n)
    let mut final_name = name.clone();
    let mut n = 1usize;
    while list
        .iter()
        .any(|e| e["name"].as_str() == Some(final_name.as_str()))
    {
        let (stem, ext) = match name.rsplit_once('.') {
            Some((s, e)) if !e.is_empty() => (s.to_string(), format!(".{e}")),
            _ => (name.clone(), String::new()),
        };
        final_name = format!("{stem} ({n}){ext}");
        n += 1;
        if n > 1000 {
            return err_json(StatusCode::CONFLICT, "could not pick file name");
        }
    }
    let blob_name = file_blob_key(&email, &final_name);
    // Owner-sealed: files are sealed to the account-scoped owner key, so
    // storage/replica nodes cannot read the plaintext. The account secret is
    // required to sign the manifest and is never derived from the node key.
    let Some(secret) = account_files_secret(&st, &email).await else {
        return err_json(StatusCode::UNAUTHORIZED, "account not found");
    };
    let report = st
        .node
        .store_blob_boxed(
            "files",
            &blob_name,
            &data,
            Some(&files_owner_ek(&secret, &email)),
            Some(&files_owner_key(&secret, &email)),
        )
        .await;
    if report.chunks == 0 || report.replicas == 0 {
        return err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "file seal failed (chunks={}, replicas={})",
                report.chunks, report.replicas
            ),
        );
    }
    list.push(json!({ "name": final_name, "size": data.len(), "at": proto::now_ms() }));
    kv_set(
        &st.node,
        &ikey,
        &serde_json::to_string(&list).unwrap_or("[]".into()),
    )
    .await;
    ok_json(json!({
        "ok": true,
        "name": final_name,
        "size": data.len(),
        "from_mail": true,
    }))
}

async fn mail_send(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<MailSendReq>,
) -> Response {
    let from = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let to = norm_email(&req.to);
    let is_internal = to.ends_with(&format!("@{MAIL_DOMAIN}"));
    // анти-спам: лимит отправки на аккаунт (и внутренние, и внешние письма)
    if rate_limit(&st.relay_guard, &format!("send:{from}"), 200, 3600 * 1000).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "hourly send limit");
    }
    if !is_internal {
        // внешний адрес: базовая проверка синтаксиса, уходит через SMTP-мост валидатора
        if !to.contains('@') || to.len() > 254 {
            return err_json(StatusCode::BAD_REQUEST, "invalid recipient address");
        }
        // анти-спам: лимит размера и частоты внешней отправки на аккаунт
        if req.body.len() > 2 * 1024 * 1024 {
            return err_json(StatusCode::PAYLOAD_TOO_LARGE, "external email exceeds 2 MB");
        }
        // АНТИ-СПАМ БЕЗ ОПЛАТЫ (репутация, а не деньги): свежий аккаунт не может
        // веерно рассылать наружу. Первые 24 часа — 5 внешних писем, дальше обычный
        // лимит. Письма остаются бесплатными; ограничивается только веерная рассылка
        // с только что созданных адресов (типичный сценарий спам-фермы).
        let age_ms = {
            let db = st.db.lock().await;
            db.accounts
                .get(&from)
                .map(|a| proto::now_ms() - a.created_ms)
                .unwrap_or(0)
        };
        let young = age_ms < 24 * 3600 * 1000;
        let ext_limit = if young { 5 } else { 200 };
        if rate_limit(&st.relay_guard, &from, ext_limit, 24 * 3600 * 1000).await {
            return err_json(
                StatusCode::TOO_MANY_REQUESTS,
                if young {
                    "new account: external email limit is 5/day for the first 24 hours"
                } else {
                    "daily external email limit"
                },
            );
        }
        return smtp_relay_external(&st, &from, &to, &req.subject, &req.body, req.attachments)
            .await;
    }
    if !valid_email(&to) {
        return err_json(StatusCode::BAD_REQUEST, "invalid recipient address");
    }
    // получатель: аккаунт или алиас (резолвим в основной ящик)
    let (owner, is_account) = {
        let db = st.db.lock().await;
        let o = resolve_db_email(&db, &to);
        let is_acc = db.accounts.contains_key(&to);
        (o, is_acc)
    };
    let owner_email = owner.clone().unwrap_or_else(|| to.clone());
    if !is_account && owner.is_none() && registry_get(&st.node, &to).await.is_none() {
        return err_json(
            StatusCode::BAD_REQUEST,
            format!("recipient {to} is not registered"),
        );
    }
    // Как в Proton: внутри сети без ключей не отправляем. У зарегистрированного
    // получателя x_pub обязан быть (публикуется при инициализации ключей на входе);
    // отсутствие = получатель ни разу не заходил. Тихий plaintext-фолбэк запрещён:
    // фронт такое больше не шлёт, старых клиентов режем здесь.
    let (sender_pub, recip_pub) = if to.ends_with(&format!("@{MAIL_DOMAIN}")) {
        let (s, r) = tokio::join!(registry_get(&st.node, &from), registry_get(&st.node, &to));
        (
            s.and_then(|v| v["x_pub"].as_str().map(String::from)),
            r.and_then(|v| v["x_pub"].as_str().map(String::from)),
        )
    } else {
        (None, None)
    };
    if to.ends_with(&format!("@{MAIL_DOMAIN}")) {
        if sender_pub.is_none() {
            return err_json(
                StatusCode::CONFLICT,
                "sender keys not initialized — log in once to create encryption keys",
            );
        }
        if recip_pub.is_none() {
            return err_json(
                StatusCode::CONFLICT,
                format!("recipient {to} has no encryption keys yet — they must log in once"),
            );
        }
    }
    // тело: если прислали encrypted_payload — храним его JSON как есть (E2E-шифротекст)
    let body = match req.encrypted_payload {
        Some(p) => p.to_string(),
        None => req.body,
    };
    let at = proto::now_ms();
    let id = hex::encode(
        blake3::hash(format!("{from}:{to}:{at}:{}", rand::random::<u64>()).as_bytes()).as_bytes(),
    );
    // вложения: валидация, лимиты, учёт в квоте. Данные держим только до записи блобов.
    let max_att = crate::inbound::max_attach_total();
    let mut att_meta: Vec<Value> = Vec::new();
    let mut att_blobs: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(atts) = req.attachments {
        let mut total = 0usize;
        if atts.len() > crate::inbound::MAX_ATTACH_COUNT {
            return err_json(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "too many attachments (max {})",
                    crate::inbound::MAX_ATTACH_COUNT
                ),
            );
        }
        for (i, a) in atts.into_iter().enumerate() {
            let name = crate::inbound::sanitize_filename(&a.name)
                .unwrap_or_else(|| format!("attachment_{i}"));
            let data = match base64::engine::general_purpose::STANDARD.decode(&a.data) {
                Ok(d) => d,
                Err(_) => return err_json(StatusCode::BAD_REQUEST, "attachment: invalid base64"),
            };
            if data.is_empty() {
                continue;
            }
            if data.len() > max_att.saturating_sub(total) {
                return err_json(StatusCode::PAYLOAD_TOO_LARGE, "attachments too large");
            }
            total += data.len();
            let mime = a
                .mime
                .map(|m| crate::inbound::sanitize_mime(&m))
                .unwrap_or_else(|| "application/octet-stream".into());
            att_meta.push(json!({ "name": name, "mime": mime, "size": data.len() }));
            att_blobs.push((format!("mail:{id}:att:{}", att_meta.len() - 1), data));
        }
    }
    // Конверт хранения (zero-trust): тело и вложения шифруем DEK'ом, DEK — box'ами
    // на ключи обеих сторон (они обязательны выше). Мета (sender/to/subject/имена)
    // остаётся открытой для индексации; превью в мету НЕ кладём (см. ниже).
    let pubs: Vec<(String, String)> = vec![
        (from.clone(), sender_pub.clone().unwrap_or_default()),
        (to.clone(), recip_pub.clone().unwrap_or_default()),
    ];
    let (dek, dek_boxes) = match storage_box_dek(&pubs) {
        Some(v) => v,
        None => return err_json(StatusCode::BAD_GATEWAY, "storage encryption failed"),
    };
    let body_sealed = storage_seal(&dek, body.as_bytes());
    let mut att_blobs_sealed: Vec<(String, Vec<u8>)> = Vec::with_capacity(att_blobs.len());
    for (aname, adata) in att_blobs {
        att_blobs_sealed.push((aname, storage_seal(&dek, &adata).into_bytes()));
    }
    let att_blobs = att_blobs_sealed;
    let blob = json!({
        "sender": from, "to": to, "at": at, "subject": req.subject, "body": body_sealed,
        "dek": { "boxes": dek_boxes },
        "attachments": att_meta,
    })
    .to_string()
    .into_bytes();
    let size = blob.len() as u64 + att_blobs.iter().map(|(_, d)| d.len() as u64).sum::<u64>();

    // квота: письмо занимает место и в ящике отправителя (Sent), и получателя (Inbox).
    // Сначала проверяем ОБЕ квоты, затем применяем инкременты — чтобы ошибка квоты
    // получателя не списала квоту отправителя (мутация в памяти до save_db).
    {
        let mut db = st.db.lock().await;
        if let Some(a) = db.accounts.get(&from) {
            if a.bytes_used + size > effective_mail_quota(a) {
                return err_json(StatusCode::PAYLOAD_TOO_LARGE, "storage quota exceeded");
            }
        }
        if owner_email != from {
            if let Some(a) = db.accounts.get(&owner_email) {
                if a.bytes_used + size > effective_mail_quota(a) {
                    return err_json(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "recipient storage quota exceeded",
                    );
                }
            }
        }
        if let Some(a) = db.accounts.get_mut(&from) {
            a.bytes_used += size;
        }
        if owner_email != from {
            if let Some(a) = db.accounts.get_mut(&owner_email) {
                a.bytes_used += size;
            }
        }
        save_db(&st.db_path, &db).await;
    }

    let name = format!("mail:{id}");
    // Опционально: Erasure Coding вместо полных реплик (INFNODE_EC="k,n", напр. 3,5).
    let ec = std::env::var("INFNODE_EC").ok().and_then(|v| {
        let mut it = v.split(',');
        let k = it.next()?.trim().parse::<usize>().ok()?;
        let n = it.next()?.trim().parse::<usize>().ok()?;
        if k > 0 && n > k {
            Some((k, n))
        } else {
            None
        }
    });
    let stored = match ec {
        Some((k, n)) => st.node.store_mail_ec(&name, &blob, None, k, n).await,
        None => st.node.store_mail(&name, &blob).await,
    };
    // A refusal is specific (e.g. an unusable owner key on a future caller),
    // and must not be reported as a generic storage failure.
    let (stored, store_err) = match stored {
        Ok(n) => (n, None),
        Err(e) => (0, Some(e.to_string())),
    };
    // если письмо не записалось нигде (0 чанков) — откатываем квоту (не списывать зря)
    if stored == 0 {
        let mut db = st.db.lock().await;
        if let Some(a) = db.accounts.get_mut(&from) {
            a.bytes_used = a.bytes_used.saturating_sub(size);
        }
        if owner_email != from {
            if let Some(a) = db.accounts.get_mut(&owner_email) {
                a.bytes_used = a.bytes_used.saturating_sub(size);
            }
        }
        save_db(&st.db_path, &db).await;
        let msg = match store_err {
            Some(e) => format!("failed to save email (storage): {e}"),
            None => "failed to save email (storage)".to_string(),
        };
        return err_json(StatusCode::BAD_GATEWAY, &msg);
    }
    // вложения пишем после конверта (id вложений детерминированы от id письма)
    for (aname, adata) in att_blobs {
        st.node.store_blob("mail", &aname, &adata).await;
    }
    let _guard = st.index_lock.lock().await;
    index_add(&st.node, &mail_index_key(&owner_email, "Inbox"), &id).await;
    index_add(&st.node, &mail_index_key(&from, "Sent"), &id).await;
    drop(_guard);
    // ПРЕВЬЮ-ИНДЕКС: тело зашифровано — серверное превью невозможно (раньше сюда
    // утекали 200 символов plaintext). Настоящее превью считает фронт локально после
    // расшифровки; здесь только заглушка.
    let preview = "🔒 Encrypted message".to_string();
    let meta = json!({
        "sender": from, "to": to, "at": at, "subject": req.subject, "preview": preview,
    });
    st.node
        .kv_store_local(&format!("mail:{owner_email}:meta:{id}"), &meta.to_string())
        .await;
    st.node
        .kv_store_local(&format!("mail:{from}:sentmeta:{id}"), &meta.to_string())
        .await;

    // best-effort pubsub-уведомление (в фоне, не блокирует ответ)
    let node = st.node.clone();
    let to_notify = to.clone();
    let id_notify = id.clone();
    tokio::spawn(async move {
        let peers: Vec<String> = node.cfg.peers.iter().map(|p| p.name.clone()).collect();
        for name in peers {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                if let Ok(pid) = node.resolve(&name) {
                    let _ = node
                        .request_to(
                            pid,
                            "pubsub.publish",
                            json!({ "topic": format!("mail:{to_notify}"), "data": id_notify })
                                .to_string()
                                .into_bytes(),
                        )
                        .await;
                }
            })
            .await;
        }
    });
    ok_json(json!({ "ok": true, "id": id, "stored": stored }))
}

/// Приветственное письмо в ящик нового пользователя (отправляется при создании почты).
/// Кладём его так же, как обычное письмо: тело + локальная мета + индекс Inbox,
/// поэтому оно сразу видно в списке и не зависит от сети.
async fn send_welcome_mail(st: &WebState, email: &str) {
    let at = proto::now_ms();
    let id = hex::encode(blake3::hash(format!("welcome:{email}:{at}").as_bytes()).as_bytes());
    let subject = "Welcome to InfMail";
    let body = format!(
        "Welcome to InfMail!\n\n\
Your mailbox {email} is ready.\n\n\
What you can do right now:\n\
• Write a letter — the Compose button is in the left panel.\n\
• Keep drafts — saved drafts stay in Drafts and can be continued any time.\n\
• Block a sender — open any letter and press Block; the list is in Settings → Blocked senders.\n\
• Turn on two-factor authentication — Settings → Two-Factor Auth.\n\n\
Your mail is encrypted on your device before it leaves it, and the network stores\n\
only encrypted chunks spread across independent nodes.\n\n\
— The InfMail team"
    );
    let blob = json!({
        "sender": "team@infmail.org",
        "to": email,
        "at": at,
        "subject": subject,
        "body": body,
    })
    .to_string()
    .into_bytes();
    let name = format!("mail:{id}");
    let _ = st.node.store_mail(&name, &blob).await;
    let meta = json!({
        "sender": "team@infmail.org",
        "to": email,
        "at": at,
        "subject": subject,
        "preview": body.chars().take(200).collect::<String>(),
        "body": body,
        "attachments": [],
    });
    st.node
        .kv_store_local(&format!("mail:{email}:sentmeta:{id}"), &meta.to_string())
        .await;
    let _guard = st.index_lock.lock().await;
    index_add(&st.node, &mail_index_key(email, "Inbox"), &id).await;
    drop(_guard);
    eprintln!("[web] welcome mail for {email}");
}

async fn mail_draft(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<MailSendReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let at = proto::now_ms();
    let id = hex::encode(
        blake3::hash(format!("draft:{email}:{at}:{}", rand::random::<u64>()).as_bytes()).as_bytes(),
    );
    // получатель — как в send: без мусора в to (раньше хранилось как есть)
    let to = norm_email(&req.to);
    if !to.is_empty() && !valid_email(&to) {
        return err_json(StatusCode::BAD_REQUEST, "invalid recipient email");
    }
    // лимит на число черновиков (защита от DoS: без него юзер/злоумышленник с валидной
    // сессией может создать неограниченное число черновиков и заполнить хранилище).
    const MAX_DRAFTS: usize = 500;
    let draft_count = index_list(&st.node, &mail_index_key(&email, "Drafts"))
        .await
        .len();
    if draft_count >= MAX_DRAFTS {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "draft limit reached");
    }
    let to_clean = if to.is_empty() {
        req.to.clone()
    } else {
        to.clone()
    };
    // черновик — тоже в конверт (box на владельца), если ключи есть
    let owner_pub = registry_get(&st.node, &email)
        .await
        .and_then(|v| v["x_pub"].as_str().map(String::from));
    let (body_stored, dek_val) = match owner_pub {
        Some(pub_hex) => match storage_box_dek(&[(email.clone(), pub_hex)]) {
            Some((dek, boxes)) => (
                storage_seal(&dek, req.body.as_bytes()),
                json!({ "boxes": boxes }),
            ),
            None => (req.body.clone(), Value::Null),
        },
        None => (req.body.clone(), Value::Null),
    };
    let blob = json!({ "sender": email, "to": to_clean, "at": at, "subject": req.subject, "body": body_stored, "dek": dek_val })
        .to_string()
        .into_bytes();
    let name = format!("mail:{id}");
    let _ = st.node.store_mail(&name, &blob).await;
    // локальная meta: список Drafts не должен зависеть от сети (иначе при
    // несходившемся меше черновик временно не виден — fetch по таймауту).
    let preview = if body_stored.starts_with("s1.") {
        "🔒 Encrypted message".to_string()
    } else {
        req.body.trim().chars().take(200).collect::<String>()
    };
    let meta = json!({
        "sender": email, "to": req.to, "at": at, "subject": req.subject,
        "preview": preview, "body": body_stored, "dek": dek_val, "attachments": [],
    });
    st.node
        .kv_store_local(&format!("mail:{email}:sentmeta:{id}"), &meta.to_string())
        .await;
    let _guard = st.index_lock.lock().await;
    index_add(&st.node, &mail_index_key(&email, "Drafts"), &id).await;
    drop(_guard);
    ok_json(json!({ "ok": true, "id": id }))
}

#[derive(Deserialize)]
struct MailActionReq {
    mail_id: String,
    action: String,
}

async fn mail_action(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<MailActionReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // владение письмом: все действия (read/spam/trash/restore/archive) должны работать только
    // с письмами юзера. Иначе злонамеренный пир добавит чужой mail_id в свой индекс
    // (через restore/unarchive) и прочитает тело в mail_inbox.
    {
        // Владение письмом. Раньше проверка опиралась ТОЛЬКО на поля to/sender в записи,
        // поэтому у E2E-шифрованных писем (в записи нет этих полей — там шифроконверт)
        // ЛЮБОЕ действие получало 403 «no access»: письмо нельзя было пометить
        // прочитанным, убрать в спам/архив/корзину. Наблюдалось вручную в браузере:
        // клик «Block» давал 200 на blacklist, а затем 403 на /mail/action и
        // необработанную ошибку страницы.
        // БЫСТРЫЙ ПУТЬ СНАЧАЛА: свои индексы читаются локально за миллисекунды.
        // Раньше сначала шёл fetch блоба с таймаутом 20с — пометка «прочитано»
        // висела по 20 секунд на каждое открытие письма (замерено: 20.02с),
        // хотя владение подтверждалось индексами. Теперь сеть — только запасной путь.
        let mut found = false;
        for f in ["Inbox", "Sent", "Drafts", "Spam", "Archive", "Trash"] {
            let ids = index_list(&st.node, &mail_index_key(&email, f)).await;
            if ids.iter().any(|x| x == &req.mail_id) {
                found = true;
                break;
            }
        }
        let owned = if found {
            true
        } else {
            // В индексах нет — проверяем по содержимому (короткий таймаут).
            let blob = fetch_mail_to(&st.node, &format!("mail:{}", req.mail_id), 3000).await;
            blob.as_ref()
                .and_then(|b| serde_json::from_slice::<Value>(b).ok())
                .map(|v| {
                    v["to"].as_str() == Some(email.as_str())
                        || v["sender"].as_str() == Some(email.as_str())
                })
                .unwrap_or(false)
        };
        if !owned {
            return err_json(StatusCode::FORBIDDEN, "no access to this email");
        }
    }
    let read_key = format!("mail:{email}:read");
    match req.action.as_str() {
        "read" => {
            let mut set = index_list(&st.node, &read_key).await;
            if !set.iter().any(|x| x == &req.mail_id) {
                set.push(req.mail_id.clone());
            }
            kv_set(&st.node, &read_key, &serde_json::to_string(&set).unwrap()).await;
        }
        "unread" => {
            let mut set = index_list(&st.node, &read_key).await;
            set.retain(|x| x != &req.mail_id);
            kv_set(&st.node, &read_key, &serde_json::to_string(&set).unwrap()).await;
        }
        "spam" => {
            // переместить из Inbox в Spam (реальный спам-индекс)
            let index_key = format!("mail:{email}:index");
            let spam_key = format!("mail:{email}:spam-index");
            index_remove(&st.node, &index_key, &req.mail_id).await;
            index_add(&st.node, &spam_key, &req.mail_id).await;
        }
        "unspam" => {
            // вернуть из Spam в Inbox
            let index_key = format!("mail:{email}:index");
            let spam_key = format!("mail:{email}:spam-index");
            index_remove(&st.node, &spam_key, &req.mail_id).await;
            index_add(&st.node, &index_key, &req.mail_id).await;
        }
        "trash" => {
            // переместить письмо в Корзину (Trash). Убираем из Inbox/Spam/Drafts/Archive.
            let inbox_key = format!("mail:{email}:index");
            let trash_key = format!("mail:{email}:trash-index");
            for key in [
                &inbox_key,
                &format!("mail:{email}:spam-index"),
                &format!("mail:{email}:draft-index"),
                &format!("mail:{email}:archive-index"),
            ] {
                index_remove(&st.node, key, &req.mail_id).await;
            }
            index_add(&st.node, &trash_key, &req.mail_id).await;
        }
        "restore" => {
            // вернуть из Корзины обратно в Inbox
            let trash_key = format!("mail:{email}:trash-index");
            let inbox_key = format!("mail:{email}:index");
            index_remove(&st.node, &trash_key, &req.mail_id).await;
            index_add(&st.node, &inbox_key, &req.mail_id).await;
        }
        "archive" => {
            // переместить в Архив (из Inbox/Spam/Trash)
            let archive_key = format!("mail:{email}:archive-index");
            for key in [
                &format!("mail:{email}:index"),
                &format!("mail:{email}:spam-index"),
                &format!("mail:{email}:trash-index"),
            ] {
                index_remove(&st.node, key, &req.mail_id).await;
            }
            index_add(&st.node, &archive_key, &req.mail_id).await;
        }
        "unarchive" => {
            // вернуть из Архива в Inbox
            let archive_key = format!("mail:{email}:archive-index");
            let inbox_key = format!("mail:{email}:index");
            index_remove(&st.node, &archive_key, &req.mail_id).await;
            index_add(&st.node, &inbox_key, &req.mail_id).await;
        }
        "delete" => {
            // безвозвратное удаление (из Корзины или любой папки): убираем из всех индексов,
            // возвращаем квоту. Корзина как промежуточный шаг — только через "trash".
            let index_keys = [
                format!("mail:{email}:index"),
                format!("mail:{email}:sent-index"),
                format!("mail:{email}:draft-index"),
                format!("mail:{email}:spam-index"),
                format!("mail:{email}:trash-index"),
                format!("mail:{email}:archive-index"),
            ];
            // идемпотентность: если письмо нигде не индексировано — уже удалено, квоту не списываем повторно
            let mut present_before = false;
            for key in &index_keys {
                if index_list(&st.node, key)
                    .await
                    .iter()
                    .any(|x| x == &req.mail_id)
                {
                    present_before = true;
                    break;
                }
            }
            if !present_before {
                return ok_json(json!({ "ok": true, "already_deleted": true }));
            }
            // Проверка владения ДО любой мутации (раньше индексы чистились до
            // проверки — чужая/битая ссылка давала 403 после порчи своих индексов).
            // Конверт собирает сервер, поэтому to/sender есть и у E2E-писем.
            let blob = fetch_mail_to(&st.node, &format!("mail:{}", req.mail_id), 8000).await;
            let owned = blob
                .as_ref()
                .and_then(|b| serde_json::from_slice::<Value>(b).ok())
                .map(|v| {
                    v["to"].as_str() == Some(email.as_str())
                        || v["sender"].as_str() == Some(email.as_str())
                })
                .unwrap_or(false);
            if !owned && blob.is_some() {
                return err_json(StatusCode::FORBIDDEN, "no access to this email");
            }
            // Висячая ссылка (индекс есть, блоба уже нет — например, второй участник
            // удалил общую копию): чистим свои индексы, квоту не трогаем (размер
            // неизвестен), это cleanup, а не ошибка.
            for key in &index_keys {
                index_remove(&st.node, key, &req.mail_id).await;
            }
            if blob.is_none() {
                return ok_json(json!({ "ok": true, "cleaned_dangling": true }));
            }
            let size = blob.as_ref().map(|b| b.len() as u64).unwrap_or(0);
            let att_size: u64 = blob
                .as_ref()
                .and_then(|b| serde_json::from_slice::<Value>(b).ok())
                .map(|v| {
                    v["attachments"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .map(|x| x["size"].as_u64().unwrap_or(0))
                                .sum::<u64>()
                        })
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            let total = size.saturating_add(att_size);
            if total > 0 {
                let mut db = st.db.lock().await;
                if let Some(a) = db.accounts.get_mut(&email) {
                    a.bytes_used = a.bytes_used.saturating_sub(total);
                }
                save_db(&st.db_path, &db).await;
            }
            // физическое удаление блобов — ТОЛЬКО если больше ничей локальный индекс
            // на них не ссылается (письмо одно на двоих: Sent у А + Inbox у Б; раньше
            // удаление у А убивало копию у Б и вешало ей висячую ссылку без возврата квоты).
            let others: Vec<String> = {
                let db = st.db.lock().await;
                db.accounts
                    .keys()
                    .filter(|e| *e != &email)
                    .cloned()
                    .collect()
            };
            let mut shared = false;
            for o in &others {
                for k in [
                    format!("mail:{o}:index"),
                    format!("mail:{o}:sent-index"),
                    format!("mail:{o}:spam-index"),
                    format!("mail:{o}:trash-index"),
                    format!("mail:{o}:archive-index"),
                ] {
                    if index_list(&st.node, &k)
                        .await
                        .iter()
                        .any(|x| x == &req.mail_id)
                    {
                        shared = true;
                        break;
                    }
                }
                if shared {
                    break;
                }
            }
            // физическое удаление блобов письма и вложений (чтобы диск не рос бесконечно)
            if shared {
                return ok_json(json!({ "ok": true, "kept_shared_copy": true }));
            }
            st.node
                .delete_blob("mail", &format!("mail:{}", req.mail_id))
                .await;
            let att_count: usize = blob
                .as_ref()
                .and_then(|b| serde_json::from_slice::<Value>(b).ok())
                .and_then(|v| v["attachments"].as_array().map(|a| a.len()))
                .unwrap_or(0)
                .min(200);
            for i in 0..att_count {
                st.node
                    .delete_blob("mail", &format!("mail:{}:att:{}", req.mail_id, i))
                    .await;
            }
        }
        other => return err_json(StatusCode::BAD_REQUEST, format!("unknown action {other}")),
    }
    ok_json(json!({ "ok": true }))
}

async fn mail_blacklist(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let sender = req["sender"].as_str().unwrap_or("").trim().to_lowercase();
    if sender.is_empty() || !sender.contains('@') || sender.len() > 254 {
        return err_json(StatusCode::BAD_REQUEST, "invalid sender");
    }
    let key = format!("blacklist:{email}");
    let mut list: Vec<String> = kv_get(&st.node, &key)
        .await
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default();
    if !list.iter().any(|s| s == &sender) {
        list.push(sender.clone());
        kv_set(
            &st.node,
            &key,
            &serde_json::to_string(&list).unwrap_or("[]".into()),
        )
        .await;
    }
    ok_json(json!({ "ok": true, "blacklisted": list }))
}

/// Список заблокированных отправителей (для настроек: показать + разблокировать).
async fn mail_blacklist_list(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let list: Vec<String> = kv_get(&st.node, &format!("blacklist:{email}"))
        .await
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default();
    ok_json(json!({ "ok": true, "blacklisted": list }))
}

async fn mail_unblock(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let sender = req["sender"].as_str().unwrap_or("").trim().to_lowercase();
    let key = format!("blacklist:{email}");
    let mut list: Vec<String> = kv_get(&st.node, &key)
        .await
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default();
    list.retain(|s| s != &sender);
    kv_set(
        &st.node,
        &key,
        &serde_json::to_string(&list).unwrap_or("[]".into()),
    )
    .await;
    ok_json(json!({ "ok": true, "blacklisted": list }))
}

// ─────────────────────────────────────────────────────────────
// SETTINGS
// ─────────────────────────────────────────────────────────────

async fn settings_plan(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let db = st.db.lock().await;
    match db.accounts.get(&email) {
        Some(a) => {
            let now = proto::now_ms();
            let plan = if a.paid_until_ms > now {
                "paid"
            } else {
                "free"
            };
            let (mq, fq, al) = plan_limits(plan);
            let min_ton = std::env::var("INFNODE_SUB_MIN_TON")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.5);
            let storage_addr = std::env::var("STORAGE_CONTRACT_ADDRESS").unwrap_or_default();
            // проф-мониторинг: дни до истечения + статус (active/expiring_soon/expired)
            let days_left = if a.paid_until_ms > now {
                ((a.paid_until_ms - now) as f64 / (24.0 * 3600.0 * 1000.0)).floor() as i64
            } else {
                0
            };
            let plan_status = if a.paid_until_ms > now {
                if days_left <= 3 {
                    "expiring_soon"
                } else {
                    "active"
                }
            } else {
                "expired"
            };
            ok_json(json!({ "plan": plan, "plan_status": plan_status,
                "paid_until_ms": a.paid_until_ms, "days_left": days_left,
                "mail_quota": mq, "file_quota": fq, "aliases_limit": al,
                "mail_used": a.bytes_used, "file_used": a.files_used,
                "payment_ton": min_ton, "payment_days": 30, "storage_address": storage_addr }))
        }
        None => err_json(StatusCode::UNAUTHORIZED, "account not found"),
    }
}

async fn settings_quota(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let db = st.db.lock().await;
    match db.accounts.get(&email) {
        Some(a) => ok_json(json!({
            "used": a.bytes_used,
            "limit": effective_mail_quota(a),
            "file_used": a.files_used,
            "file_limit": effective_file_quota(a),
        })),
        None => err_json(StatusCode::UNAUTHORIZED, "account not found"),
    }
}

#[derive(Deserialize)]
struct ChangePwReq {
    current_pass: String,
    new_pass: String,
}

async fn settings_change_password(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<ChangePwReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // rate-limit (ревью F6): чувствительная ручка без троттлинга
    if rate_limit(&st.login_guard, &format!("chpw:{email}"), 10, 900000).await {
        return err_json(
            StatusCode::TOO_MANY_REQUESTS,
            "too many password changes, wait",
        );
    }
    if req.new_pass.len() < 8 {
        return err_json(
            StatusCode::BAD_REQUEST,
            "new password is shorter than 8 characters",
        );
    }
    // Argon2 ВНЕ мьютекса (тот же H1-класс: verify+hash ~0.2-1с под глобальным lock вешали API)
    let pw_hash = {
        let db = st.db.lock().await;
        match db.accounts.get(&email) {
            Some(a) => a.pw_hash.clone(),
            None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
        }
    };
    let ok = PasswordHash::new(&pw_hash)
        .map(|h| {
            Argon2::default()
                .verify_password(req.current_pass.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false);
    if !ok {
        return err_json(StatusCode::UNAUTHORIZED, "invalid current password");
    }
    let salt = SaltString::generate(&mut OsRng);
    let new_hash = Argon2::default()
        .hash_password(req.new_pass.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_default();
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    acc.pw_hash = new_hash;
    // M2: backup_codes_enc зашифрованы СТАРЫМ паролем — перешифровываем новым,
    // иначе Reveal после смены пароля отдаёт мусор навсегда
    if !acc.backup_codes_enc.is_empty() {
        let plain = unxor_codes(&req.current_pass, &acc.backup_codes_enc);
        acc.backup_codes_enc = xor_codes(&req.new_pass, &plain);
    }
    // смена пароля → отзываем все сессии (кроме текущей, которую перевыдаём ниже)
    acc.sessions.clear();
    acc.session_epoch = acc.session_epoch.wrapping_add(1);
    save_db(&st.db_path, &db).await;
    drop(db);
    let device = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .chars()
        .take(64)
        .collect::<String>();
    let ip = client_ip(&headers);
    let token = issue_session(&st, &email, &device, &ip).await;
    ok_json(json!({ "ok": true, "token": token }))
}

/// Удаление аккаунта: только СВОЙ аккаунт, только целиком.
///
/// Что удаляется (локально, на этой ноде):
/// - запись аккаунта в accounts.json (вместе с ней умирают все сессии — все
///   устройства разлогиниваются, токены перестают валидироваться);
/// - почтовые индексы и превью-мета этого адреса
///   (mail:{email}:index/sent-index/draft-index/spam-index/trash-index/archive-index/read/deleted,
///   mail:{email}:meta:{id}, mail:{email}:sentmeta:{id});
/// - файловый индекс (files:{email}) и история subscribe-nonce;
/// - ящик в Stalwart (best-effort: query id по имени + delete).
///
/// Что НЕ трогается (сознательно):
/// - общие блобы писем mail:{id} — у каждого письма два владельца (Inbox получателя
///   и Sent отправителя); удаление блоба сломало бы копию у собеседника;
/// - чужие аккаунты, реестр DHT, NFT в блокчейне и локальные NFT-карточки
///   (публичные метаданные токена, не приватная почта);
/// - реплики DHT на ДРУГИХ нодах — локальное удаление их не стирает, они догниют
///   по TTL/GC. Это честно отражено в ответе (dht_replicas: "not_purged") и в UI.
#[derive(Deserialize)]
struct DeleteAccountReq {
    current_password: String,
    #[serde(default)]
    code: String,
}

async fn settings_account_delete(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<DeleteAccountReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // защита от перебора пароля через ручку удаления
    let ip = client_ip(&headers);
    if rate_limit(&st.login_guard, &format!("del:{email}"), 10, 60 * 60 * 1000).await
        || rate_limit(&st.login_guard, &format!("deli:{ip}"), 30, 60 * 60 * 1000).await
    {
        return err_json(
            StatusCode::TOO_MANY_REQUESTS,
            "too many delete attempts, wait",
        );
    }
    // пароль обязателен; при включённой 2FA обязателен и код (TOTP или бэкап-код).
    // Исключение: passwordless web3-аккаунты (pw_hash пуст — пароля нет по дизайну):
    // для них хватает самой сессии (получена по wallet-proof при входе), код 2FA —
    // по-прежнему обязателен, если 2FA включена.
    let need_2fa = {
        let db = st.db.lock().await;
        let acc = match db.accounts.get(&email) {
            Some(a) => a,
            None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
        };
        if !acc.pw_hash.is_empty() && !verify_account_password(acc, &req.current_password) {
            return err_json(StatusCode::UNAUTHORIZED, "invalid current password");
        }
        acc.totp_enabled
    };
    if need_2fa {
        let db = st.db.lock().await;
        let acc = match db.accounts.get(&email) {
            Some(a) => a,
            None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
        };
        let now = proto::now_ms() / 1000;
        let secret = acc.totp_secret.clone().unwrap_or_default();
        let totp_ok = !secret.is_empty() && infnode::totp::verify_totp(&secret, &req.code, now);
        let hash = sha256_hex(&req.code);
        let is_backup = acc.backup_codes.iter().any(|h| h == &hash);
        drop(db);
        if !totp_ok && !is_backup {
            return err_json(StatusCode::UNAUTHORIZED, "2FA code required");
        }
    }
    // 1) собираем id писем из индексов, чтобы вычистить превью-мета
    let folders = [
        "index",
        "sent-index",
        "draft-index",
        "spam-index",
        "trash-index",
        "archive-index",
    ];
    let mut ids: Vec<String> = Vec::new();
    for f in folders {
        ids.extend(index_list(&st.node, &format!("mail:{email}:{f}")).await);
    }
    ids.sort();
    ids.dedup();
    // 2) чистим KV. ВАЖНО: индексы писались реплицированно (kv_set), поэтому
    // удалять только локально недостаточно — реплики в DHT «воскрешают» почту
    // после повторной регистрации того же адреса. Перезаписываем ПУСТЫМ
    // значением через kv_set (реплицируемо), затем чистим локально.
    let mut removed_keys = 0usize;
    let mut meta_keys = 0usize;
    for f in folders.iter().chain(["read", "deleted"].iter()) {
        let k = format!("mail:{email}:{f}");
        kv_set(&st.node, &k, "[]").await;
        st.node.kv_remove_local(&k).await;
        removed_keys += 1;
    }
    for id in &ids {
        for mk in [
            format!("mail:{email}:meta:{id}"),
            format!("mail:{email}:sentmeta:{id}"),
        ] {
            kv_set(&st.node, &mk, "").await;
            st.node.kv_remove_local(&mk).await;
            meta_keys += 1;
        }
    }
    for k in [format!("files:{email}"), format!("subnonce:{email}")] {
        kv_set(&st.node, &k, "").await;
        st.node.kv_remove_local(&k).await;
    }
    // 3) удаляем запись аккаунта (сессии умирают вместе с ней)
    {
        let mut db = st.db.lock().await;
        if db.accounts.remove(&email).is_none() {
            return err_json(StatusCode::UNAUTHORIZED, "account not found");
        }
        save_db(&st.db_path, &db).await;
    }
    // 4) ящик в Stalwart (best-effort: id резолвим по имени, как в CLI)
    let stalwart = delete_stalwart_mailbox(&email).await;
    eprintln!("[web] account deleted: {email} (indexes={removed_keys}, metas={meta_keys}, stalwart={stalwart})");
    // сброс cookie — аккаунта больше нет, сессия мертва
    let cookie_val =
        format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Secure; Path=/api; Max-Age=0");
    let mut resp = ok_json(json!({
        "ok": true,
        "deleted": { "index_keys": removed_keys, "meta_keys": meta_keys, "mails_indexed": ids.len() },
        "stalwart": stalwart,
        "kept": ["nft_onchain", "nft_cards", "shared_mail_blobs", "dht_registry"],
        "dht_replicas": "not_purged",
        "note": "NFT в блокчейне остаётся у владельца; общие блобы писем не тронуты (копия у собеседника); реплики на других нодах догниют по TTL",
    }));
    if let Ok(v) = header::HeaderValue::from_str(&cookie_val) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// Удалить ящик в Stalwart: резолв внутреннего id по имени, затем delete.
/// Возвращает короткое состояние для ответа API. Best-effort: ошибка здесь не
/// откатывает удаление аккаунта, только логируется.
async fn delete_stalwart_mailbox(email: &str) -> String {
    let cli = std::env::var("INFNODE_SMTP_CLI").unwrap_or_else(|_| "stalwart-cli".into());
    let url = std::env::var("STALWART_URL").unwrap_or_else(|_| "http://localhost:8080".into());
    let user = std::env::var("STALWART_USER").unwrap_or_default();
    let pass = std::env::var("STALWART_PASSWORD").unwrap_or_default();
    if user.is_empty() || pass.is_empty() {
        return "skipped_no_creds".to_string();
    }
    let local = email.split('@').next().unwrap_or(email);
    // резолв id
    let q = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(&cli)
            .env("STALWART_URL", &url)
            .env("STALWART_USER", &user)
            .env("STALWART_PASSWORD", &pass)
            .arg("query")
            .arg("account")
            .arg("--where")
            .arg(format!("name={local}"))
            .arg("--json")
            .output(),
    )
    .await;
    let id = match q {
        Ok(Ok(o)) if o.status.success() => {
            let out = String::from_utf8_lossy(&o.stdout);
            // query отдаёт по объекту на строку; берём поле "id" первого
            let mut found = String::new();
            for line in out.lines() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    if let Some(i) = v.get("id").and_then(|x| x.as_str()) {
                        found = i.to_string();
                        break;
                    }
                }
            }
            found
        }
        _ => String::new(),
    };
    if id.is_empty() {
        return "not_found".to_string();
    }
    let d = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(&cli)
            .env("STALWART_URL", &url)
            .env("STALWART_USER", &user)
            .env("STALWART_PASSWORD", &pass)
            .arg("delete")
            .arg("account")
            .arg("--ids")
            .arg(&id)
            .output(),
    )
    .await;
    match d {
        Ok(Ok(o)) if o.status.success() => "deleted".to_string(),
        _ => "delete_failed".to_string(),
    }
}

// E2E на новой системе включён всегда (ключи генерируются в браузере при первом входе).
// Отдаём enabled:true, чтобы фронтенд не блокировал E2EE-тумблер.
fn verify_account_password(acc: &Account, pw: &str) -> bool {
    PasswordHash::new(&acc.pw_hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn xor_codes(password: &str, codes: &[String]) -> Vec<String> {
    let key = blake3::hash(password.as_bytes());
    let k = key.as_bytes();
    codes
        .iter()
        .map(|c| {
            let x: Vec<u8> = c
                .bytes()
                .enumerate()
                .map(|(i, b)| b ^ k[i % k.len()])
                .collect();
            hex::encode(x)
        })
        .collect()
}

fn unxor_codes(password: &str, enc: &[String]) -> Vec<String> {
    let key = blake3::hash(password.as_bytes());
    let k = key.as_bytes();
    enc.iter()
        .filter_map(|h| {
            let x = hex::decode(h).ok()?;
            if x.is_empty() {
                return None;
            }
            let s: String = x
                .iter()
                .enumerate()
                .map(|(i, b)| (*b ^ k[i % k.len()]) as char)
                .collect();
            Some(s)
        })
        .collect()
}

async fn settings_2fa_status(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let db = st.db.lock().await;
    let acc = match db.accounts.get(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    ok_json(json!({
        "enabled": acc.totp_enabled,
        "backup_codes_left": acc.backup_codes.len(),
        "trusted_email": acc.trusted_email,
        "pending_email": acc.pending_email,
    }))
}

async fn settings_2fa_setup(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let secret = infnode::totp::new_totp_secret();
    let qr = infnode::totp::otpauth_uri(&secret, &email);
    let mut db = st.db.lock().await;
    if let Some(acc) = db.accounts.get_mut(&email) {
        // Защита: если 2FA уже включён, НЕ перезаписываем активный секрет (иначе
        // сломаем 2FA юзера: totp_enabled останется true, а код станет от нового
        // неподтверждённого секрета → юзер заблокирован). Сначала нужно disable.
        if acc.totp_enabled {
            return err_json(
                StatusCode::CONFLICT,
                "2FA already enabled — disable it before re-setting up",
            );
        }
        acc.totp_secret = Some(secret.clone());
    }
    save_db(&st.db_path, &db).await;
    ok_json(json!({ "secret": secret, "qr_uri": qr }))
}

#[derive(Deserialize)]
struct Enable2FaReq {
    secret: String,
    code: String,
    current_password: String,
}

async fn settings_2fa_enable(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<Enable2FaReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // rate-limit (ревью F6): чувствительная ручка без троттлинга
    if rate_limit(&st.login_guard, &format!("2fae:{email}"), 10, 900000).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "too many 2fa attempts, wait");
    }
    let now = proto::now_ms() / 1000;
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    if !verify_account_password(acc, &req.current_password) {
        return err_json(StatusCode::BAD_REQUEST, "invalid password");
    }
    let stored = acc.totp_secret.clone().unwrap_or_default();
    if stored.is_empty() || stored != req.secret {
        return err_json(
            StatusCode::BAD_REQUEST,
            "secret does not match — request setup again",
        );
    }
    if !infnode::totp::verify_totp(&stored, &req.code, now) {
        return err_json(StatusCode::BAD_REQUEST, "invalid authenticator code");
    }
    acc.totp_enabled = true;
    let codes = infnode::totp::new_backup_codes(10);
    acc.backup_codes = codes.iter().map(|c| sha256_hex(c)).collect();
    acc.backup_codes_enc = xor_codes(&req.current_password, &codes);
    save_db(&st.db_path, &db).await;
    drop(db);
    // Возвращаем НАСТОЯЩУЮ сессию (с sid), а не токен без sid: иначе после включения
    // 2FA пользователь оставался с токеном, который не подлежит отзыву.
    let device = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .chars()
        .take(64)
        .collect::<String>();
    let ip = client_ip(&headers);
    let token = issue_session(&st, &email, &device, &ip).await;
    ok_json(json!({
        "new_token": token,
        "backup_codes": codes,
    }))
}

#[derive(Deserialize)]
struct Disable2FaReq {
    current_password: String,
    /// TOTP-код или резервный код: снятие 2FA без владения authenticator
    /// делало угон сессии+пароля достаточным (асимметрия с enable).
    code: String,
}

async fn settings_2fa_disable(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<Disable2FaReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // rate-limit (ревью F6): чувствительная ручка без троттлинга
    if rate_limit(&st.login_guard, &format!("2fad:{email}"), 10, 900000).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "too many 2fa attempts, wait");
    }
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    if !verify_account_password(acc, &req.current_password) {
        return err_json(StatusCode::BAD_REQUEST, "invalid password");
    }
    if acc.totp_enabled {
        let now = proto::now_ms();
        let totp_ok = acc
            .totp_secret
            .as_deref()
            .map(|s| infnode::totp::verify_totp(s, &req.code, now))
            .unwrap_or(false);
        let backup_ok = {
            let h = sha256_hex(&req.code);
            acc.backup_codes.iter().any(|c| c == &h)
        };
        if !totp_ok && !backup_ok {
            return err_json(
                StatusCode::BAD_REQUEST,
                "authenticator or backup code required",
            );
        }
    }
    acc.totp_enabled = false;
    acc.totp_secret = None;
    acc.backup_codes = Vec::new();
    acc.backup_codes_enc = Vec::new();
    save_db(&st.db_path, &db).await;
    ok_json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct BackupCodesReq {
    current_password: String,
}

async fn settings_2fa_backup_codes(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<BackupCodesReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // rate-limit (ревью F6): чувствительная ручка без троттлинга
    if rate_limit(&st.login_guard, &format!("2fab:{email}"), 10, 900000).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "too many 2fa attempts, wait");
    }
    let db = st.db.lock().await;
    let acc = match db.accounts.get(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    if !verify_account_password(acc, &req.current_password) {
        return err_json(StatusCode::BAD_REQUEST, "invalid password");
    }
    let plain = unxor_codes(&req.current_password, &acc.backup_codes_enc);
    ok_json(json!({ "backup_codes": plain }))
}

async fn settings_trusted_email(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let te = req["trusted_email"].as_str().unwrap_or("").to_string();
    let password = req["password"].as_str().unwrap_or("");
    if te.is_empty() || !te.contains('@') {
        return err_json(StatusCode::BAD_REQUEST, "provide a valid backup email");
    }
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    // пароль обязателен, если у аккаунта он есть (раньше пустой пароль проходил —
    // угнанная сессия привязывала чужой ящик без знания пароля). У web3-аккаунтов
    // без пароля сама сессия доказывает владение кошельком.
    if !acc.pw_hash.is_empty() && (password.is_empty() || !verify_account_password(acc, password)) {
        return err_json(StatusCode::BAD_REQUEST, "password required");
    }
    acc.trusted_email = Some(te.clone());
    acc.pending_email = None;
    save_db(&st.db_path, &db).await;
    ok_json(json!({ "ok": true, "trusted_email": te }))
}

async fn settings_signature_get(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let db = st.db.lock().await;
    match db.accounts.get(&email) {
        Some(a) => ok_json(json!({ "signature": a.signature.clone().unwrap_or_default() })),
        None => err_json(StatusCode::UNAUTHORIZED, "account not found"),
    }
}

async fn settings_signature_set(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let sig = req["signature"]
        .as_str()
        .unwrap_or("")
        .chars()
        .take(2000)
        .collect::<String>();
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    acc.signature = if sig.trim().is_empty() {
        None
    } else {
        Some(sig.clone())
    };
    save_db(&st.db_path, &db).await;
    ok_json(json!({ "ok": true, "signature": sig }))
}

async fn settings_sessions(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let db = st.db.lock().await;
    match db.accounts.get(&email) {
        Some(a) => ok_json(json!(a.sessions)),
        None => err_json(StatusCode::UNAUTHORIZED, "account not found"),
    }
}

#[derive(Deserialize)]
struct SessionReq {
    session_id: Option<String>,
}

async fn settings_sessions_revoke(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<SessionReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let sid = match req.session_id {
        Some(s) => s,
        None => return err_json(StatusCode::BAD_REQUEST, "session_id required"),
    };
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    let before = acc.sessions.len();
    acc.sessions.retain(|s| s.id != sid);
    if acc.sessions.len() == before {
        return err_json(StatusCode::NOT_FOUND, "session not found");
    }
    save_db(&st.db_path, &db).await;
    ok_json(json!({ "ok": true }))
}

async fn settings_sessions_set_primary(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<SessionReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let sid = match req.session_id {
        Some(s) => s,
        None => return err_json(StatusCode::BAD_REQUEST, "session_id required"),
    };
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    for s in acc.sessions.iter_mut() {
        s.is_current = s.id == sid;
    }
    save_db(&st.db_path, &db).await;
    ok_json(json!({ "ok": true }))
}

async fn settings_sessions_revoke_all(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    acc.sessions.clear();
    // инвалидируем все выданные JWT (следующие auth_email_sid отклонят по epoch)
    acc.session_epoch = acc.session_epoch.wrapping_add(1);
    save_db(&st.db_path, &db).await;
    ok_json(json!({ "ok": true }))
}

async fn settings_contract_balance(State(st): State<WebState>, headers: HeaderMap) -> Response {
    match auth_email(&st, &headers).await {
        Ok(_) => {
            let addr = std::env::var("REGISTRY_CONTRACT_ADDRESS").unwrap_or_default();
            if addr.is_empty() {
                return ok_json(json!({ "balance": "0", "admin_address": null }));
            }
            let addr2 = addr.clone();
            let bal = tokio::task::spawn_blocking(move || {
                crate::blockchain::get_contract_balance(&addr2)
            })
            .await
            .unwrap_or(0);
            ok_json(json!({ "balance": bal.to_string(), "admin_address": null }))
        }
        Err(r) => r,
    }
}

async fn settings_aliases_list(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let db = st.db.lock().await;
    match db.accounts.get(&email) {
        Some(a) => ok_json(json!({ "aliases": a.aliases })),
        None => err_json(StatusCode::UNAUTHORIZED, "account not found"),
    }
}

#[derive(Deserialize)]
struct AliasReq {
    alias: String,
}

async fn settings_aliases_add(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<AliasReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // rate-limit (ревью F6): чувствительная ручка без троттлинга
    if rate_limit(&st.login_guard, &format!("alias:{email}"), 30, 600000).await {
        return err_json(
            StatusCode::TOO_MANY_REQUESTS,
            "too many alias operations, wait",
        );
    }
    let local = req.alias.trim().to_lowercase();
    if local.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "empty alias");
    }
    let alias_email = format!("{local}@{MAIL_DOMAIN}");
    if !valid_email(&alias_email) {
        return err_json(StatusCode::BAD_REQUEST, "invalid alias format");
    }
    let mut db = st.db.lock().await;
    // алиас не должен совпадать с чужим аккаунтом или чужим алиасом
    if let Some(owner) = resolve_db_email(&db, &alias_email) {
        if owner != email {
            return err_json(StatusCode::CONFLICT, "this address is already taken");
        }
    }
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    if acc.aliases.iter().any(|a| a == &local) {
        return err_json(StatusCode::CONFLICT, "such alias already exists");
    }
    let al = if acc.paid_until_ms > proto::now_ms() {
        plan_limits("paid").2
    } else {
        FREE_ALIAS_LIMIT
    };
    if acc.aliases.len() >= al {
        return err_json(StatusCode::PAYLOAD_TOO_LARGE, format!("alias limit: {al}"));
    }
    acc.aliases.push(local.clone());
    save_db(&st.db_path, &db).await;
    drop(db);
    // best-effort синк в DHT-реестр (для CLI-адресации)
    let x = st
        .db
        .lock()
        .await
        .accounts
        .get(&email)
        .and_then(|a| a.x_pub.clone());
    if let Some(x) = x {
        let node = st.node.clone();
        let ed = "00".repeat(32);
        tokio::spawn(async move {
            registry_set(&node, &alias_email, &x, &ed).await;
        });
    }
    ok_json(json!({ "ok": true, "alias": local }))
}

async fn settings_aliases_delete(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<AliasReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let local = req.alias.trim().to_lowercase();
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    acc.aliases.retain(|a| a != &local);
    save_db(&st.db_path, &db).await;
    ok_json(json!({ "ok": true }))
}

async fn nft_status(State(st): State<WebState>, Path(email): Path<String>) -> Response {
    let email = norm_email(&email);
    let collection = std::env::var("NFT_COLLECTION_ADDRESS").unwrap_or_default();
    if collection.is_empty() {
        return ok_json(json!({ "has_nft": false, "token_id": null, "collection_address": null }));
    }
    // Свежий кэш — в chain не идём. Публичный TON RPC жёстко лимитирует (429),
    // а дашборд дёргает этот эндпоинт на каждом открытии.
    let now = nft_now_ms();
    let fresh = { st.nft_status_cache.lock().await.get(&email).cloned() };
    if let Some((ts, cached)) = fresh {
        if now - ts < NFT_STATUS_TTL_MS {
            return ok_json(cached);
        }
    }
    // реальная проверка NFT у email в Collection + on-chain владелец токена.
    // ВАЖНО: сбой chain/RPC (429 rate limit, таймаут) — это НЕИЗВЕСТНО, а не «NFT нет».
    // Иначе владелец NFT видел бы «нет NFT» на каждом rate-limit TON Center.
    let email2 = email.clone();
    let token_id =
        match tokio::task::spawn_blocking(move || crate::blockchain::check_nft_status(&email2))
            .await
        {
            Ok(Ok(v)) => v,
            _ => {
                // Chain недоступен. Если есть прошлый ответ — отдаём его, помечая stale:
                // это честнее и полезнее 503. Иначе 503 «неизвестно» (именно НЕ «нет NFT»).
                let prev = { st.nft_status_cache.lock().await.get(&email).cloned() };
                if let Some((ts, mut v)) = prev {
                    if let Some(o) = v.as_object_mut() {
                        o.insert("stale".to_string(), json!(true));
                        o.insert("cached_age_secs".to_string(), json!((now - ts) / 1000));
                    }
                    return ok_json(v);
                }
                return err_json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "chain unavailable: NFT status unknown (not 'no NFT')",
                );
            }
        };
    // владелец on-chain (для детекта передачи NFT другому кошельку — owner_changed в UI)
    // отдельный spawn_blocking с таймаутом: chain-запрос не должен тормозить статус
    let owner = if let Some(tid) = token_id {
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::task::spawn_blocking(move || crate::blockchain::get_nft_owner(tid)),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .flatten()
    } else {
        None
    };
    let body = json!({
        "has_nft": token_id.is_some(),
        "token_id": token_id,
        "owner": owner,
        "collection_address": collection,
    });
    st.nft_status_cache
        .lock()
        .await
        .insert(email, (now, body.clone()));
    ok_json(body)
}

async fn nft_upgrade(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // проверяем настройку контрактов и сервиса карточек
    let collection = std::env::var("NFT_COLLECTION_ADDRESS").unwrap_or_default();
    if collection.is_empty() {
        return err_json(
            StatusCode::BAD_REQUEST,
            "NFT Collection not configured (NFT_COLLECTION_ADDRESS)",
        );
    }
    // проверяем подписывающий ключ
    if crate::nft::lsb::signing_key().is_none() {
        return err_json(StatusCode::BAD_REQUEST, "NFT_SIGNING_SECRET not set");
    }
    // token_id: по хэшу email (стабильный)
    let hash = crate::blockchain::email_hash_hex(&email);
    let token_id = {
        let mut v: u64 = 0;
        for b in hash.as_bytes().iter().take(8) {
            v = (v << 8) | (*b as u64);
        }
        v
    };
    let username = email.split('@').next().unwrap_or(&email).to_string();
    let creator_wallet = std::env::var("NFT_CREATOR_WALLET").unwrap_or_default();
    // генерируем карточку
    match crate::nft::nft::generate_card(&username, token_id, &email, &collection, &creator_wallet)
    {
        Ok((png, payload)) => {
            let data_dir = st.node.data_dir.clone();
            match crate::nft::nft::save_card(
                token_id,
                &png,
                &payload,
                data_dir.to_str().unwrap_or("."),
            ) {
                Ok(path) => ok_json(json!({
                    "ok": true,
                    "token_id": token_id,
                    "email": email,
                    "email_hash": hash,
                    "collection_address": collection,
                    "card_path": path.to_string_lossy(),
                    "size": png.len(),
                })),
                Err(e) => err_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to save card: {e}"),
                ),
            }
        }
        Err(e) => err_json(
            StatusCode::BAD_GATEWAY,
            format!("failed to generate card: {e}"),
        ),
    }
}

// ─────────────────────────────────────────────────────────────
// SMTP-мост (исходящая почта в интернет)
// ─────────────────────────────────────────────────────────────

/// Отправить письмо внешнему получателю через SMTP (валидатор = SMTP-клиент своего MTA).
/// Конфиг: INFNODE_SMTP_HOST / _PORT / _USER / _PASS (по умолчанию relay через stalwart).
/// MAIL FROM = отправитель; требует, чтобы у отправителя был ящик в MTA (provisioning).
async fn smtp_relay_external(
    st: &WebState,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    attachments: Option<Vec<MailAttachmentReq>>,
) -> Response {
    use lettre::message::header::ContentType;
    use lettre::message::Message;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::transport::smtp::client::{Tls, TlsParameters};
    use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

    let host = std::env::var("INFNODE_SMTP_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("INFNODE_SMTP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(465);
    let user = from.to_string();
    // авторизация паролем SMTP-ящика отправителя (создаётся при регистрации)
    let pass = {
        let db = st.db.lock().await;
        db.accounts
            .get(from)
            .and_then(|a| a.smtp_pass.clone())
            .unwrap_or_default()
    };

    let from_addr: lettre::Address = match from.parse() {
        Ok(a) => a,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid sender address"),
    };
    let to_addr: lettre::Address = match to.parse() {
        Ok(a) => a,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid recipient address"),
    };
    // Мета вложений для копии в Sent — считаем ДО move (attachments уходит в сборку ниже).
    // Без этого в Sent вложение не отображалось (писался пустой список).
    let att_meta: Vec<Value> = attachments
        .as_ref()
        .map(|atts| {
            atts.iter()
                .map(|a| {
                    let size = base64::engine::general_purpose::STANDARD
                        .decode(&a.data)
                        .map(|d| d.len())
                        .unwrap_or(0);
                    json!({ "name": a.name.clone(), "mime": a.mime.clone(), "size": size })
                })
                .collect()
        })
        .unwrap_or_default();
    let max_att = crate::inbound::max_attach_total();
    let mut att_blobs: Vec<(usize, Vec<u8>)> = Vec::new();
    if let Some(atts) = attachments.as_ref() {
        if atts.len() > crate::inbound::MAX_ATTACH_COUNT {
            return err_json(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "too many attachments (max {})",
                    crate::inbound::MAX_ATTACH_COUNT
                ),
            );
        }
        let mut total = 0usize;
        for (i, a) in atts.iter().enumerate() {
            match base64::engine::general_purpose::STANDARD.decode(&a.data) {
                Err(_) => return err_json(StatusCode::BAD_REQUEST, "attachment: invalid base64"),
                Ok(data) => {
                    if data.is_empty() {
                        continue;
                    }
                    if data.len() > max_att.saturating_sub(total) {
                        return err_json(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "attachments too large (max 25 MB)",
                        );
                    }
                    total += data.len();
                    att_blobs.push((i, data));
                }
            }
        }
    }
    // внешние письма с вложениями → multipart/mixed; без них — просто text/plain
    let mut builder = Message::builder()
        .from(lettre::message::Mailbox::new(None, from_addr))
        .to(lettre::message::Mailbox::new(None, to_addr))
        .subject(subject);
    let msg = if let Some(atts) = attachments {
        if atts.is_empty() {
            builder = builder.header(ContentType::TEXT_PLAIN);
            match builder.body(body.to_string()) {
                Ok(m) => m,
                Err(_) => return err_json(StatusCode::BAD_REQUEST, "failed to assemble email"),
            }
        } else {
            use lettre::message::Attachment;
            use lettre::message::MultiPart;
            let mut multipart = MultiPart::mixed().multipart(
                MultiPart::alternative().multipart(
                    MultiPart::related().singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(body.to_string()),
                    ),
                ),
            );
            for a in atts {
                let data = match base64::engine::general_purpose::STANDARD.decode(&a.data) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                if data.is_empty() {
                    continue;
                }
                let name = crate::inbound::sanitize_filename(&a.name)
                    .unwrap_or_else(|| "attachment".into());
                let mime = a
                    .mime
                    .map(|m| crate::inbound::sanitize_mime(&m))
                    .unwrap_or_else(|| "application/octet-stream".into());
                let ct = match mime.parse::<ContentType>() {
                    Ok(c) => c,
                    Err(_) => ContentType::TEXT_PLAIN,
                };
                multipart = multipart.singlepart(Attachment::new(name).body(data, ct));
            }
            // ВАЖНО: здесь НЕ ставим Content-Type: text/plain — тело multipart,
            // builder.multipart сам выставит multipart/mixed с boundary. Раньше
            // заголовок говорил text/plain при multipart-теле — Gmail показывал
            // исходник письма вместо текста (жалоба с реальным письмом).
            match builder.multipart(multipart) {
                Ok(m) => m,
                Err(_) => return err_json(StatusCode::BAD_REQUEST, "failed to assemble email"),
            }
        }
    } else {
        builder = builder.header(ContentType::TEXT_PLAIN);
        match builder.body(body.to_string()) {
            Ok(m) => m,
            Err(_) => return err_json(StatusCode::BAD_REQUEST, "failed to assemble email"),
        }
    };

    // TLS: для локального SMTP-моста (stalwart на loopback с самоподписанным сертификатом)
    // допускаем невалидный сертификат, НО для внешнего SMTP_HOST — строгая проверка
    // (иначе relay можно перехватить MitM). Синхронно с inbound IMAP (inbound.rs).
    let is_loopback = host == "127.0.0.1" || host == "::1" || host == "localhost";
    let tls_params = match TlsParameters::builder(host.clone())
        .dangerous_accept_invalid_certs(is_loopback)
        .dangerous_accept_invalid_hostnames(is_loopback)
        .build()
    {
        Ok(p) => p,
        Err(_) => return err_json(StatusCode::BAD_GATEWAY, "SMTP TLS setup error"),
    };
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
        .port(port)
        .tls(Tls::Wrapper(tls_params))
        .credentials(Credentials::new(user, pass))
        .build();

    match mailer.send(msg).await {
        Ok(_) => {
            // Копия в Sent: раньше внешнее письмо уходило через мост и НЕ
            // сохранялось — вкладка Sent оставалась пустой, хотя интерфейс
            // сообщал об успешной отправке. Кладём как обычное письмо
            // (тело + мета + индекс Sent), чтобы оно было видно сразу.
            let at = proto::now_ms();
            let id = hex::encode(
                blake3::hash(format!("{from}:{to}:{at}:{}", rand::random::<u64>()).as_bytes())
                    .as_bytes(),
            );
            // Sent-копия внешнего: конверт на отправителя, если ключи есть
            // (само письмо наружу всё равно уходит открытым SMTP — это неизбежно).
            let sender_pub_ext = registry_get(&st.node, from)
                .await
                .and_then(|v| v["x_pub"].as_str().map(String::from));
            let (body_ext, dek_ext, dek_opt) = match sender_pub_ext {
                Some(pub_hex) => match storage_box_dek(&[(from.to_string(), pub_hex)]) {
                    Some((dek, boxes)) => (
                        storage_seal(&dek, body.as_bytes()),
                        json!({ "boxes": boxes }),
                        Some(dek),
                    ),
                    None => (body.to_string(), Value::Null, None),
                },
                None => (body.to_string(), Value::Null, None),
            };
            let mut att_blobs_ext: Vec<(usize, Vec<u8>)> = Vec::with_capacity(att_blobs.len());
            for (i, adata) in &att_blobs {
                match &dek_opt {
                    Some(dek) => att_blobs_ext.push((*i, storage_seal(dek, adata).into_bytes())),
                    None => att_blobs_ext.push((*i, adata.clone())),
                }
            }
            // дальше код использует att_blobs — подменяем зашифрованными
            let att_blobs = att_blobs_ext;
            let blob = json!({
                "sender": from, "to": to, "at": at, "subject": subject, "body": body_ext,
                "dek": dek_ext,
                "attachments": [],
            })
            .to_string()
            .into_bytes();
            let name = format!("mail:{id}");
            let _ = st.node.store_mail(&name, &blob).await;
            // ВАЖНО: мета включает body — иначе список писем вынужден тянуть тело
            // из сети при каждом открытии, а при таймауте показывает пустое письмо
            // (наблюдалось: внешнее письмо открывалось без текста).
            // Блобы вложений для копии: скачивание из Sent идёт по ключу
            // mail:{id}:att:{i}. Имена подставляем здесь (id уже известен).
            for (i, adata) in &att_blobs {
                st.node
                    .store_blob("mail", &format!("mail:{id}:att:{i}"), adata)
                    .await;
            }
            // Квота: внешняя отправка раньше не учитывалась — счётчик почты
            // показывал 0 Bytes при непустом ящике. Считаем как у внутренних.
            {
                let size =
                    blob.len() as u64 + att_blobs.iter().map(|(_, d)| d.len() as u64).sum::<u64>();
                let mut db = st.db.lock().await;
                if let Some(a) = db.accounts.get_mut(from) {
                    a.bytes_used = a.bytes_used.saturating_add(size);
                }
                save_db(&st.db_path, &db).await;
            }
            let preview = body.trim().chars().take(200).collect::<String>();
            let meta = json!({
                "sender": from, "to": to, "at": at, "subject": subject, "preview": preview,
                "body": body, "attachments": att_meta,
            });
            st.node
                .kv_store_local(&format!("mail:{from}:sentmeta:{id}"), &meta.to_string())
                .await;
            let _guard = st.index_lock.lock().await;
            index_add(&st.node, &mail_index_key(from, "Sent"), &id).await;
            drop(_guard);
            ok_json(json!({ "ok": true, "relayed": true, "to": to, "id": id }))
        }
        Err(e) => {
            eprintln!("[web] smtp relay fail: {e}");
            err_json(
                StatusCode::BAD_GATEWAY,
                "failed to send to external mail (SMTP bridge)",
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────
// FILE.STORAGE (раздельное пространство, owner-gate)
// ─────────────────────────────────────────────────────────────

fn safe_filename(name: &str) -> bool {
    // имя файла может содержать путь с '/' (папки в Files), но:
    // - без '..', '\\', контроля каждого компонента
    // - не пустой, <= 256, без leading/trailing/double slash
    if name.is_empty() || name.len() > 256 {
        return false;
    }
    if name.contains('\\') || name.contains("..") {
        return false;
    }
    if name.starts_with('/') || name.ends_with('/') || name.contains("//") {
        return false;
    }
    name.bytes().all(|b| b == b'/' || b.is_ascii_graphic())
}

/// blob-ключ файла: хэш пути (без '/' в ключе манифеста и на диске).
fn file_blob_key(email: &str, name: &str) -> String {
    let h = blake3::hash(format!("{email}:{name}").as_bytes());
    format!("file:{email}:{}", hex::encode(h.as_bytes()))
}

/// Domain separation for the account-scoped Files key.
const FILES_OWNER_DOMAIN: &str = "infmail-files-owner-v2";
/// Legacy node-scoped derivation (read-only compatibility, see below).
const LEGACY_FILES_OWNER_DOMAIN: &[u8] = b"infmail-files-owner-v1";

/// Per-account owner ML-KEM seed for Files blobs.
///
/// The seed is derived from an ACCOUNT secret (`Account::files_key_secret`,
/// 32 random bytes generated on first use and stored next to `pw_hash`), not
/// from the node's KEM seed. Consequences:
/// * two accounts on the same node have unrelated Files keys;
/// * re-keying/restoring the NODE KEM key no longer changes every account's
///   Files key (the old `blake3_xof(node KEM seed || email)` did);
/// * the web tier still holds the account secret (like `pw_hash`), so this is
///   **server-side at-rest sealing, NOT end-to-end encryption**. A node that
///   has `accounts.json` can open the account's Files; a storage/replica node
///   (sealed manifest only) cannot.
///
/// Hard limitation (documented, fail-closed): a web node that does NOT have
/// the account record has no Files key. There is no node-wide fallback and
/// `files_download` refuses rather than deriving anything from the node KEM
/// seed. The legacy v1 derivation exists only to READ blobs written before
/// this change (and those are re-sealed on the next upload).
fn files_owner_seed(
    account_secret: &[u8; 32],
    email: &str,
) -> [u8; infnode::mailbox::KEM_SEED_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(FILES_OWNER_DOMAIN);
    hasher.update(account_secret);
    hasher.update(email.as_bytes());
    let mut seed = [0u8; infnode::mailbox::KEM_SEED_LEN];
    hasher.finalize_xof().fill(&mut seed);
    seed
}

/// LEGACY (v1) node-scoped derivation. READ-ONLY: never used to seal a new
/// blob, only to open files written before `files_key_secret` existed.
fn legacy_file_owner_seed(node: &Node, email: &str) -> [u8; infnode::mailbox::KEM_SEED_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEGACY_FILES_OWNER_DOMAIN);
    hasher.update(&node.keys.kem_seed);
    hasher.update(email.as_bytes());
    let mut seed = [0u8; infnode::mailbox::KEM_SEED_LEN];
    hasher.finalize_xof().fill(&mut seed);
    seed
}

/// Owner encapsulation key (hex) for Files blobs of `email`.
fn files_owner_ek(account_secret: &[u8; 32], email: &str) -> String {
    hex::encode(infnode::mailbox::kem_ek_from_seed(&files_owner_seed(
        account_secret,
        email,
    )))
}

/// Owner seed (hex, secret) used to open Files blobs of `email`.
fn files_owner_key(account_secret: &[u8; 32], email: &str) -> String {
    hex::encode(files_owner_seed(account_secret, email))
}

/// Load (or create once) the account's Files secret.
///
/// Fail-closed: `None` when the account record does not exist. A malformed
/// stored value is replaced with a fresh random secret (the blob then fails
/// closed at AEAD, never decrypts under a guessable key).
async fn account_files_secret(st: &WebState, email: &str) -> Option<[u8; 32]> {
    let mut db = st.db.lock().await;
    let acc = db.accounts.get_mut(email)?;
    let parsed = acc
        .files_key_secret
        .as_deref()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
    match parsed {
        Some(secret) => Some(secret),
        None => {
            use rand::RngCore;
            let mut secret = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut secret);
            acc.files_key_secret = Some(hex::encode(secret));
            save_db(&st.db_path, &db).await;
            Some(secret)
        }
    }
}

/// Fetch a Files blob for `email`: account-scoped key first, the legacy
/// node-scoped key only for blobs written before the account secret existed,
/// then the (unsealed) legacy at-rest format.
async fn fetch_file_blob(st: &WebState, email: &str, name: &str) -> Option<Vec<u8>> {
    // Fail closed without the account secret: a node that cannot load the
    // account record must NOT derive a key from the node KEM seed. (The v1
    // branch below is only a compatibility read for blobs written before the
    // account secret existed; it still requires the account to exist.)
    let secret = account_files_secret(st, email).await?;
    let blob_name = file_blob_key(email, name);
    if let Some(v) = st
        .node
        .fetch_blob_owner("files", &blob_name, &files_owner_key(&secret, email))
        .await
    {
        return Some(v);
    }
    let legacy_key = hex::encode(legacy_file_owner_seed(&st.node, email));
    if let Some(v) = st
        .node
        .fetch_blob_owner("files", &blob_name, &legacy_key)
        .await
    {
        return Some(v);
    }
    match st.node.fetch_blob("files", &blob_name).await {
        Some(v) => Some(v),
        None => {
            // raw-name layout (files before folders existed)
            st.node
                .fetch_blob("files", &format!("file:{email}:{name}"))
                .await
        }
    }
}

fn file_index_key(email: &str) -> String {
    format!("files:{email}")
}

async fn files_index(node: &Arc<Node>, email: &str) -> Vec<Value> {
    match node.get_local_kv(&file_index_key(email)).await {
        Some(s) => serde_json::from_str(&s).unwrap_or_default(),
        None => Vec::new(),
    }
}

async fn files_list(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let items = files_index(&st.node, &email).await;
    ok_json(json!({ "files": items }))
}

#[derive(Deserialize)]
struct FileUploadReq {
    name: String,
    data: String, // base64
}

async fn files_upload(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<FileUploadReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // rate-limit заливок: 60/10мин на аккаунт (флуд шифртекстом выжирает диск трём нодам)
    if rate_limit(&st.login_guard, &format!("fup:{email}"), 60, 10 * 60 * 1000).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "too many uploads, wait");
    }
    if !safe_filename(&req.name) {
        return err_json(StatusCode::BAD_REQUEST, "invalid file name");
    }
    let data = match base64::engine::general_purpose::STANDARD.decode(&req.data) {
        Ok(d) => d,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid base64"),
    };
    // папки создаются как пустой ".keep" файл — разрешаем пустые данные для них.
    let is_folder_keep = req.name.ends_with("/.keep") || req.name.ends_with("\\.keep");
    if (!is_folder_keep && data.is_empty()) || data.len() > 64 * 1024 * 1024 {
        return err_json(StatusCode::PAYLOAD_TOO_LARGE, "file is empty or >64 MB");
    }
    // защита от XSS через активные типы: html/svg/xml/js не храним в Files
    // (риск исполнения при открытии из предпросмотра)
    let ext = req
        .name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(
        ext.as_str(),
        "html" | "htm" | "svg" | "xml" | "xhtml" | "js" | "mjs"
    ) {
        return err_json(
            StatusCode::BAD_REQUEST,
            "file type is forbidden in file storage",
        );
    }
    // квота файлов (раздельная от почты). При перезаписи файла возвращаем старый размер.
    {
        let mut db = st.db.lock().await;
        let acc = match db.accounts.get_mut(&email) {
            Some(a) => a,
            None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
        };
        let fq = effective_file_quota(acc);
        let list = files_index(&st.node, &email).await;
        let prev_size = list
            .iter()
            .find(|e| e["name"].as_str() == Some(req.name.as_str()))
            .and_then(|e| e["size"].as_u64())
            .unwrap_or(0);
        let cur_used = acc.files_used.saturating_sub(prev_size);
        let new_total = cur_used + data.len() as u64;
        if new_total > fq {
            return err_json(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("file storage limit: {} bytes", fq),
            );
        }
        acc.files_used = new_total;
        save_db(&st.db_path, &db).await;
    }
    let blob_name = file_blob_key(&email, &req.name);
    // Owner-sealed upload (account-scoped owner key; see `files_owner_seed`).
    // The account secret is required both to seal AND to authenticate the
    // manifest, so a node without the account record fails closed here.
    let Some(secret) = account_files_secret(&st, &email).await else {
        return err_json(StatusCode::UNAUTHORIZED, "account not found");
    };
    let report = st
        .node
        .store_blob_boxed(
            "files",
            &blob_name,
            &data,
            Some(&files_owner_ek(&secret, &email)),
            Some(&files_owner_key(&secret, &email)),
        )
        .await;
    if report.chunks == 0
        && st
            .node
            .get_local_kv(&Node::blob_manifest_key("files", &blob_name))
            .await
            .is_none()
    {
        return err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "file seal failed (owner key refused by storage)",
        );
    }
    // Honest durability: a write that no node kept (replicas == 0) is not
    // reported as success.
    if report.replicas == 0 {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "file stored locally but no durable replica accepted it",
        );
    }
    // индекс файлов владельца
    let ikey = file_index_key(&email);
    let mut list = files_index(&st.node, &email).await;
    list.retain(|e| e["name"].as_str() != Some(req.name.as_str()));
    list.push(json!({ "name": req.name, "size": data.len(), "at": proto::now_ms() }));
    kv_set(
        &st.node,
        &ikey,
        &serde_json::to_string(&list).unwrap_or("[]".into()),
    )
    .await;
    ok_json(json!({ "ok": true, "name": req.name, "size": data.len() }))
}

async fn files_download(
    State(st): State<WebState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if !safe_filename(&name) {
        return err_json(StatusCode::BAD_REQUEST, "invalid file name");
    }
    // web-путь: файл юзера живёт на нодах (репликация f:*) — fetch_blob сам сделает
    // DHT-fallback манифеста и чанков, если локально нет (не только локальный манифест).
    // The account-scoped key is required; there is no node-key derivation here.
    let data = fetch_file_blob(&st, &email, &name).await;
    match data {
        Some(data) => ok_json(json!({
            "name": name,
            "size": data.len(),
            "data": base64::engine::general_purpose::STANDARD.encode(&data),
        })),
        None => err_json(StatusCode::NOT_FOUND, "file not found"),
    }
}

/// Создать публичную ссылку на файл (шаринг). Возвращает {token, url}.
async fn files_share_create(
    State(st): State<WebState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if !safe_filename(&name) {
        return err_json(StatusCode::BAD_REQUEST, "invalid file name");
    }
    // проверяем, что файл реально существует (владелец)
    let has = fetch_file_blob(&st, &email, &name).await.is_some();
    if !has {
        return err_json(StatusCode::NOT_FOUND, "file not found");
    }
    // токен: 16 байт случайных -> hex
    let mut rnd = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    let token = hex::encode(rnd);
    let exp = proto::now_ms() + 30 * 24 * 3600 * 1000; // 30 дней
    let rec = json!({ "owner": email, "name": name, "exp": exp }).to_string();
    // share-ключи — локально-авторитетные (не реплицируются, см. handle_dht_store)
    st.node
        .kv_store_local(&format!("share:file:{token}"), &rec)
        .await;
    ok_json(json!({ "ok": true, "token": token, "url": format!("/api/v1/files/share/{token}") }))
}

/// Отзыв share-ссылки (только владелец файла).
async fn files_share_revoke(
    State(st): State<WebState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if token.len() != 32 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return err_json(StatusCode::BAD_REQUEST, "invalid token");
    }
    let key = format!("share:file:{token}");
    let rec = match st.node.get_local_kv(&key).await {
        Some(r) => r,
        None => {
            return err_json(
                StatusCode::NOT_FOUND,
                "share not found (may live on another node)",
            )
        }
    };
    let owner = serde_json::from_str::<Value>(&rec)
        .ok()
        .and_then(|v| v["owner"].as_str().map(String::from))
        .unwrap_or_default();
    if owner != email {
        return err_json(StatusCode::FORBIDDEN, "not your share");
    }
    st.node.kv_remove_local(&key).await;
    ok_json(json!({ "ok": true, "revoked": true }))
}

/// Список своих активных share-ссылок (только эта нода: share-ключи локальны).
async fn files_shares_list(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let now = proto::now_ms();
    let keys = st.node.kv_manifest_keys("share:file:").await;
    let mut out = Vec::new();
    for k in keys {
        if let Some(rec) = st.node.get_local_kv(&k).await {
            if let Ok(v) = serde_json::from_str::<Value>(&rec) {
                if v["owner"].as_str() == Some(email.as_str())
                    && v["exp"].as_i64().unwrap_or(0) > now
                {
                    out.push(json!({
                        "token": k.trim_start_matches("share:file:"),
                        "name": v["name"],
                        "exp": v["exp"],
                    }));
                }
            }
        }
    }
    ok_json(json!({ "shares": out }))
}

/// Публичное скачивание по токену (без auth).
async fn files_share_download(State(st): State<WebState>, Path(token): Path<String>) -> Response {
    if token.len() != 32 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return err_json(StatusCode::BAD_REQUEST, "invalid token");
    }
    let Some(rec) = st.node.get_local_kv(&format!("share:file:{token}")).await else {
        return err_json(StatusCode::NOT_FOUND, "link not found or expired");
    };
    let Ok(recv) = serde_json::from_str::<serde_json::Value>(&rec) else {
        return err_json(StatusCode::NOT_FOUND, "link corrupted");
    };
    if recv["exp"].as_i64().unwrap_or(0) < proto::now_ms() {
        return err_json(StatusCode::GONE, "link expired");
    }
    let owner = recv["owner"].as_str().unwrap_or("").to_string();
    let name = recv["name"].as_str().unwrap_or("").to_string();
    if owner.is_empty() || !safe_filename(&name) {
        return err_json(StatusCode::NOT_FOUND, "invalid link");
    }
    let data = fetch_file_blob(&st, &owner, &name).await;
    match data {
        Some(data) => ok_json(json!({
            "name": name,
            "size": data.len(),
            "data": base64::engine::general_purpose::STANDARD.encode(&data),
        })),
        None => err_json(StatusCode::NOT_FOUND, "file not found"),
    }
}

async fn files_delete(
    State(st): State<WebState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if !safe_filename(&name) {
        return err_json(StatusCode::BAD_REQUEST, "invalid file name");
    }
    let ikey = file_index_key(&email);
    let mut list = files_index(&st.node, &email).await;
    let before = list.len();
    let mut removed_size = 0u64;
    list.retain(|e| {
        if e["name"].as_str() == Some(name.as_str()) {
            removed_size = e["size"].as_u64().unwrap_or(0);
            false
        } else {
            true
        }
    });
    if list.len() == before {
        return err_json(StatusCode::NOT_FOUND, "file not found");
    }
    kv_set(
        &st.node,
        &ikey,
        &serde_json::to_string(&list).unwrap_or("[]".into()),
    )
    .await;
    // физическое удаление: манифест + локальные чанки + best-effort на репликах
    // (пробуем новый хэш-ключ и старый raw-ключ для обратной совместимости)
    let deleted = st
        .node
        .delete_blob("files", &file_blob_key(&email, &name))
        .await
        + st.node
            .delete_blob("files", &format!("file:{email}:{name}"))
            .await;
    {
        let mut db = st.db.lock().await;
        if let Some(a) = db.accounts.get_mut(&email) {
            a.files_used = a.files_used.saturating_sub(removed_size);
        }
        save_db(&st.db_path, &db).await;
    }
    ok_json(json!({ "ok": true, "removed": removed_size, "chunks_deleted": deleted }))
}

/// Категория файла по расширению (для ревью-отчёта).
fn file_type_from_name(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "svg" | "bmp" | "ico" | "heic" | "avif" => {
            "image"
        }
        "mp4" | "mkv" | "webm" | "mov" | "avi" | "flv" | "wmv" | "m4v" => "video",
        "mp3" | "wav" | "flac" | "aac" | "ogg" | "opus" | "m4a" | "mid" | "midi" => "audio",
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp"
        | "rtf" | "txt" | "md" => "document",
        "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "tgz" | "zst" => "archive",
        "rs" | "ts" | "tsx" | "js" | "mjs" | "py" | "go" | "c" | "cpp" | "h" | "hpp" | "java"
        | "rb" | "php" | "sh" | "json" | "yaml" | "yml" | "toml" | "sql" | "html" | "css"
        | "vue" | "jsx" => "code",
        _ => "other",
    }
}

/// Ревью файлового хранилища: список, типы и распределение по нодам сети.
async fn files_review(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let items = files_index(&st.node, &email).await;
    let mut by_node: HashMap<String, (u64, usize)> = HashMap::new();
    let mut by_type: HashMap<String, (u64, usize)> = HashMap::new();
    let mut total_bytes = 0u64;
    let mut id_to_name: HashMap<String, String> = HashMap::new();
    let own_id = hex::encode(st.node.id);
    id_to_name.insert(own_id.clone(), st.node.cfg.name.clone());
    for (name, pid) in &st.node.by_name {
        id_to_name.insert(hex::encode(pid), name.clone());
    }
    let mut files_out: Vec<Value> = Vec::new();
    let mut chunk_budget = 400usize;
    for f in items {
        let fname = f["name"].as_str().unwrap_or("").to_string();
        let fsize = f["size"].as_u64().unwrap_or(0);
        let at = f["at"].as_i64().unwrap_or(0);
        let ftype = file_type_from_name(&fname).to_string();
        total_bytes += fsize;
        by_type.entry(ftype.clone()).or_insert((0, 0)).0 += fsize;
        by_type.entry(ftype.clone()).or_insert((0, 0)).1 += 1;
        // ноды, ответственные за чанки файла (локальный взгляд на k-ближайших)
        let mkey = format!("f:{}", file_blob_key(&email, &fname));
        let mut mstr = st.node.get_local_kv(&mkey).await;
        if mstr.is_none() {
            mstr = st
                .node
                .get_local_kv(&format!("f:file:{email}:{fname}"))
                .await;
        }
        let mut assigned_node: Option<String> = None;
        if let Some(ms) = mstr {
            if let Ok(mv) = serde_json::from_str::<Value>(&ms) {
                if let Some(chunks) = mv["chunks"].as_array() {
                    for c in chunks {
                        if chunk_budget == 0 {
                            break;
                        }
                        chunk_budget -= 1;
                        let cid = c["id"].as_str().unwrap_or("");
                        let clen = c["len"].as_u64().unwrap_or(0);
                        let h = blake3::hash(format!("files:{cid}").as_bytes());
                        let mut target = [0u8; proto::NODEID_LEN];
                        target.copy_from_slice(&h.as_bytes()[..proto::NODEID_LEN]);
                        let closest = st.node.dht_closest_local(&target).await;
                        if let Some(primary) = closest.first() {
                            let nid = hex::encode(primary.id);
                            by_node.entry(nid.clone()).or_insert((0, 0)).0 += clen;
                            by_node.entry(nid.clone()).or_insert((0, 0)).1 += 1;
                            if assigned_node.is_none() {
                                assigned_node = Some(nid);
                            }
                        }
                    }
                }
            }
        }
        files_out.push(json!({
            "name": fname, "size": fsize, "at": iso_date(at), "type": ftype,
            "primary_node": assigned_node,
        }));
    }
    let types: Vec<Value> = by_type
        .iter()
        .map(|(k, (b, c))| json!({ "type": k, "bytes": b, "count": c }))
        .collect();
    let nodes: Vec<Value> = by_node
        .iter()
        .map(|(id, (b, c))| {
            json!({
                "id": id,
                "name": id_to_name.get(id).cloned().unwrap_or_else(|| format!("{}…", &id[..8])),
                "bytes": b,
                "chunks": c,
            })
        })
        .collect();
    ok_json(json!({
        "total_bytes": total_bytes,
        "files": files_out,
        "types": types,
        "nodes": nodes,
    }))
}

// ─────────────────────────────────────────────────────────────
// WEB3 (TON Connect) — регистрация/вход по кошельку
// ─────────────────────────────────────────────────────────────

/// Приведение адреса TON к каноническому raw-хэшу (64 hex).
fn normalize_ton_address(addr: &str) -> String {
    let a = addr.trim();
    if a.len() == 64 && a.chars().all(|c| c.is_ascii_hexdigit()) {
        return a.to_lowercase();
    }
    if a.contains(':') {
        let parts: Vec<&str> = a.split(':').collect();
        if parts.len() == 2 {
            let hex_part = parts[1].trim();
            if hex_part.len() == 64 && hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return hex_part.to_lowercase();
            }
            return parts[1].to_lowercase();
        }
    }
    if a.len() >= 44 {
        let decoded = base64::engine::general_purpose::URL_SAFE
            .decode(a)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(a));
        if let Ok(bytes) = decoded {
            if bytes.len() >= 34 {
                return hex::encode(&bytes[2..34]);
            }
        }
    }
    a.to_lowercase()
}

/// Криптографическая проверка TON Connect v2 proof (Ed25519).
/// Порт из старого backend web3.rs (все варианты подписи).
fn verify_ton_proof_cryptographically(
    address: &str,
    public_key: &str,
    domain: &str,
    length_bytes: u32,
    timestamp: u64,
    payload: &str,
    signature_b64: &str,
) -> bool {
    use ed25519_dalek::Verifier;
    use sha2::Digest;
    let pubkey_hex = public_key
        .strip_prefix("0x")
        .or_else(|| public_key.strip_prefix("0X"))
        .unwrap_or(public_key);
    let Ok(pubkey_bytes) = hex::decode(pubkey_hex) else {
        return false;
    };
    let Ok(pubkey_arr) = <[u8; 32]>::try_from(pubkey_bytes) else {
        return false;
    };
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr) else {
        return false;
    };
    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(signature_b64))
    else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

    let raw_addr = normalize_ton_address(address);
    let Ok(addr_bytes) = hex::decode(&raw_addr) else {
        return false;
    };
    if addr_bytes.len() != 32 {
        return false;
    }
    let workchain: i32 = if address.contains(':') {
        address
            .split(':')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    } else {
        0
    };
    let try_v = |msg: &[u8]| verifying_key.verify(msg, &signature).is_ok();

    // Variant 1: TON Connect v2 spec-go (35 байт signed)
    let mut m = b"ton-proof-item-v2/".to_vec();
    m.extend_from_slice(&workchain.to_be_bytes());
    m.extend_from_slice(&addr_bytes);
    m.extend_from_slice(&length_bytes.to_le_bytes());
    m.extend_from_slice(domain.as_bytes());
    m.extend_from_slice(&timestamp.to_le_bytes());
    m.extend_from_slice(payload.as_bytes());
    let m_hash = Sha256::digest(&m);
    let mut v1 = Vec::new();
    v1.extend_from_slice(&[0xff, 0xff]);
    v1.extend_from_slice(b"ton-connect");
    v1.extend_from_slice(&m_hash);
    if try_v(&v1) {
        return true;
    }
    let v1_hash = Sha256::digest(&v1);
    if try_v(&v1_hash) {
        return true;
    }

    // Variant 2: per-item hashes
    let mut addr_buf = b"ton-proof-item-v2/".to_vec();
    let mut app_address = Vec::new();
    app_address.extend_from_slice(&workchain.to_be_bytes());
    app_address.extend_from_slice(&addr_bytes);
    addr_buf.extend_from_slice(&app_address);
    let h_addr = Sha256::digest(&addr_buf);

    let mut dom_buf = b"ton-proof-item-v2/".to_vec();
    dom_buf.extend_from_slice(&length_bytes.to_le_bytes());
    dom_buf.extend_from_slice(domain.as_bytes());
    let h_dom = Sha256::digest(&dom_buf);

    let mut ts_buf = b"ton-proof-item-v2/".to_vec();
    ts_buf.extend_from_slice(&timestamp.to_le_bytes());
    let h_ts = Sha256::digest(&ts_buf);

    let mut payload_buf = b"ton-proof-item-v2/".to_vec();
    payload_buf.extend_from_slice(payload.as_bytes());
    let h_payload = Sha256::digest(&payload_buf);

    let mut v2_raw = Vec::new();
    v2_raw.extend_from_slice(&[0xff, 0xff]);
    v2_raw.extend_from_slice(b"ton-connect");
    v2_raw.extend_from_slice(&h_addr);
    v2_raw.extend_from_slice(&h_dom);
    v2_raw.extend_from_slice(&h_ts);
    v2_raw.extend_from_slice(&h_payload);
    if try_v(&v2_raw) {
        return true;
    }
    let v2_final = Sha256::digest(&v2_raw);
    if try_v(&v2_final) {
        return true;
    }

    // Variant 4: raw concatenation
    let mut raw_buf = b"ton-proof-item-v2/".to_vec();
    raw_buf.extend_from_slice(&app_address);
    raw_buf.extend_from_slice(&length_bytes.to_le_bytes());
    raw_buf.extend_from_slice(domain.as_bytes());
    raw_buf.extend_from_slice(&timestamp.to_le_bytes());
    raw_buf.extend_from_slice(payload.as_bytes());
    let mut v4 = Vec::new();
    v4.extend_from_slice(&[0xff, 0xff]);
    v4.extend_from_slice(b"ton-connect");
    v4.extend_from_slice(&raw_buf);
    if try_v(&v4) {
        return true;
    }
    let v4_hash = Sha256::digest(&v4);
    try_v(&v4_hash)
}

/// Недавно выданные web3-nonce (список, а не один): иначе повторная выдача/успешный
/// вход подменяли единственный nonce, и уже подписанный кошельком payload переставал
/// совпадать -> «payload does not match issued nonce» при оплате/входе.
const WEB3N_KEY: &str = "web3n_recent";
const WEB3N_TTL_MS: i64 = 10 * 60 * 1000;

fn web3n_parse(raw: Option<String>) -> Vec<Value> {
    raw.and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok())
        .unwrap_or_default()
}

fn web3n_prune(mut list: Vec<Value>, now: i64) -> Vec<Value> {
    list.retain(|e| {
        e["ts"]
            .as_i64()
            .map(|t| now - t < WEB3N_TTL_MS)
            .unwrap_or(false)
    });
    list
}

async fn web3_generate_payload(State(st): State<WebState>) -> Response {
    // Идемпотентность через фиксированный ключ web3n_active: пока выданный nonce не потрачен
    // (<10 мин) — возвращаем ЕГО ЖЕ. Иначе повторный скан кошелька меняет payload →
    // подписанный proof невалиден → "payload does not match issued nonce" (баг при оплате).
    let now = proto::now_ms();
    let mut list = web3n_prune(web3n_parse(st.node.get_local_kv(WEB3N_KEY).await), now);
    // если есть неиспользованный неистёкший nonce — отдаём ЕГО ЖЕ (идемпотентность)
    if let Some(e) = list.iter().find(|e| e["used"].as_bool() != Some(true)) {
        if let Some(salt) = e["salt"].as_str() {
            let tsn = e["ts"].as_i64().unwrap_or(now);
            if !salt.is_empty() && tsn > 0 {
                return ok_json(json!({
                    "payload": { "domain": "infmail.org", "timestamp": tsn, "salt": salt },
                    "reused": true,
                }));
            }
        }
    }
    let ts = now;
    let salt = hex::encode(rand::random::<[u8; 16]>());
    // одноразовый nonce, 10 мин, держим последние 8 (мультивкладка/повторный вход)
    list.push(json!({ "salt": salt, "ts": ts, "used": false }));
    if list.len() > 8 {
        let n = list.len() - 8;
        list.drain(0..n);
    }
    st.node
        .kv_store_local(
            WEB3N_KEY,
            &serde_json::to_string(&list).unwrap_or("[]".into()),
        )
        .await;
    ok_json(json!({
        "payload": {
            "domain": "infmail.org",
            "timestamp": ts,
            "salt": salt,
        }
    }))
}

#[derive(Deserialize)]
struct Web3LoginReq {
    address: String,
    #[allow(dead_code)] // GATE: persisted account field for multi-net rollout
    network: String,
    public_key: String,
    /// proof обязателен только для НОВОГО кошелька (регистрация).
    /// Для уже привязанного (восстановленная сессия, как Fragment) — опционален.
    proof: Option<Web3Proof>,
}

#[derive(Deserialize)]
struct Web3Proof {
    timestamp: u64,
    domain: Web3Domain,
    signature: String,
    payload: String,
}

#[derive(Deserialize)]
struct Web3Domain {
    #[serde(alias = "lengthBytes")]
    length_bytes: u32,
    value: String,
}

async fn web3_login(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<Web3LoginReq>,
) -> Response {
    let ip = client_ip(&headers);
    if rate_limit(&st.login_guard, &format!("w3:{ip}"), 30, 15 * 60 * 1000).await {
        return err_json(
            StatusCode::TOO_MANY_REQUESTS,
            "too many web3 login attempts",
        );
    }
    // КОШЕЛЁК УЖЕ ПРИВЯЗАН? (восстановленная сессия, как Fragment) — вход по адресу без proof.
    // Только для НОВОГО кошелька (нет аккаунта) proof обязателен (доказательство владения).
    let wallet_norm = normalize_ton_address(&req.address);
    let known_wallet = {
        let db = st.db.lock().await;
        db.accounts
            .values()
            .any(|a| a.wallet.as_deref() == Some(wallet_norm.as_str()))
    };
    // verified=true только если владение адресом доказано криптографическим proof
    // (pk привязан к адресу). Путь known_wallet (вход по адресу без proof) — НЕ verified:
    // им можно лишь выбирать УЖЕ привязанные аккаунты, но нельзя РЕГИСТРИРОВАТЬ новые.
    let mut verified = false;
    // nonce сжигаем ТОЛЬКО после успешной проверки подписи (см. ниже)
    let mut burn_salt: Option<String> = None;
    let valid = if known_wallet {
        // известный кошелёк: восстановленная сессия — владение уже доказано ранее.
        // Не требуем подпись заново (как Fragment). verified=false (см. выше).
        true
    } else if let Some(pr) = req.proof.as_ref() {
        // новый кошелёк: полная криптографическая проверка proof
        verified = true;
        let domain_ok = pr
            .domain
            .value
            .trim()
            .trim_matches('"')
            .eq_ignore_ascii_case("infmail.org");
        if !domain_ok {
            return err_json(StatusCode::UNAUTHORIZED, "invalid proof domain");
        }
        if proto::now_ms().abs_diff(pr.timestamp as i64 * 1000) > 10 * 60 * 1000 {
            return err_json(StatusCode::UNAUTHORIZED, "proof expired");
        }
        // анти-replay: payload должен содержать выданный nonce (web3n_active)
        let p = pr.payload.trim_matches('"').to_string();
        let issued: Option<String> = serde_json::from_str::<Value>(&p)
            .ok()
            .and_then(|v| v["salt"].as_str().map(String::from))
            .or_else(|| Some(p.clone()));
        let payload_ok = match issued {
            Some(salt)
                if !salt.is_empty()
                    && salt.len() <= 64
                    && salt.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                let now = proto::now_ms();
                let list = web3n_prune(web3n_parse(st.node.get_local_kv(WEB3N_KEY).await), now);
                // ВАЖНО: здесь только ПРОВЕРЯЕМ, не сжигая nonce. Сжигаем после успешной
                // проверки подписи: иначе любая неудачная попытка (или ошибка в UI)
                // съедала nonce, и повтор с тем же подписанным payload давал
                // «payload does not match issued nonce».
                let mut ok = false;
                for e in list.iter() {
                    if e["salt"].as_str() == Some(salt.as_str())
                        && e["used"].as_bool() != Some(true)
                    {
                        ok = true;
                        break;
                    }
                }
                if !ok {
                    // обратная совместимость: старый одиночный ключ web3n_active
                    if let Some(raw) = st.node.get_local_kv("web3n_active").await {
                        if raw.split_once('|').map(|(_, s)| s == salt).unwrap_or(false) {
                            st.node.kv_remove_local("web3n_active").await;
                            ok = true;
                        }
                    }
                }
                if ok {
                    burn_salt = Some(salt.clone());
                }
                ok
            }
            _ => false,
        };
        if !payload_ok {
            return err_json(
                StatusCode::UNAUTHORIZED,
                "payload does not match issued nonce",
            );
        }
        let req_address = req.address.clone();
        let req_pubkey = req.public_key.clone();
        let req_domain = pr.domain.value.clone();
        let req_len = pr.domain.length_bytes;
        let req_ts = pr.timestamp;
        let req_payload = pr.payload.clone();
        let req_sig = pr.signature.clone();
        tokio::task::spawn_blocking(move || {
            verify_ton_proof_cryptographically(
                &req_address,
                &req_pubkey,
                &req_domain,
                req_len,
                req_ts,
                &req_payload,
                &req_sig,
            )
        })
        .await
        .unwrap_or(false)
    } else {
        false
    };
    if !valid {
        return err_json(StatusCode::UNAUTHORIZED, "TON proof not verified");
    }
    // подпись подтверждена — теперь nonce одноразовый (защита от replay)
    if let Some(s) = burn_salt {
        let now = proto::now_ms();
        let mut list = web3n_prune(web3n_parse(st.node.get_local_kv(WEB3N_KEY).await), now);
        for e in list.iter_mut() {
            if e["salt"].as_str() == Some(s.as_str()) {
                e["used"] = json!(true);
            }
        }
        st.node
            .kv_store_local(
                WEB3N_KEY,
                &serde_json::to_string(&list).unwrap_or("[]".into()),
            )
            .await;
        st.node.kv_remove_local("web3n_active").await;
    }
    let wallet = normalize_ton_address(&req.address);
    let pk_norm = req
        .public_key
        .strip_prefix("0x")
        .or_else(|| req.public_key.strip_prefix("0X"))
        .unwrap_or(&req.public_key)
        .to_lowercase();
    let db = st.db.lock().await;
    // Привязка public_key ↔ address: если у аккаунта уже сохранён wallet_pub —
    // допускаем вход только если public_key из proof совпадает с ним.
    // Иначе (новый кошелёк) — аккаунты не отдаём, требуется регистрация.
    let accounts: Vec<Value> = db
        .accounts
        .iter()
        .filter(|(_, a)| a.wallet.as_deref() == Some(wallet.as_str()))
        .filter(|(_, a)| {
            match a.wallet_pub.as_deref() {
                Some(pub_saved) => pub_saved.eq_ignore_ascii_case(&pk_norm),
                // legacy-аккаунт без сохранённого ключа: вход через web3 не разрешаем
                // (не можем подтвердить владение) — только паролем.
                None => false,
            }
        })
        .map(|(e, a)| json!({ "email": e, "type": if a.ed_pub.is_some() { "nft" } else { "zk" } }))
        .collect();
    drop(db);
    // если кошелёк известен, но владение не подтверждено — отдаём признак для UI
    let known_wallet = {
        let db = st.db.lock().await;
        db.accounts
            .values()
            .any(|a| a.wallet.as_deref() == Some(wallet.as_str()))
    };
    if known_wallet && accounts.is_empty() {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "wallet not linked to this account — web3 login is only possible for the owner",
        );
    }
    ok_json(json!({
        "temp_token": jwt_sign_web3(&st.jwt_secret, &wallet, &pk_norm, verified, 600),
        "accounts": accounts,
    }))
}

#[derive(Deserialize)]
struct RegisterWeb3Req {
    email: String,
    #[allow(dead_code)] // GATE: persisted web3 identity, read by login flows
    wallet_address: String,
}

async fn register_web3(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<RegisterWeb3Req>,
) -> Response {
    // регистрация web3 требует temp_token (кошелёк доказал владение) — принимаем
    // и его, и сессию (комментарий всегда это требовал, а код требовал сессию).
    let wallet = match web3_auth(&st, &headers).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    // извлекаем подтверждённый public_key из temp_token (связка ключа и адреса)
    let (wallet_pub, verified) = match jwt_verify_pk(&st.jwt_secret, bearer_token(&headers)) {
        Some((_, Some(pk), v)) => (Some(pk.to_lowercase()), v),
        _ => (None, false),
    };
    // MED-1 фикс: регистрация нового аккаунта допустима ТОЛЬКО если кошелёк доказал
    // владение адресом криптографическим proof (verified). Псевдо-вход по чужому адресу
    // (стелс-сквоттинг) даёт verified=false и здесь отклоняется.
    if !verified {
        return err_json(
            StatusCode::FORBIDDEN,
            "wallet ownership not proven — re-connect your wallet and sign to register",
        );
    }
    let email = norm_email(&req.email);
    if !valid_email(&email) {
        return err_json(StatusCode::BAD_REQUEST, "invalid email (only @infmail.org)");
    }
    let db = st.db.lock().await;
    if db.accounts.contains_key(&email) {
        return err_json(StatusCode::CONFLICT, "this address is already registered");
    }
    // email не должен быть алиасом другого аккаунта (иначе перехват почты алиаса)
    if let Some(owner) = resolve_db_email(&db, &email) {
        if owner != email {
            return err_json(
                StatusCode::CONFLICT,
                "this address is an alias of another account",
            );
        }
    }
    // защита от захвата: email уже занят в DHT-реестре (зарегистрирован через CLI/иную ноду)
    if registry_get(&st.node, &email).await.is_some() {
        return err_json(
            StatusCode::CONFLICT,
            "this address is already registered on the network",
        );
    }
    // ПРОВЕРКА ОПЛАТЫ/ВЛАДЕНИЯ: web3-аккаунт создаётся ТОЛЬКО если email зарегистрирован
    // в TON Registry И владелец (getOwnerByHash) == текущий кошелёк (MED-2 фикс: «стек непуст»
    // не доказывал владельца — теперь проверяем реальный адрес владельца on-chain).
    {
        if !crate::blockchain::check_registry_ownership(&email, &wallet) {
            return err_json(
                StatusCode::PAYMENT_REQUIRED,
                "email is not owned by this wallet on the blockchain — register the email to your wallet first",
            );
        }
        // та же проверка цены тира, что и в опросе (self-attested usernameLength)
        if !crate::blockchain::verify_registry_payment(&email, "", &wallet) {
            return err_json(
                StatusCode::PAYMENT_REQUIRED,
                "ownership found but no sufficient registration payment — pay the tier price first",
            );
        }
    }
    create_web3_account(&st, &email, &wallet, &wallet_pub).await;
    let device = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .chars()
        .take(64)
        .collect::<String>();
    let token = issue_session(&st, &email, &device, &client_ip(&headers)).await;
    ok_with_session(
        json!({ "token": token.clone(), "email": email }),
        &token,
        7 * 24 * 3600,
    )
}

#[derive(Deserialize)]
struct SelectAccountReq {
    email: String,
}

async fn web3_select_account(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<SelectAccountReq>,
) -> Response {
    let wallet = match web3_auth(&st, &headers).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let email = norm_email(&req.email);
    // подтверждённый public_key из temp_token (связка ключа и адреса).
    // ВАЖНО (HIGH-фикс): требовать verified=true — только тогда владение адресом доказано
    // криптографическим proof (pk привязан к адресу). Иначе злоумышленник, знающий публичные
    // wallet+wallet_pub жертвы, захватывает ящик (вход по адресу без подписи).
    let (pk, verified) = match jwt_verify_pk(&st.jwt_secret, bearer_token(&headers)) {
        Some((_, p, v)) => (p, v),
        None => (None, false),
    };
    if !verified {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "wallet ownership not proven — sign with your wallet and try again",
        );
    }
    let db = st.db.lock().await;
    let owned = db
        .accounts
        .get(&email)
        .map(|a| {
            // кошелёк совпадает И (если ключ сохранён) public_key совпадает с ним
            let wallet_ok = a.wallet.as_deref() == Some(wallet.as_str());
            let pk_ok = match (a.wallet_pub.as_deref(), pk.as_deref()) {
                (Some(saved), Some(got)) => saved.eq_ignore_ascii_case(got),
                // legacy-аккаунт без сохранённого ключа: не допускаем (владение не подтверждено)
                _ => false,
            };
            wallet_ok && pk_ok
        })
        .unwrap_or(false);
    drop(db);
    if !owned {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "account does not belong to this wallet",
        );
    }
    let device = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .chars()
        .take(64)
        .collect::<String>();
    let token = issue_session(&st, &email, &device, &client_ip(&headers)).await;
    ok_with_session(json!({ "token": token.clone() }), &token, 7 * 24 * 3600)
}

/// Деривация ключей шифрования от кошелька (П.3): x_pub + эпоха владельца.
/// POST /api/v1/web3/derive-keys — письма шифруются ключом, детерминированно
/// выведенным из кошелька. Смена владельца → новая эпоха.
///
/// Два режима:
///  - { wallet_ed_pub } — служебный, из ПУБЛИЧНОГО ключа (НЕ для шифрования писем:
///    приватный x25519 был бы вычислим любым). Полезен для эпохи/метки владельца.
///  - { signature } — БЕЗОПАСНАЯ ветка П.3: x_pub шифрования выводится из ПОДПИСИ
///    кошелька (секретна). Бэкенд хранит x_pub, браузер — приватный x25519 из той же
///    подписи. Смена кошелька → другая подпись → другой ключ (эпоха).
#[derive(Deserialize)]
struct DeriveKeysReq {
    wallet_ed_pub: Option<String>,
    signature: Option<String>,
}

async fn web3_derive_keys(Json(req): Json<DeriveKeysReq>) -> Response {
    if let Some(sig) = req.signature {
        let resp = crate::nft::derive::derive_response_from_signature(&sig);
        return if resp["ok"].as_bool().unwrap_or(false) {
            ok_json(resp)
        } else {
            err_json(
                StatusCode::BAD_REQUEST,
                resp["error"]
                    .as_str()
                    .unwrap_or("derive failed")
                    .to_string(),
            )
        };
    }
    if let Some(wallet_ed_pub) = req.wallet_ed_pub {
        let resp = crate::nft::derive::derive_response(&wallet_ed_pub);
        return if resp["ok"].as_bool().unwrap_or(false) {
            ok_json(resp)
        } else {
            err_json(
                StatusCode::BAD_REQUEST,
                resp["error"]
                    .as_str()
                    .unwrap_or("derive failed")
                    .to_string(),
            )
        };
    }
    err_json(
        StatusCode::BAD_REQUEST,
        "provide either 'signature' or 'wallet_ed_pub'".to_string(),
    )
}

/// Сохранить производный x_pub (от подписи кошелька) на бэкенде как x_pub аккаунта.
/// POST /api/v1/web3/save-keys { x_pub, epoch, signature } — auth обязателен.
/// После этого входящая внешняя почта шифруется на этот x_pub (см. keys_get).
/// Смена кошелька → другая подпись → другой x_pub → старые письма нечитаемы (П3 эпоха).
#[derive(Deserialize)]
struct SaveKeysReq {
    x_pub: String,
    epoch: String,
    signature: String,
}

async fn web3_save_keys(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<SaveKeysReq>,
) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // Валидация: x_pub — hex 32 байта (64 символа); signature — hex 64 байта (128 символов).
    let x_pub_bytes = match hex::decode(&req.x_pub) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return err_json(
                StatusCode::BAD_REQUEST,
                "invalid x_pub (must be 32 bytes hex)".to_string(),
            )
        }
    };
    let _sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return err_json(
                StatusCode::BAD_REQUEST,
                "invalid signature (must be 64 bytes hex)".to_string(),
            )
        }
    };
    // Перепроверяем: производный x_pub должен соответствовать подписи (защита от подмены).
    let derived = crate::nft::derive::derive_x_pub_from_signature(&req.signature)
        .map_err(|e| err_json(StatusCode::BAD_REQUEST, e));
    let derived = match derived {
        Ok(x) => x,
        Err(r) => return r,
    };
    if derived != req.x_pub {
        return err_json(
            StatusCode::BAD_REQUEST,
            "x_pub does not match signature (must be derived via /derive-keys)".to_string(),
        );
    }
    let mut db = st.db.lock().await;
    if let Some(a) = db.accounts.get_mut(&email) {
        a.x_pub = Some(hex::encode(&x_pub_bytes));
        // epoch пишем в e2e_secret (служебный, 32 байта hex) — не используется для крипто,
        // но позволяет UI/мониторингу видеть эпоху при необходимости.
        a.e2e_secret = Some(req.epoch.clone());
    } else {
        return err_json(StatusCode::NOT_FOUND, "account not found".to_string());
    }
    save_db(&st.db_path, &db).await;
    drop(db);
    ok_json(json!({ "ok": true, "epoch": req.epoch }))
}

/// Сканировать NFT-коллекцию и вернуть NFT-почты, принадлежащие кошельку.
/// GET /api/v1/web3/wallet-nfts?wallet={addr} — при подключении кошелька предлагаем
/// добавить его NFT-почты (пункт "сканирование кошелька и контракта").
async fn web3_wallet_nfts(State(st): State<WebState>, headers: HeaderMap) -> Response {
    // auth обязателен — скан NFT без авторизации был бы открытым (DoS + утечка почт)
    let wallet = match auth_email(&st, &headers).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    // rate-limit: скан дорогой (запросы к TON) → 10/мин
    let ip = client_ip(&headers);
    if rate_limit(&st.nft_guard, &format!("wallet_nfts:{ip}"), 10, 60_000).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "too many requests, wait");
    }
    let data_dir = st.node.data_dir.to_str().unwrap_or(".").to_string();
    let wallet_scan = wallet.clone();
    // сканируем токены коллекции (с лимитом в scan_nfts_by_wallet)
    let token_ids =
        tokio::task::spawn_blocking(move || crate::blockchain::scan_nfts_by_wallet(&wallet_scan))
            .await
            .unwrap_or_default();
    let mut nfts = Vec::new();
    for tid in token_ids {
        if let Some(meta) = crate::nft::nft::load_nft_meta(tid, &data_dir) {
            if let Some(email) = meta["email"].as_str() {
                nfts.push(json!({
                    "token_id": tid,
                    "email": email,
                    "name": meta["name"].as_str().unwrap_or(email),
                }));
            }
        }
    }
    ok_json(json!({
        "wallet": wallet,
        "nfts": nfts,
        "count": nfts.len(),
    }))
}

async fn web3_recover_email(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<SelectAccountReq>,
) -> Response {
    let wallet = match auth_email(&st, &headers).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let email = norm_email(&req.email);
    // HIGH-фикс: подтверждение владения email кошельком только при verified proof + совпадение
    // public_key (иначе знание публичного wallet жертвы = захват ящика).
    let (pk, verified) = match jwt_verify_pk(&st.jwt_secret, bearer_token(&headers)) {
        Some((_, p, v)) => (p, v),
        None => (None, false),
    };
    if !verified {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "wallet ownership not proven — sign with your wallet and try again",
        );
    }
    let db = st.db.lock().await;
    let owned = db
        .accounts
        .get(&email)
        .map(|a| {
            let wallet_ok = a.wallet.as_deref() == Some(wallet.as_str());
            let pk_ok = match (a.wallet_pub.as_deref(), pk.as_deref()) {
                (Some(saved), Some(got)) => saved.eq_ignore_ascii_case(got),
                _ => false,
            };
            wallet_ok && pk_ok
        })
        .unwrap_or(false);
    drop(db);
    if owned {
        ok_json(json!({ "ok": true, "email": email }))
    } else {
        err_json(StatusCode::NOT_FOUND, "no account for this wallet")
    }
}

// ─────────────────────────────────────────────────────────────
// Внутренние уведомления (верификация, коды, системные письма)
// ─────────────────────────────────────────────────────────────

/// Отправить письмо ПРЯМО в ящик юзера (без SMTP/MX) — мгновенно, для
/// «мы прислали вам письмо» (подтверждение почты, код входа, уведомления).
pub async fn internal_notify(node: &Arc<Node>, email: &str, subject: &str, body: &str) {
    let at = proto::now_ms();
    let id = hex::encode(
        blake3::hash(format!("{email}:notify:{at}:{}", rand::random::<u64>()).as_bytes())
            .as_bytes(),
    );
    let envelope = json!({
        "sender": "infmail@infmail.org",
        "to": email,
        "at": at,
        "subject": subject,
        "body": body,
    })
    .to_string()
    .into_bytes();
    let name = format!("mail:{id}");
    node.store_blob("mail", &name, &envelope).await;
    let key = format!("mail:{email}:index");
    let mut list: Vec<String> = match node.get_local_kv(&key).await {
        Some(s) => serde_json::from_str(&s).unwrap_or_default(),
        None => Vec::new(),
    };
    if !list.iter().any(|x| x == &id) {
        list.push(id.clone());
    }
    node.kv_store_local(&key, &serde_json::to_string(&list).unwrap_or("[]".into()))
        .await;
}

/// Web3: сохранить intent регистрации (после проверки proof в /web3/login).
#[derive(Deserialize)]
struct SaveIntentReq {
    email: String,
    #[allow(dead_code)] // GATE: persisted TON proof blob for paymaster flow
    ton_proof: Value,
}

async fn web3_save_intent(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<SaveIntentReq>,
) -> Response {
    let wallet = match web3_auth(&st, &headers).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let email = norm_email(&req.email);
    if !valid_email(&email) {
        return err_json(StatusCode::BAD_REQUEST, "invalid email (only @infmail.org)");
    }
    let db = st.db.lock().await;
    if db.accounts.contains_key(&email) {
        return err_json(StatusCode::CONFLICT, "this address is already registered");
    }
    // email не должен быть алиасом другого аккаунта (иначе перехват почты алиаса)
    if let Some(owner) = resolve_db_email(&db, &email) {
        if owner != email {
            return err_json(
                StatusCode::CONFLICT,
                "this address is an alias of another account",
            );
        }
    }
    if registry_get(&st.node, &email).await.is_some() {
        return err_json(
            StatusCode::CONFLICT,
            "this address is already registered on the network",
        );
    }
    // Шаг ДО оплаты: проверяем только свободу адреса и крипто-владение кошельком
    // (verified). Аккаунт НЕ создаём — иначе бесплатные аккаунты без оплаты.
    // Создание — в poll_activation, когда контракт подтвердит регистрацию.
    let verified = match jwt_verify_pk(&st.jwt_secret, bearer_token(&headers)) {
        Some((_, _, v)) => v,
        _ => false,
    };
    if !verified {
        return err_json(
            StatusCode::FORBIDDEN,
            "wallet ownership not proven — re-connect your wallet and sign",
        );
    }
    // Уже оплачен этим кошельком ранее (страница была закрыта до финализации)?
    // Фронт тогда пропустит повторную отправку и сразу перейдёт к опросу.
    let owned = crate::blockchain::check_registry_ownership(&email, &wallet);
    ok_json(json!({ "ok": true, "email": email, "owned": owned }))
}

/// Web3: проверить активацию (аккаунт создан для кошелька).
/// Авторизация web3-потока: сессия ИЛИ свежий temp-токен (jwt_verify_pk).
/// Поток оплаты/регистрации идёт до создания сессии — требовать строго сессию
/// здесь значит 401 на каждый запрос (наблюдалось: «Сессия не принята сервером»
/// при оплате web3-аккаунта, затем повтор со сожжённым proof).
async fn web3_auth(st: &WebState, headers: &HeaderMap) -> Result<String, Response> {
    match auth_email(st, headers).await {
        Ok(w) => Ok(w),
        Err(_) => match jwt_verify_pk(&st.jwt_secret, bearer_token(headers)) {
            Some((sub, _, _)) => Ok(sub),
            None => Err(err_unauth("session required")),
        },
    }
}

/// Создать web3-аккаунт: вставка в базу + приветственное письмо + сохранение.
/// Вызывать ТОЛЬКО после проверки владения on-chain (getOwnerByHash == кошелёк).
async fn create_web3_account(
    st: &WebState,
    email: &str,
    wallet: &str,
    wallet_pub: &Option<String>,
) {
    let acc = Account {
        pw_hash: String::new(),
        created_ms: proto::now_ms(),
        quota_limit: DEFAULT_QUOTA,
        bytes_used: 0,
        x_pub: None,
        ed_pub: None,
        enc_priv: None,
        aliases: Vec::new(),
        file_quota_limit: default_file_quota(),
        files_used: 0,
        smtp_pass: None,
        wallet: Some(wallet.to_string()),
        wallet_pub: wallet_pub.clone(),
        e2e_secret: None,
        files_key_secret: None,
        plan: "free".into(),
        paid_until_ms: 0,
        totp_secret: None,
        totp_enabled: false,
        backup_codes: Vec::new(),
        backup_codes_enc: Vec::new(),
        trusted_email: None,
        pending_email: None,
        sessions: Vec::new(),
        session_epoch: 0,
        signature: None,
    };
    let mut db = st.db.lock().await;
    // LOW-6: атомарный check-then-insert — два параллельных опроса (даблклик
    // "Verify again", два девайса) не плодят двойное создание + двойной welcome
    if let Some(existing) = db.accounts.get(email) {
        if existing.wallet.as_deref() == Some(wallet) {
            return;
        }
    }
    db.accounts.insert(email.to_string(), acc);
    send_welcome_mail(st, email).await;
    save_db(&st.db_path, &db).await;
}

async fn web3_poll_activation(
    State(st): State<WebState>,
    headers: HeaderMap,
    query: axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let wallet = match web3_auth(&st, &headers).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let email = query
        .get("email")
        .map(|e| norm_email(e))
        .unwrap_or_default();
    let active = {
        let db = st.db.lock().await;
        db.accounts
            .get(&email)
            .map(|a| a.wallet.as_deref() == Some(wallet.as_str()))
            .unwrap_or(false)
    };
    if active {
        return ok_json(json!({ "status": "active" }));
    }
    // Аккаунта ещё нет — проверяем, подтвердил ли контракт регистрацию и
    // владелец ли это нашего кошелька. Только verified-токен (proof-привязка),
    // иначе чужой temp-токен мог бы забрать чужой оплаченный адрес.
    let (wallet_pub, verified) = match jwt_verify_pk(&st.jwt_secret, bearer_token(&headers)) {
        Some((_, pk, v)) => (pk.map(|s| s.to_lowercase()), v),
        _ => (None, false),
    };
    if !verified {
        return ok_json(json!({ "status": "pending" }));
    }
    // Адрес могли занять, пока шла оплата, — перепроверяем конфликты.
    {
        let db = st.db.lock().await;
        if db.accounts.contains_key(&email) {
            return ok_json(json!({ "status": "taken" }));
        }
        if let Some(owner) = resolve_db_email(&db, &email) {
            if owner != email {
                return ok_json(json!({ "status": "taken" }));
            }
        }
    }
    if registry_get(&st.node, &email).await.is_some() {
        return ok_json(json!({ "status": "taken" }));
    }
    // MED-2 гарантия сохранена: аккаунт создаётся ТОЛЬКО если on-chain владелец
    // email (getOwnerByHash) == текущий кошелёк. Но теперь проверка ПОСЛЕ оплаты,
    // а не до неё (раньше был тупик «зарегистрируй, чтобы зарегистрировать»).
    if crate::blockchain::check_registry_ownership(&email, &wallet) {
        // Цена тира по РЕАЛЬНОЙ длине имени: закрывает self-attested usernameLength
        // (короткое имя, оплаченное как длинное — контракт пропустит, мы — нет).
        // Ищем RegisterZK с нашим emailHash и суммой >= цены тира в последних 100
        // входящих контракту. Без найденной оплаты — не создаём (pending, не active).
        if !crate::blockchain::verify_registry_payment(&email, "", &wallet) {
            eprintln!("[web3] ownership ok but no sufficient payment found for {email}");
            return ok_json(json!({ "status": "pending" }));
        }
        create_web3_account(&st, &email, &wallet, &wallet_pub).await;
        return ok_json(json!({ "status": "active" }));
    }
    ok_json(json!({ "status": "pending" }))
}

/// 2FA на новой системе не используется (E2E-ключи генерируются без него).
/// Заглушка для совместимости с фронтендом (вход никогда не требует 2FA).
async fn verify_2fa(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Response {
    let email_from_token = match auth_email_2fa(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let ip = client_ip(&headers);
    if rate_limit(
        &st.login_guard,
        &format!("2fa:{email_from_token}"),
        5,
        60 * 1000,
    )
    .await
        || rate_limit(&st.login_guard, &format!("2fai:{ip}"), 20, 60 * 1000).await
    {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "too many 2FA attempts, wait");
    }
    let email_req = req["email"].as_str().unwrap_or("");
    let code = req["code"].as_str().unwrap_or("");
    if email_from_token != email_req {
        return err_json(StatusCode::BAD_REQUEST, "email does not match");
    }
    let now = proto::now_ms() / 1000;
    let db = st.db.lock().await;
    let acc = match db.accounts.get(email_req) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    if !acc.totp_enabled {
        return err_json(StatusCode::BAD_REQUEST, "2FA not enabled");
    }
    let secret = acc.totp_secret.clone().unwrap_or_default();
    let totp_ok = infnode::totp::verify_totp(&secret, code, now);
    let hash = sha256_hex(code);
    let is_backup = acc.backup_codes.iter().any(|h| h == &hash);
    drop(db);
    if !totp_ok && !is_backup {
        return err_json(StatusCode::BAD_REQUEST, "invalid code");
    }
    // бэкап-код одноразовый — списываем использованный
    if is_backup {
        let mut db = st.db.lock().await;
        if let Some(a) = db.accounts.get_mut(email_req) {
            a.backup_codes.retain(|h| h != &hash);
        }
        let _ = save_db(&st.db_path, &db).await;
    }
    let device = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .chars()
        .take(64)
        .collect::<String>();
    let token = issue_session(&st, email_req, &device, &client_ip(&headers)).await;
    ok_with_session(json!({ "token": token.clone() }), &token, 7 * 24 * 3600)
}

async fn nft_verify(State(st): State<WebState>, Path(token_id): Path<String>) -> Response {
    let tid: u64 = match token_id.parse() {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid token_id"),
    };
    // карточка должна существовать на диске (выпущена)
    let data_dir = st.node.data_dir.to_str().unwrap_or(".").to_string();
    let png_bytes = match crate::nft::nft::load_card(tid, &data_dir) {
        Some(b) => b,
        None => return err_json(StatusCode::NOT_FOUND, "card not issued"),
    };
    let collection = std::env::var("NFT_COLLECTION_ADDRESS").unwrap_or_default();
    // ЧЕСТНАЯ проверка: извлекаем LSB-payload из пикселей PNG и проверяем подпись
    // Ed25519 ключом из NFT_SIGNING_SECRET. Без валидной подписи authentic=false.
    let (authentic, verify_detail) = match decode_png_rgba(&png_bytes) {
        Some(pixels) => match crate::nft::lsb::extract(&pixels) {
            Ok((payload, sig)) => match crate::nft::lsb::public_key_hex() {
                Some(pubkey) if crate::nft::lsb::verify(&payload, &sig, &pubkey) => {
                    (true, "lsb-ed25519: signature valid".to_string())
                }
                _ => (false, "lsb-ed25519: bad signature or no pubkey".to_string()),
            },
            Err(e) => (false, format!("lsb-ed25519: extract failed: {e}")),
        },
        None => (false, "lsb-ed25519: png decode failed".to_string()),
    };
    // email и метаданные (name=email, description, attributes) читаем из sidecar payload
    let mut resp = crate::nft::nft::verify_response(tid, "", &collection, &data_dir);
    resp["authentic"] = json!(authentic);
    resp["verifyDetail"] = json!(verify_detail);
    ok_json(resp)
}

/// Декодировать PNG в сырые RGBA-байты (для LSB-извлечения).
/// Возвращает None если декодирование невозможно.
fn decode_png_rgba(png_bytes: &[u8]) -> Option<Vec<u8>> {
    use std::io::Cursor;
    let decoder = png::Decoder::new(Cursor::new(png_bytes));
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    let w = info.width as usize;
    let h = info.height as usize;
    use png::ColorType;
    match info.color_type {
        ColorType::Rgba => Some(buf[..w * h * 4].to_vec()),
        ColorType::Rgb => {
            // LSB вшивается по всем 4 каналам RGBA — достраиваем alpha=255
            let mut rgba = Vec::with_capacity(w * h * 4);
            for px in buf[..w * h * 3].chunks_exact(3) {
                rgba.extend_from_slice(px);
                rgba.push(255);
            }
            Some(rgba)
        }
        _ => None,
    }
}

async fn nft_card(State(st): State<WebState>, Path(token_id): Path<String>) -> Response {
    let tid: u64 = match token_id.parse() {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid token_id"),
    };
    let data_dir = st.node.data_dir.to_str().unwrap_or(".").to_string();
    match crate::nft::nft::load_card(tid, &data_dir) {
        Some(png) => {
            let mut resp = Response::new(axum::body::Body::from(png));
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("image/png"),
            );
            resp
        }
        None => err_json(StatusCode::NOT_FOUND, "card not issued"),
    }
}

/// Метаданные NFT (TEP-64/GetGems): name=email, description, image, attributes.
/// GET /api/v1/nft/{token_id}/meta — off-chain URI для NFT-item в контракте.
async fn nft_meta(State(st): State<WebState>, Path(token_id): Path<String>) -> Response {
    // индексеры (GetGems и др.) могут дописать ".json" к index-path
    let raw_id = token_id.strip_suffix(".json").unwrap_or(&token_id);
    let tid: u64 = match raw_id.parse() {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid token_id"),
    };
    let data_dir = st.node.data_dir.to_str().unwrap_or(".").to_string();
    let meta = match crate::nft::nft::load_nft_meta(tid, &data_dir) {
        Some(m) => m,
        None => return err_json(StatusCode::NOT_FOUND, "card not issued"),
    };
    // контракт коллекции из env
    let collection = std::env::var("NFT_COLLECTION_ADDRESS").unwrap_or_default();
    // стандартный формат NFT-метаданных (GetGems/TON):
    // name, description, image, attributes
    let name = meta["email"]
        .as_str()
        .unwrap_or(&format!("#{tid}"))
        .to_string();
    let description = meta["description"]
        .as_str()
        .unwrap_or("InfMail NFT — Your web3 email name.")
        .to_string();
    let image = format!("https://infmail.org/api/v1/nft/{tid}/card");
    ok_json(json!({
        "name": name,
        "description": description,
        "image": image,
        "collection_address": collection,
        "token_id": tid,
        "attributes": meta["attributes"].as_array().cloned().unwrap_or_default(),
    }))
}

/// Подписка: отметить аккаунт оплаченным (напрямую, для теста/демо; реальная
/// оплата идёт через Storage-контракт — проверка платежа индексером).
#[derive(Deserialize)]
struct SubscribeReq {
    days: Option<i64>,
}

async fn settings_subscribe(
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<SubscribeReq>,
) -> Response {
    // Демо/тестовый эндпоинт: включён только если задан INFNODE_WEB_ALLOW_DEMO_SUBSCRIBE=1.
    // В проде подписка активируется ТОЛЬКО индексером по реальному платежу в Storage-контракт.
    if std::env::var("INFNODE_WEB_ALLOW_DEMO_SUBSCRIBE")
        .map(|v| v != "1")
        .unwrap_or(true)
    {
        return err_json(
            StatusCode::FORBIDDEN,
            "subscription activates only by TON payment",
        );
    }
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let days = req.days.unwrap_or(30);
    let mut db = st.db.lock().await;
    let acc = match db.accounts.get_mut(&email) {
        Some(a) => a,
        None => return err_json(StatusCode::UNAUTHORIZED, "account not found"),
    };
    let now = proto::now_ms();
    let paid_until = (acc.paid_until_ms.max(now)) + days * 24 * 3600 * 1000;
    acc.paid_until_ms = paid_until;
    acc.plan = "paid".into();
    save_db(&st.db_path, &db).await;
    drop(db);
    ok_json(json!({ "ok": true, "plan": "paid", "paid_until_ms": paid_until }))
}

/// Выдать одноразовый owner-nonce для оплаты подписки классического аккаунта.
/// Владелец (после входа) получает этот nonce и указывает его в комментарии
/// `INFMAIL_SUB:<email>:<nonce>` — это доказывает, что платит владелец, а не чужой.
/// Nonce одноразовый и протухает (по умолчанию 60 минут).
async fn settings_subscribe_nonce(State(st): State<WebState>, headers: HeaderMap) -> Response {
    let email = match auth_email(&st, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    // rate-limit (ревью F6): чувствительная ручка без троттлинга
    if rate_limit(&st.login_guard, &format!("subn:{email}"), 30, 600000).await {
        return err_json(
            StatusCode::TOO_MANY_REQUESTS,
            "too many nonce requests, wait",
        );
    }
    // Идемпотентность (проф-поведение): если непотраченный nonce уже выдан и не истёк —
    // возвращаем ЕГО ЖЕ, а не новый. Иначе повторный скан кошелька меняет nonce,
    // старый платёж становится невалидным → "payload does not match issued nonce".
    let key = format!("subnonce:{email}");
    if let Some(existing) = st.node.get_local_kv(&key).await {
        if !existing.trim().is_empty() {
            return ok_json(json!({
                "nonce": existing,
                "comment": format!("INFMAIL_SUB:{email}:{existing}"),
                "expires_in_secs": 3600,
                "reused": true,
            }));
        }
    }
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    // TTL 60 минут — достаточно для перевода в TON-кошелёк
    st.node.kv_store_local(&key, &nonce).await;
    // История выданных nonce: потерянный/разошедшийся платёж с ранее выданным nonce
    // всё равно принимается индексатором (иначе деньги юзера теряются на контракте).
    append_nonce_history(&st.node, &email, &nonce).await;
    ok_json(json!({
        "nonce": nonce,
        "comment": format!("INFMAIL_SUB:{email}:{nonce}"),
        "expires_in_secs": 3600,
    }))
}

/// Хранит историю выданных owner-nonce для email (JSON-массив, до 50 шт).
/// Позволяет индексатору принять платёж, отправленный с nonce, который с тех пор
/// был перевыдан (например, юзер обновил страницу /plan после оплаты).
async fn append_nonce_history(node: &Arc<Node>, email: &str, nonce: &str) {
    let hist_key = format!("subnonce_hist:{email}");
    let hist = node.get_local_kv(&hist_key).await;
    let mut list: Vec<String> = hist
        .as_deref()
        .and_then(|h| serde_json::from_str(h).ok())
        .unwrap_or_default();
    if !list.iter().any(|n| n == nonce) {
        list.push(nonce.to_string());
    }
    if list.len() > 50 {
        let keep = list.len() - 50;
        list.drain(..keep);
    }
    node.kv_store_local(&hist_key, &serde_json::to_string(&list).unwrap_or_default())
        .await;
}

/// Индексер платежей: сканирует Storage-контракт, активирует подписки по комментариям
/// вида `INFMAIL_SUB:<email>:<nonce>`.
async fn check_subscription_payments(
    node: &Arc<Node>,
    db: &Arc<Mutex<AccountsDb>>,
    db_path: &PathBuf,
) -> Result<()> {
    let storage = std::env::var("STORAGE_CONTRACT_ADDRESS").unwrap_or_default();
    if storage.is_empty() {
        return Ok(());
    }
    let storage2 = storage.clone();
    let payments = tokio::task::spawn_blocking(move || {
        crate::blockchain::get_payment_comments(&storage2, 1000)
    })
    .await
    .unwrap_or_default();
    if payments.is_empty() {
        return Ok(());
    }
    // минимальная сумма подписки (в TON). По умолчанию 0.5 TON ≈ $1 (SUB_MIN_TON env).
    let min_ton = std::env::var("INFNODE_SUB_MIN_TON")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.5);
    let min_nanoton = (min_ton * 1e9) as u64;

    let mut db = db.lock().await;
    let mut activated = 0usize;
    // курсор: не обрабатываем транзакции, уже виденные в прошлых раундах
    // (TON Center отдаёт свежие первыми; tx_hash уникален и служит идентификатором)
    let mut newest_tx: Option<String> = None;
    // ВАЖНО: НЕ делаем break по курсору. Платёж может оказаться СТАРШЕ курсора
    // (курсор продвинулся на более свежую активацию), если он был SKIPPED в прошлых
    // раундах (напр. не было валидного nonce). Если break по курсору — такой платёж
    // теряется навсегда, хотя деньги на контракте. Обрабатываем ВСЕ транзакции,
    // дедупликация — через processed_payments (не активируем дважды).
    for (sender, value, comment, tx_hash) in payments {
        if newest_tx.is_none() && !tx_hash.is_empty() {
            newest_tx = Some(tx_hash);
        }
        let Some(rest) = comment.strip_prefix("INFMAIL_SUB:") else {
            continue;
        };
        if db.processed_payments.iter().any(|p| p == &comment) {
            continue;
        }
        // формат: <email>:<nonce>
        let parts: Vec<&str> = rest.split(':').collect();
        let email = norm_email(parts.first().copied().unwrap_or(""));
        let nonce = parts.get(1).copied().unwrap_or("");
        if !valid_email(&email) {
            continue;
        }
        // проверка суммы: платёж ниже порога не активирует подписку
        if value < min_nanoton {
            eprintln!(
                "[web] payment for {email} SKIPPED: {:.4} TON < min {:.4} TON (comment {})",
                value as f64 / 1e9,
                min_ton,
                comment
            );
            continue;
        }
        if let Some(acc) = db.accounts.get_mut(&email) {
            // web3-аккаунт: подписку активирует только платёж С привязанного кошелька аккаунта.
            // Классический аккаунт (wallet=None): требуется одноразовый owner-nonce, выданный
            // бэкендом владельцу при входе (GET /settings/subscribe-nonce). Иначе любой, кто знает
            // email, мог бы оплатить/продлить чужую подписку. Это доказывает владение аккаунтом.
            if let Some(bound) = acc.wallet.clone() {
                // sender из TON Center — сырой адрес (EQ...); acc.wallet — нормализованный hex.
                // Сравниваем в ЕДИНОМ формате (normalize_ton_address), иначе платёж от
                // привязанного кошелька отклоняется ("wallet != bound").
                let sender_norm = normalize_ton_address(&sender);
                if !sender_norm.eq_ignore_ascii_case(&bound) {
                    eprintln!(
                        "[web] payment for {email} SKIPPED: wallet {sender_norm} != bound {bound} (comment {})",
                        comment
                    );
                    continue;
                }
            } else {
                // классический аккаунт: проверяем owner-nonce.
                // Nonce одноразовый и одноразово используется, НО платёж, отправленный с
                // РАНЕЕ выданным nonce (который с тех пор был перевыдан, напр. юзер обновил
                // /plan после оплаты), тоже принимается — nonce есть в истории subnonce_hist.
                // Иначе деньги юзера теряются на контракте (платёж на блокчейне, подписка нет).
                let expected = node.get_local_kv(&format!("subnonce:{email}")).await;
                let ok_current = expected
                    .map(|e| e.trim() == nonce && !nonce.is_empty())
                    .unwrap_or(false);
                let ok_hist = if ok_current {
                    true
                } else {
                    node.get_local_kv(&format!("subnonce_hist:{email}"))
                        .await
                        .as_deref()
                        .and_then(|h| serde_json::from_str::<Vec<String>>(h).ok())
                        .map(|list| list.iter().any(|n| n == nonce))
                        .unwrap_or(false)
                };
                if !ok_hist {
                    eprintln!(
                        "[web] payment for {email} SKIPPED: no valid owner-nonce (comment {})",
                        comment
                    );
                    continue;
                }
                // одноразовое использование (история остаётся для аудита/восстановления)
                node.kv_remove_local(&format!("subnonce:{email}")).await;
            }
            let now = proto::now_ms();
            // ДИСКРЕТНЫЕ ПАКЕТЫ (как проф сервис) c КРЕДИТОВАНИЕМ переплаты (LOW-2 фикс):
            //   - 1 месяц = 1 порог (0.5 TON) = 30 дней
            //   - 1 год   = 10 × порог (5 TON) = 365 дней (год дешевле)
            // Остаток сверх целых лет не теряется: переплата конвертируется в доп. месяцы.
            let month_nanoton = min_nanoton; // 0.5 TON = 1 месяц
            let year_months: u64 = 10; // 5 TON = 1 год
            let months = value / month_nanoton; // сколько месячных порогов покрывает платёж
            let days = if months > 0 {
                let years = months / year_months; // полные годы (по 365 дней)
                let rem_months = months % year_months; // остаток — по 30 дней/мес
                (years * 365 + rem_months * 30) as i64
            } else {
                0
            };
            if days <= 0 {
                eprintln!(
                    "[web] payment for {email} SKIPPED: below 1 month ({} TON < {} TON)",
                    value as f64 / 1e9,
                    min_ton
                );
                continue;
            }
            acc.paid_until_ms = (acc.paid_until_ms.max(now)) + days * 24 * 3600 * 1000;
            acc.plan = "paid".into();
            db.processed_payments.push(comment.clone());
            activated += 1;
            eprintln!(
                "[web] subscription activated for {email} (Storage payment {:.4} TON -> +{days} days)",
                value as f64 / 1e9
            );
        }
    }
    // продвигаем курсор ТОЛЬКО если реально активировали платёж (activated>0).
    // Иначе (все SKIPPED/не-платёжные) НЕ двигаем курсор — чтобы не пропустить
    // валидные платежи, которые могут стать обрабатываемыми (напр. nonce появится).
    if activated > 0 {
        if let Some(nt) = newest_tx {
            db.last_payment_tx = Some(nt);
        }
        if db.processed_payments.len() > 500 {
            let keep = db.processed_payments.len() - 500;
            db.processed_payments.drain(..keep);
        }
        let _ = save_db(db_path, &db).await;
    }
    let _ = node;
    Ok(())
}

#[cfg(test)]
mod secrets_tests {
    use super::{dec_secret, enc_secret};

    #[test]
    fn enc_dec_roundtrip_and_isolation() {
        let key = [7u8; 32];
        let s = "Sup3rSecret!";
        let e = enc_secret(&key, s);
        assert!(e.starts_with("enc1:"), "должен быть префикс версии");
        assert_eq!(dec_secret(&key, &e).as_deref(), Some(s));
        // чужим ключом не расшифровывается
        assert!(dec_secret(&[9u8; 32], &e).is_none());
        // открытый текст не считается шифртекстом
        assert!(dec_secret(&key, s).is_none());
        // разные шифртексты для одного значения (случайный nonce)
        assert_ne!(enc_secret(&key, s), enc_secret(&key, s));
        // многократный прогон не портит данные
        let e2 = enc_secret(&key, &e);
        assert_eq!(dec_secret(&key, &e2).as_deref(), Some(e.as_str()));
    }
}

#[cfg(test)]
mod mime_tests {
    // Письмо с вложением обязано иметь Content-Type: multipart/*, а не text/plain:
    // иначе Gmail показывает исходник вместо текста (реальный случай с продом).
    use lettre::message::header::ContentType;
    use lettre::message::{Message, MultiPart, SinglePart};

    fn build_external(text: &str, with_attachment: bool) -> Message {
        let from: lettre::Address = "a@infmail.org".parse().unwrap();
        let to: lettre::Address = "b@gmail.com".parse().unwrap();
        let builder = Message::builder()
            .from(lettre::message::Mailbox::new(None, from))
            .to(lettre::message::Mailbox::new(None, to))
            .subject("t");
        if with_attachment {
            let multipart = MultiPart::mixed().singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_PLAIN)
                    .body(text.to_string()),
            );
            builder.multipart(multipart).unwrap()
        } else {
            builder
                .header(ContentType::TEXT_PLAIN)
                .body(text.to_string())
                .unwrap()
        }
    }

    #[test]
    fn attachment_mail_is_multipart_not_plaintext() {
        let msg = build_external("test", true);
        let formatted = msg.formatted();
        let raw = String::from_utf8_lossy(&formatted);
        let ctype = raw
            .lines()
            .find(|l| l.to_lowercase().starts_with("content-type:"))
            .unwrap_or("")
            .to_string();
        assert!(
            ctype.to_lowercase().contains("multipart/mixed"),
            "вложение должно давать multipart/mixed, получили: {ctype}"
        );
        assert!(
            !ctype.to_lowercase().starts_with("content-type: text/plain"),
            "баг: text/plain при multipart-теле — Gmail покажет исходник"
        );
    }

    #[test]
    fn plain_mail_stays_text_plain() {
        let msg = build_external("test", false);
        let formatted = msg.formatted();
        let raw = String::from_utf8_lossy(&formatted);
        let ctype = raw
            .lines()
            .find(|l| l.to_lowercase().starts_with("content-type:"))
            .unwrap_or("")
            .to_string();
        assert!(
            ctype.to_lowercase().starts_with("content-type: text/plain"),
            "письмо без вложений должно остаться text/plain, получили: {ctype}"
        );
    }
}

#[cfg(test)]
mod files_key_tests {
    use super::{files_owner_ek, files_owner_key, files_owner_seed};

    /// M2: the Files key is account-scoped. Same email + different account
    /// secrets must produce unrelated KEM keys, and the key must never be a
    /// function of the node (the helpers take no `Node` argument at all).
    #[test]
    fn files_key_is_derived_from_the_account_secret_not_the_node() {
        let email = "alice@infmail.org";
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];

        let seed_a = files_owner_seed(&a, email);
        let seed_b = files_owner_seed(&b, email);
        assert_eq!(seed_a.len(), infnode::mailbox::KEM_SEED_LEN);
        assert_ne!(
            seed_a, seed_b,
            "two account secrets must not share a Files key"
        );
        assert_ne!(files_owner_ek(&a, email), files_owner_ek(&b, email));
        assert_ne!(files_owner_key(&a, email), files_owner_key(&b, email));

        // Same account secret, different account email: also distinct.
        assert_ne!(
            files_owner_ek(&a, "bob@infmail.org"),
            files_owner_ek(&a, email)
        );
        assert_eq!(
            files_owner_key(&a, email).len(),
            infnode::mailbox::KEM_SEED_LEN * 2
        );
        assert_eq!(
            files_owner_ek(&a, email).len(),
            infnode::mailbox::KEM_EK_LEN * 2
        );
    }
}
