use anyhow::Result;
use base64::Engine;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use infnode::config::NodeConfig;
use infnode::keyring::NodeKeys;
use infnode::node::Node;

#[derive(Parser)]
#[command(
    name = "infnode",
    version,
    about = "Lightweight overlay protocol on QUIC + Ed25519"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Сгенерировать ключи ноды и пример конфига
    Keygen {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Инициализировать ноду: ключи + конфиг с ролью и авто-подключением к валидатору.
    /// Пример: infnode init --role mail --validator 109.107.155.67:9400 --validator-pub <ed_hex>
    /// После init: infnode serve --config node.yaml (или --role для быстрого запуска).
    Init {
        /// рабочая папка ноды (создаст keys/ + node.yaml)
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// роль хранения: mail | files | both (пусто = только сеть)
        #[arg(long)]
        role: Option<String>,
        /// адрес валидатора (endpoints), напр. 109.107.155.67:9400
        #[arg(long)]
        validator: Option<String>,
        /// ed-pub валидатора (hex, без inf1:) — для аутентификации подключения
        #[arg(long)]
        validator_pub: Option<String>,
        /// слушать на этом адресе (default 0.0.0.0:9400)
        #[arg(long, default_value = "0.0.0.0:9400")]
        listen: String,
        /// публичный advertise адрес (для нод за NAT); пусто = listen
        #[arg(long)]
        advertise: Option<String>,
        /// web-интерфейс валидатора (только для role=validator)
        #[arg(long)]
        web_listen: Option<String>,
        /// домен сети (федерация), напр. infmail.org — для DNS TXT подтверждения валидатора
        #[arg(long)]
        domain: Option<String>,
        /// TON-кошелёк владельца ноды (для выплат наград)
        #[arg(long)]
        wallet: Option<String>,
    },
    /// Запустить ноду (сервер + исходящие соединения).
    /// Если конфиг не существует — сгенерирует его с ролью и авто-подключением к валидатору.
    Serve {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        /// роль хранения: mail | files | both | validator (если конфиг ещё не создан)
        #[arg(long)]
        role: Option<String>,
        /// адрес валидатора (если конфиг ещё не создан)
        #[arg(long)]
        validator: Option<String>,
        /// ed-pub валидатора (hex, без inf1:), если конфиг ещё не создан
        #[arg(long)]
        validator_pub: Option<String>,
        /// домен сети (федерация), напр. infmail.org — для DNS TXT подтверждения валидатора
        #[arg(long)]
        domain: Option<String>,
    },
    /// Отправить запрос в сервис удалённой ноды
    Send {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        service: String,
        #[arg(long)]
        data: String,
    },
    /// Пинг удалённой ноды (RTT)
    Ping {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "5")]
        count: u32,
    },
    /// Тест пропускной способности
    Perf {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "1048576")]
        size: usize,
        #[arg(long, default_value = "5")]
        count: u32,
        #[arg(long, default_value = "echo", help = "echo | upload | download")]
        direction: String,
    },
    /// NAT hole punch discovery через удалённую ноду
    Poke {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
    },
    /// Опубликовать сообщение в топик (флуд по mesh)
    PubsubPublish {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        topic: String,
        #[arg(long)]
        data: String,
    },
    /// Подписаться на топик и печатать сообщения N секунд
    PubsubSubscribe {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        topic: String,
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Статус ноды и пиров
    Status {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
    },
    /// InfMail: зарегистрировать почтовый ящик (ключи + реестр в DHT)
    MailRegister {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        email: String,
        #[arg(long, default_value = ".mailkeys")]
        dir: PathBuf,
        #[arg(long)]
        to: String,
    },
    /// InfMail: отправить E2E-письмо
    MailSend {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        from: String,
        #[arg(long)]
        dest: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        body: String,
        #[arg(long, default_value = ".mailkeys")]
        dir: PathBuf,
    },
    /// InfMail: список писем ящика
    MailList {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        email: String,
        #[arg(long, default_value = ".mailkeys")]
        dir: PathBuf,
    },
    /// InfMail: прочитать письмо (расшифровать)
    MailGet {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        id: String,
        #[arg(long, default_value = ".mailkeys")]
        dir: PathBuf,
    },
    /// Storage: положить файл/данные (чанки + репликация + манифест в DHT)
    StoragePut {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value = "files")]
        bucket: String,
    },
    /// Storage: получить файл/данные по имени
    StorageGet {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "files")]
        bucket: String,
    },
    /// DHT: найти k ближайших нод к target
    DhtFind {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        target: String,
    },
    /// DHT: сохранить значение под ключом (репликация на k ближайших)
    DhtStore {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        value: String,
    },
    /// DHT: найти значение по ключу
    DhtGet {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        key: String,
    },
    /// Discovery: найти ноду по её inf1:... через сеть
    Find {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        node: String,
    },
    /// Быстрая сводка ноды: kv, chunks, rewards, payouts (встроенная observability)
    Stats {
        /// data-dir ноды (по умолчанию рядом с конфигом)
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Сгенерировать DNS TXT подтверждение валидатора (федерация).
    /// Пример: infnode announce --domain infmail.org --advertise 109.107.155.67:9400
    Announce {
        /// домен сети (федерации), напр. infmail.org
        #[arg(long)]
        domain: String,
        /// публичный адрес валидатора, напр. 109.107.155.67:9400
        #[arg(long)]
        advertise: String,
        /// путь к node.yaml валидатора (для node_id)
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
    },
    /// Проверить, что DNS TXT домена подтверждает валидатора (node_id).
    /// Пример: infnode verify-validator --domain infmail.org --node-id inf1:...
    VerifyValidator {
        /// домен сети
        #[arg(long)]
        domain: String,
        /// node_id валидатора (inf1:...)
        #[arg(long)]
        node_id: String,
    },
    /// Восстановить валидатора после сноса: подключиться к нодам, синкать KV (dht.sync),
    /// восстановить манифесты/индексы/профили аккаунтов из DHT. Секреты (pw_hash/smtp_pass/e2e_secret)
    /// НЕ реплицируются — их нужно восстановить из бэкапа ключей валидатора (keys/).
    /// Пример: infnode restore --config node.yaml
    Restore {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
    },
    /// Аудит kv.json через Zig FFI (быстрая статистика)
    AuditKv {
        /// Путь к kv.json (по умолчанию ./kv.json относительно конфига)
        #[arg(long)]
        kv: Option<PathBuf>,
        /// Поиск ключей по подстроке
        #[arg(long)]
        find: Option<String>,
    },
    /// Консенсус: мастер считает хэш состояния, запрашивает подписи у валидаторов (validators),
    /// проверяет кворум ceil(2/3·N) и пишет consensus.json.
    /// При 1 валидаторе мастер подписывает сам (1 из 1); при 3 — нужны 2 из 3.
    Consensus {
        /// конфиг (node.yaml) мастера
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
        /// только посчитать хэш состояния (без запроса подписей)
        #[arg(long)]
        hash_only: bool,
    },
}

fn load(cfg: &Path) -> Result<(NodeConfig, NodeKeys, PathBuf, PathBuf)> {
    let cfg_obj = infnode::config::load(cfg)?;
    let keys_dir = cfg
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("keys");
    let keys = NodeKeys::load(&keys_dir)?;
    let data_dir = cfg
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();
    Ok((cfg_obj, keys, data_dir, cfg.to_path_buf()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { dir } => {
            // не перезаписываем существующие ключи (иначе реран генерирует новые)
            let keys = if dir.join("keys").join("identity.key").exists() {
                NodeKeys::load(&dir.join("keys"))?
            } else {
                let k = NodeKeys::generate();
                k.save(&dir.join("keys"))?;
                k
            };
            let name = dir
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "node".into());
            let cfg = NodeConfig {
                name,
                listen: "0.0.0.0:9400".into(),
                client_listen: None,
                advertise: None,
                peers: vec![],
                allow_unknown: false,
                unknown_allow: vec![],
                metrics_listen: None,
                log_level: Some(2),
                roles: Default::default(),
                outbox_ttl_secs: 3600,
                storage_roles: vec![],
                validators: vec![],
                domain: None,
                web_listen: None,
                web_static: None,
                wallet: None,
            };
            let cfg_path = dir.join("node.yaml");
            if !cfg_path.exists() {
                infnode::config::save(&cfg_path, &cfg)?;
            }
            println!("=== InfNode node ===");
            println!("node_id: {}", keys.id_hex());
            println!("ed_pub : {}", keys.ed_hex());
            println!("x_pub  : {}", keys.x_hex());
            println!("keys   : {}/keys", dir.display());
            println!("config : {}", cfg_path.display());
        }
        Cmd::Init { dir, role, validator, validator_pub, listen, advertise, web_listen, domain, wallet } => {
            // node_id валидатора = blake3(ed_pub)[..NODEID_LEN]. Если ed_pub не задан —
            // используется TOFU (наш ключ как placeholder, Node заменит при первом контакте?).
            // На практике: без ed_pub подключение не пройдёт авторизацию — выведем предупреждение.
            fn ed_pub_to_id(ed_hex: &str, keys: &NodeKeys) -> String {
                if ed_hex.is_empty() {
                    return keys.id_hex(); // placeholder; чел должен указать validator-pub
                }
                let bytes = hex::decode(ed_hex).unwrap_or_default();
                let h = blake3::hash(&bytes);
                let mut id = [0u8; infnode::proto::NODEID_LEN];
                id.copy_from_slice(&h.as_bytes()[..infnode::proto::NODEID_LEN]);
                format!("inf1:{}", hex::encode(id))
            }
            std::fs::create_dir_all(&dir).ok();
            // ключи (не перезаписываем существующие)
            let keys = if dir.join("keys").join("identity.key").exists() {
                NodeKeys::load(&dir.join("keys"))?
            } else {
                let k = NodeKeys::generate();
                k.save(&dir.join("keys"))?;
                k
            };
            let name = dir
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "node".into());

            // роль хранения
            let storage_roles: Vec<String> = match role.as_deref() {
                Some("mail") => vec!["mail".into()],
                Some("files") => vec!["files".into()],
                Some("both") => vec!["mail".into(), "files".into()],
                Some("validator") => vec!["mail".into(), "files".into()],
                _ => vec![],
            };

            // peers: валидатор (если указан). Если не указан, но задан domain (и это НЕ валидатор) —
            // АВТОМАТИЧЕСКИ ищем валидатора в DNS TXT (федерация): нода сама находит валидатора по домену.
            let mut peers = Vec::new();
            if role.as_deref() != Some("validator") && validator.is_none() {
                if let Some(dom) = &domain {
                    println!("[federation] looking up validator of domain {dom} in DNS TXT...");
                    match infnode::federation::resolve_validator(dom).await {
                        Ok(Some((nid, ed_pub, ip))) => {
                            match &ed_pub {
                                Some(ep) => {
                                    println!("[federation] OK validator found: {nid} @ {ip} (ed_pub {})", &ep[..16]);
                                    peers.push(infnode::config::PeerConfig {
                                        name: "validator".into(),
                                        node_id: nid,
                                        ed_pub: ep.clone(),
                                        x_pub: String::new(),
                                        pq_pub: None,
                                        endpoints: vec![ip],
                                        allow: vec!["*".into()],
                                        rate_limit_per_sec: 200,
                                        role: None,
                                        storage_roles: vec![],
                                    });
                                }
                                None => {
                                    // строгий режим: TXT БЕЗ ed_pub не принимается (TOFU запрещён)
                                    println!("[federation] ERR TXT for {dom} has no ed_pub — rejected (add record: infnode announce --domain {dom} --advertise <IP:port>)");
                                }
                            }
                        }
                        Ok(None) => println!("[federation] ERR TXT for {dom} not found — no validator (add a record, then: --validator ADDR or --domain again)"),
                        Err(e) => println!("[federation] ERR DNS error: {e}"),
                    }
                }
            }
            if let Some(vaddr) = &validator {
                // если ed_pub не указан — TOFU: примем ключ при первом контакте (небезопасно,
                // лучше указать validator-pub). Используем плейсхолдер "tofu" → Node при
                // handshake заменит? Нет — проще требовать pub или оставить unknown.
                let ed_pub = validator_pub.clone().unwrap_or_default();
                let vname = if role.as_deref() == Some("validator") {
                    "self".into()
                } else {
                    "validator".into()
                };
                if vname != "self" {
                    peers.push(infnode::config::PeerConfig {
                        name: vname,
                        node_id: ed_pub_to_id(&ed_pub, &keys),
                        ed_pub: ed_pub.clone(),
                        x_pub: String::new(),
                        pq_pub: None,
                        endpoints: vec![vaddr.clone()],
                        allow: vec!["*".into()],
                        rate_limit_per_sec: 200,
                        role: None,
                        storage_roles: vec![],
                    });
                }
            }

            let advertise_final = advertise.clone().unwrap_or_else(|| listen.clone());
            let cfg = NodeConfig {
                name,
                listen: listen.clone(),
                client_listen: None,
                advertise: Some(advertise_final.clone()),
                peers,
                allow_unknown: role.as_deref() == Some("validator"),
                unknown_allow: vec!["core.ping".into(), "dht.update".into(), "dht.lookup".into(), "dht.find_node".into()],
                metrics_listen: None,
                log_level: Some(2),
                roles: Default::default(),
                outbox_ttl_secs: 3600,
                storage_roles,
                validators: vec![],
                domain: domain.clone(),
                web_listen: web_listen.clone(),
                web_static: None,
                wallet: wallet.clone(),
            };
            let cfg_path = dir.join("node.yaml");
            infnode::config::save(&cfg_path, &cfg)?;

            println!("=== InfNode node initialized ===");
            println!("role      : {}", role.as_deref().unwrap_or("network"));
            println!("node_id   : {}", keys.id_hex());
            println!("ed_pub    : {}", keys.ed_hex());
            println!("x_pub     : {}", keys.x_hex());
            println!("listen    : {}", listen);
            if let Some(w) = &wallet {
                println!("wallet    : {}", w);
            }
            println!("advertise : {}", advertise_final);
            if let Some(v) = &validator {
                println!("validator : {}", v);
            }
            println!("keys      : {}/keys", dir.display());
            println!("config    : {}", cfg_path.display());
            println!();
            println!("Run:  {} serve --config {}", std::env::current_exe()?.display(), cfg_path.display());
            if role.as_deref() == Some("validator") {
                println!("VALIDATOR: set INFNODE_VALIDATOR_KEY (owner secret) and INFNODE_REWARDS=1 in env.");
            }
        }
        Cmd::Serve { config, role, validator, validator_pub, domain } => {
            // если конфиг не существует — авто-инициализация с ролью и валидатором
            if !config.exists() {
                let dir = config.parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
                std::fs::create_dir_all(&dir).ok();
                let keys = if dir.join("keys").join("identity.key").exists() {
                    NodeKeys::load(&dir.join("keys"))?
                } else {
                    let k = NodeKeys::generate();
                    k.save(&dir.join("keys"))?;
                    k
                };
                let name = dir
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "node".into());
                let storage_roles: Vec<String> = match role.as_deref() {
                    Some("mail") => vec!["mail".into()],
                    Some("files") => vec!["files".into()],
                    Some("both") => vec!["mail".into(), "files".into()],
                    Some("validator") => vec!["mail".into(), "files".into()],
                    _ => vec![],
                };
                let peers = if let Some(vaddr) = &validator {
                    // node_id валидатора = blake3(ed_pub). Если ed_pub не знаем —
                    // TOFU placeholder; но лучше чтобы чел дал --validator-pub.
                    let ed_pub = validator_pub.clone()
                        .or_else(|| std::env::var("INFNODE_VALIDATOR_PUB").ok())
                        .unwrap_or_default();
                    let nid = if ed_pub.is_empty() {
                        keys.id_hex()
                    } else {
                        let bytes = hex::decode(&ed_pub).unwrap_or_default();
                        let h = blake3::hash(&bytes);
                        let mut id = [0u8; infnode::proto::NODEID_LEN];
                        id.copy_from_slice(&h.as_bytes()[..infnode::proto::NODEID_LEN]);
                        format!("inf1:{}", hex::encode(id))
                    };
                    vec![infnode::config::PeerConfig {
                        name: "validator".into(),
                        node_id: nid,
                        ed_pub,
                        x_pub: String::new(),
                        pq_pub: None,
                        endpoints: vec![vaddr.clone()],
                        allow: vec!["*".into()],
                        rate_limit_per_sec: 200,
                        role: None,
                        storage_roles: vec![],
                    }]
                } else {
                    vec![]
                };
                let cfg = NodeConfig {
                    name,
                    listen: "0.0.0.0:9400".into(),
                    client_listen: None,
                    advertise: Some("0.0.0.0:9400".into()),
                    peers,
                    allow_unknown: role.as_deref() == Some("validator"),
                    unknown_allow: vec!["core.ping".into(), "dht.update".into(), "dht.lookup".into(), "dht.find_node".into()],
                    metrics_listen: None,
                    log_level: Some(2),
                    roles: Default::default(),
                    outbox_ttl_secs: 3600,
                    storage_roles,
                    validators: vec![],
                    domain: domain.clone(),
                    web_listen: None,
                    web_static: None,
                    wallet: None,
                };
                infnode::config::save(&config, &cfg)?;
                println!("config not found — generated a new one: {}", config.display());
            }
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            // ПОДТВЕРЖДЕНИЕ ВАЛИДАТОРА (федерация, СТРОГО): если в конфиге указан domain и это НЕ валидатор,
            // нода ОБЯЗАНА пройти проверку TXT — иначе не запустится. Мягкий режим убран:
            // нода не может подключиться к неподтверждённому валидатору.
            if let Some(domain) = &cfg_obj.domain {
                let is_validator = cfg_obj.storage_roles.len() == 2; // validator = обе роли
                if !is_validator {
                    // ожидаемый node_id валидатора = первый peer
                    let expected = cfg_obj.peers.first().map(|p| p.node_id.clone());
                    if let Some(exp_nid) = expected {
                        println!("[federation] checking validator of domain {domain}...");
                        match infnode::federation::verify_domain_validator(domain, &exp_nid).await {
                            Ok(true) => println!("[federation] OK validator confirmed ({exp_nid})"),
                            Ok(false) => {
                                eprintln!("[federation] ERR TXT of domain {domain} does NOT confirm validator {exp_nid}");
                                eprintln!("[federation]   Refusing to start (strict mode).");
                                eprintln!("[federation]   Add record: infnode announce --domain {domain} --advertise <IP:port>");
                                anyhow::bail!("validator is not confirmed by domain {domain} (strict mode)");
                            }
                            Err(e) => {
                                eprintln!("[federation] ERR failed to check DNS: {e}");
                                anyhow::bail!("failed to confirm validator of domain {domain} (strict mode)");
                            }
                        }
                    }
                }
            }
            let node = Node::new(cfg_obj, keys, data_dir.clone(), config_path).await?;
            if std::env::var("INFNODE_REWARDS").as_deref() == Ok("1") {
                let node_r = node.clone();
                let data_dir_r = data_dir.clone();
                tokio::spawn(async move {
                    let _ = infnode::rewards::run(&node_r, &data_dir_r).await;
                });
                println!("rewards tracker enabled (uptime × storage)");
            }
            // прогреваем узел ДО открытия API: первый запрос клиента не должен
            // ждать сходимости меша и построения карты чанков
            {
                let node_w = node.clone();
                tokio::spawn(async move {
                    node_w.warmup().await;
                });
            }
            node.serve().await?;
        }
        Cmd::Send {
            config,
            to,
            service,
            data,
        } => {
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            let resp = node.request(&to, &service, data.into_bytes()).await?;
            println!("{}", String::from_utf8_lossy(&resp));
        }
        Cmd::Ping { config, to, count } => {
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            println!("{}", node.ping(&to, count).await?);
        }
        Cmd::Perf {
            config,
            to,
            size,
            count,
            direction,
        } => {
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            println!("{}", node.perf(&to, size, count, &direction).await?);
        }
        Cmd::Poke { config, to } => {
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            println!("{}", node.poke(&to).await?);
        }
        Cmd::PubsubPublish {
            config,
            to,
            topic,
            data,
        } => {
            use serde_json::json;
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            let payload = json!({ "topic": topic, "data": data }).to_string().into_bytes();
            let resp = node.request(&to, "pubsub.publish", payload).await?;
            println!("{}", String::from_utf8_lossy(&resp));
        }
        Cmd::PubsubSubscribe {
            config,
            to,
            topic,
            timeout,
        } => {
            use serde_json::json;
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            let mut rx = node.register_app_sub(&topic).await;
            let payload = json!({ "topic": topic }).to_string().into_bytes();
            let resp = node.request(&to, "pubsub.subscribe", payload).await?;
            println!("{}", String::from_utf8_lossy(&resp));
            node.start_listener(&to).await?;
            eprintln!("[sub] waiting up to {timeout}s for topic '{topic}'...");
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout);
            let mut rcvd = 0u32;
            loop {
                let r = tokio::time::timeout_at(deadline, rx.recv()).await;
                match r {
                    Ok(Some(msg)) => {
                        rcvd += 1;
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&msg) {
                            println!(
                                "[{}] #{} {} (msg_id={})",
                                topic,
                                rcvd,
                                v["data"].as_str().unwrap_or(&msg),
                                v["msg_id"].as_u64().unwrap_or(0)
                            );
                        } else {
                            println!("[{topic}] #{rcvd} {msg}");
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
        Cmd::Status { config } => {
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            println!("{}", node.status().await?);
        }
        Cmd::MailRegister { config, email, dir, to: _ } => {
            use serde_json::json;
            let keys = infnode::mailbox::MailKeys::generate();
            keys.save(&dir, &email)?;
            let (cfg_obj, keys2, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys2, data_dir, config_path).await?;
            // проверка: email уже занят? (защита от захвата чужого ящика)
            let ukey = format!("user:{email}");
            let h0 = blake3::hash(ukey.as_bytes());
            let mut t0 = [0u8; 20];
            t0.copy_from_slice(&h0.as_bytes()[..20]);
            let c0 = node.dht_find_node(&t0).await;
            let q0 = json!({ "key": ukey }).to_string().into_bytes();
            let mut exists = false;
            for n in c0.iter() {
                if exists { break; }
                if node.ensure_dht_peer(n).await.is_ok() {
                    if let Ok(resp) = node.request_to(n.id, "dht.find_value", q0.clone()).await {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                            if v["found"].as_bool().unwrap_or(false) {
                                exists = true;
                            }
                        }
                    }
                }
            }
            if exists {
                println!("email {email} is already registered — takeover is impossible");
                return Ok(());
            }
            let h = blake3::hash(ukey.as_bytes());
            let mut target = [0u8; 20];
            target.copy_from_slice(&h.as_bytes()[..20]);
            let closest = node.dht_find_node(&target).await;
            let val = json!({ "x_pub": keys.x_hex(), "ed_pub": keys.ed_hex() }).to_string();
            let payload = json!({ "key": ukey, "value": val }).to_string().into_bytes();
            let mut saved = 0usize;
            for n in closest {
                if node.ensure_dht_peer(&n).await.is_ok()
                    && node.request_to(n.id, "dht.store", payload.clone()).await.is_ok()
                {
                    saved += 1;
                }
            }
            println!("registered {email} x_pub={} (saved on {saved} nodes)", keys.x_hex());
        }
        Cmd::MailSend { config, to, from, dest, subject, body, dir } => {
            use serde_json::json;
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            // 1) реестр: получаем x_pub получателя
            let ukey = format!("user:{dest}");
            let h = blake3::hash(ukey.as_bytes());
            let mut target = [0u8; 20];
            target.copy_from_slice(&h.as_bytes()[..20]);
            let closest = node.dht_find_node(&target).await;
            let q = json!({ "key": ukey }).to_string().into_bytes();
            let mut rx = None;
            for n in closest.iter() {
                if rx.is_some() { break; }
                if node.ensure_dht_peer(n).await.is_ok() {
                    if let Ok(resp) = node.request_to(n.id, "dht.find_value", q.clone()).await {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                            if v["found"].as_bool().unwrap_or(false) {
                                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(v["value"].as_str().unwrap_or("")) {
                                    rx = meta["x_pub"].as_str().map(String::from);
                                }
                            }
                        }
                    }
                }
            }
            let rx_hex = rx.ok_or_else(|| anyhow::anyhow!("recipient {dest} is not registered"))?;
            let rx_bytes: [u8; 32] = hex::decode(&rx_hex)?.try_into().map_err(|_| anyhow::anyhow!("bad x_pub"))?;
            let recipient_pub = x25519_dalek::PublicKey::from(rx_bytes);
            // 1б) реестр отправителя: ed_pub для подписи
            let fkey = format!("user:{from}");
            let fh = blake3::hash(fkey.as_bytes());
            let mut ft = [0u8; 20];
            ft.copy_from_slice(&fh.as_bytes()[..20]);
            let fcl = node.dht_find_node(&ft).await;
            let qf = json!({ "key": fkey }).to_string().into_bytes();
            let mut from_ed = None;
            for n in fcl.iter() {
                if from_ed.is_some() { break; }
                if node.ensure_dht_peer(n).await.is_ok() {
                    if let Ok(resp) = node.request_to(n.id, "dht.find_value", qf.clone()).await {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                            if v["found"].as_bool().unwrap_or(false) {
                                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(v["value"].as_str().unwrap_or("")) {
                                    from_ed = meta["ed_pub"].as_str().map(String::from);
                                }
                            }
                        }
                    }
                }
            }
            let _from_ed = from_ed.ok_or_else(|| anyhow::anyhow!("sender {from} is not registered"))?;
            // 2) подписываем payload и шифруем к получателю
            let sender_keys = infnode::mailbox::MailKeys::load(&dir, &from)?;
            let plain = json!({ "from": from, "to": dest, "subject": subject, "body": body, "ts": infnode::proto::now_ms() })
                .to_string()
                .into_bytes();
            let sig = sender_keys.sign(&plain);
            let envelope = json!({ "payload": String::from_utf8_lossy(&plain), "sig": hex::encode(sig) })
                .to_string()
                .into_bytes();
            let blob = infnode::mailbox::seal(&recipient_pub, &envelope)?;
            let id = hex::encode(blake3::hash(format!("{from}:{dest}:{}", infnode::proto::now_ms()).as_bytes()).as_bytes());
            // 3) храним письмо в storage (репликация)
            let mname = format!("mail:{dest}:{id}");
            let stored = node.store_mail(&mname, &blob).await;
            // 4) индекс ящика: append id
            let ikey = format!("mail:{dest}:index");
            let i_h = blake3::hash(ikey.as_bytes());
            let mut it = [0u8; 20];
            it.copy_from_slice(&i_h.as_bytes()[..20]);
            let iclose = node.dht_find_node(&it).await;
            let qi = json!({ "key": ikey }).to_string().into_bytes();
            let mut idx: Vec<String> = Vec::new();
            for n in iclose.iter() {
                if node.ensure_dht_peer(n).await.is_ok() {
                    if let Ok(resp) = node.request_to(n.id, "dht.find_value", qi.clone()).await {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                            if v["found"].as_bool().unwrap_or(false) {
                                if let Ok(list) = serde_json::from_str::<Vec<String>>(v["value"].as_str().unwrap_or("[]")) {
                                    idx = list; break;
                                }
                            }
                        }
                    }
                }
            }
            idx.push(id.clone());
            let ipayload = json!({ "key": ikey, "value": serde_json::to_string(&idx)? }).to_string().into_bytes();
            let mut idxsaved = 0usize;
            for n in iclose {
                if node.ensure_dht_peer(&n).await.is_ok()
                    && node.request_to(n.id, "dht.store", ipayload.clone()).await.is_ok()
                {
                    idxsaved += 1;
                }
            }
            // 5) уведомление через pubsub
            let _ = node.request_to(node.resolve(&to)?, "pubsub.publish", json!({ "topic": format!("mail:{dest}"), "data": id }).to_string().into_bytes()).await;
            println!("sent to {dest}: id={id} (stored on {stored} nodes, index on {idxsaved})");
        }
        Cmd::MailList { config, to, email, dir } => {
            use serde_json::json;
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            let ikey = format!("mail:{email}:index");
            let h = blake3::hash(ikey.as_bytes());
            let mut target = [0u8; 20];
            target.copy_from_slice(&h.as_bytes()[..20]);
            let closest = node.dht_find_node(&target).await;
            let q = json!({ "key": ikey }).to_string().into_bytes();
            let mut _idx = String::from("[]");
            let mut local = node.get_local_kv(&ikey).await;
            if let Some(v) = local.take() { _idx = v; }
            else {
                for n in closest.iter() {
                    if node.ensure_dht_peer(n).await.is_ok() {
                        if let Ok(resp) = node.request_to(n.id, "dht.find_value", q.clone()).await {
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                                if v["found"].as_bool().unwrap_or(false) {
                                    _idx = v["value"].as_str().unwrap_or("[]").to_string(); break;
                                }
                            }
                        }
                    }
                }
            }
            // владелец: подписываем запрос и спрашиваем сервис mail.list
            let owner = match infnode::mailbox::MailKeys::load(&dir, &email) {
                Ok(k) => k,
                Err(_) => {
                    println!("no key of owner {email} in {} — cannot read someone else's mailbox", dir.display());
                    return Ok(());
                }
            };
            let ts = infnode::proto::now_ms();
            let sig = owner.sign(format!("{email}:{ts}").as_bytes());
            let req = json!({ "email": email, "ts": ts, "sig": hex::encode(sig) }).to_string().into_bytes();
            let mut ids = Vec::new();
            let mut denied = false;
            let pid = node.resolve(&to)?;
            if let Ok(resp) = node.request_to(pid, "mail.list", req).await {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                    if v["ok"].as_bool().unwrap_or(false) {
                        ids = v["ids"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                    } else {
                        denied = true;
                        println!("  {}", v["err"].as_str().unwrap_or("denied"));
                    }
                }
            } else {
                denied = true;
                println!("  mail.list unavailable");
            }
            if !denied {
                println!("mailbox {email}: {} messages", ids.len());
                for id in ids { println!("  {id}"); }
            }
        }
        Cmd::MailGet { config, to: _, email, id, dir } => {
            let keys = infnode::mailbox::MailKeys::load(&dir, &email)?;
            let (cfg_obj, node_keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, node_keys, data_dir, config_path).await?;
            // скачиваем письмо из storage (через манифест)
            let mname = format!("mail:{email}:{id}");
            let blob = node.fetch_mail(&mname).await.ok_or_else(|| anyhow::anyhow!("mail not found"))?;
            let plain = infnode::mailbox::open(&keys, &blob)?;
            let env: serde_json::Value = serde_json::from_slice(&plain)?;
            let payload = env["payload"].as_str().unwrap_or("{}").to_string();
            let sig_hex = env["sig"].as_str().unwrap_or("");
            let sig = hex::decode(sig_hex).unwrap_or_default();
            let msg: serde_json::Value = serde_json::from_str(&payload)?;
            // проверка подписи отправителя по реестру
            let from = msg["from"].as_str().unwrap_or("");
            let mut verified = false;
            if sig.len() == 64 {
                if let Some(ed_hex) = node.user_ed_pub(from).await {
                    if let Ok(edb) = hex::decode(&ed_hex) {
                        if edb.len() == 32 {
                            let mut edk = [0u8; 32];
                            edk.copy_from_slice(&edb);
                            let mut sigk = [0u8; 64];
                            sigk.copy_from_slice(&sig);
                            verified = infnode::mailbox::MailKeys::verify(&edk, payload.as_bytes(), &sigk);
                        }
                    }
                }
            }
            println!("--- message {id} (sender signature: {}) ---", if verified { "OK" } else { "NOT VERIFIED" });
            println!("from:    {}", from);
            println!("to:      {}", msg["to"].as_str().unwrap_or(""));
            println!("subject: {}", msg["subject"].as_str().unwrap_or(""));
            println!("body:    {}", msg["body"].as_str().unwrap_or(""));
            println!("ts:      {}", msg["ts"].as_u64().unwrap_or(0));
        }
        Cmd::StoragePut {
            config,
            to: _,
            name,
            file,
            bucket,
        } => {
            use serde_json::json;
            let data = std::fs::read(&file)?;
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            // чанкинг по 1MB
            const CHUNK: usize = 1024 * 1024;
            let mut chunks: Vec<serde_json::Value> = Vec::new();
            // детерминированное шифрование + content-адресные id (см. blob_key_nonce /
            // chunk_id_for): повторный put того же имени с тем же контентом
            // перезаписывает те же чанки, а не добавляет новые.
            let content_hash = infnode::node::blob_content_hash(&data);
            let (data_key, nonce) = infnode::node::blob_key_nonce(&bucket, &name, &content_hash);
            // данные шифруем (XChaCha20) — E2E-слой; ключ в манифест (v1, TODO: шифровать ключом владельца)
            let chunks_blob = infnode::node::e2e_encrypt_det(&data_key, &nonce, &data);
            let mut offset = 0usize;
            while offset < chunks_blob.len() {
                let end = (offset + CHUNK).min(chunks_blob.len());
                let chunk = &chunks_blob[offset..end];
                let chunk_id = infnode::node::chunk_id_for(&bucket, &name, offset, &content_hash);
                let stored = node.store_chunk_replicated(&bucket, &chunk_id, chunk).await;
                chunks.push(json!({ "id": chunk_id, "n": stored, "off": offset, "len": chunk.len(), "hash": hex::encode(blake3::hash(chunk).as_bytes()) }));
                offset = end;
            }
            // манифест в DHT KV
            let manifest = json!({
                "bucket": bucket,
                "name": name,
                "size": data.len(),
                "nonce": hex::encode(nonce),
                "key": hex::encode(data_key),
                "chunks": chunks,
            });
            let mkey = format!("{bucket}:{name}");
            // сохранить манифест через dht-store на k-ближайших
            let h = blake3::hash(mkey.as_bytes());
            let mut target = [0u8; 20];
            target.copy_from_slice(&h.as_bytes()[..20]);
            let closest = node.dht_find_node(&target).await;
            let mpayload = json!({ "key": mkey, "value": manifest.to_string() }).to_string().into_bytes();
            let mut saved = 0usize;
            for n in closest {
                if node.ensure_dht_peer(&n).await.is_ok()
                    && node.request_to(n.id, "dht.store", mpayload.clone()).await.is_ok()
                {
                    saved += 1;
                }
            }
            println!("put ok: name={name} bytes={} chunks={} manifest saved on {saved} nodes", data.len(), chunks.len());
        }
        Cmd::StorageGet { config, to: _, name, out, bucket } => {
            use serde_json::json;
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            // читаем манифест из DHT
            let mkey = format!("{bucket}:{name}");
            let h = blake3::hash(mkey.as_bytes());
            let mut target = [0u8; 20];
            target.copy_from_slice(&h.as_bytes()[..20]);
            let closest = node.dht_find_node(&target).await;
            let q = json!({ "key": mkey }).to_string().into_bytes();
            // сначала локальный KV (манифест мог быть сохранён на этой ноде)
            let mut manifest_str = node.get_local_kv(&mkey).await;
            for n in closest.iter() {
                if manifest_str.is_some() { break; }
                if node.ensure_dht_peer(n).await.is_ok() {
                    if let Ok(resp) = node.request_to(n.id, "dht.find_value", q.clone()).await {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                            if v["found"].as_bool().unwrap_or(false) {
                                manifest_str = v["value"].as_str().map(String::from);
                                break;
                            }
                        }
                    }
                }
            }
            let manifest: serde_json::Value = match manifest_str {
                Some(m) => serde_json::from_str(&m)?,
                None => { println!("manifest not found"); return Ok(()); }
            };
            let nonce = hex::decode(manifest["nonce"].as_str().unwrap_or("")).unwrap_or_default();
            let key = hex::decode(manifest["key"].as_str().unwrap_or("")).unwrap_or_default();
            let mut data_key = [0u8; 32];
            if key.len() == 32 { data_key.copy_from_slice(&key); }
            let mut buf: Vec<u8> = Vec::new();
            if let Some(chunks) = manifest["chunks"].as_array() {
                for c in chunks {
                    let cid = c["id"].as_str().unwrap_or("");
                    let _len = c["len"].as_u64().unwrap_or(0) as usize;
                    let q2 = json!({ "bucket": bucket, "chunk_id": cid }).to_string().into_bytes();
                    // пробуем локальный чанк + реплики
                    let mut got = node.local_chunk_get(&bucket, cid);
                    for n in closest.iter() {
                        if got.is_some() { break; }
                        if node.ensure_dht_peer(n).await.is_ok() {
                            if let Ok(resp) = node.request_to(n.id, "storage.fetch", q2.clone()).await {
                                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                                    if v["ok"].as_bool().unwrap_or(false) {
                                        if let Some(b64) = v["data"].as_str() {
                                            if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(b64) {
                                                got = Some(b); break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    match got {
                        Some(b) => buf.extend_from_slice(&b),
                        None => { println!("chunk missing: {cid}"); return Ok(()); }
                    }
                }
            }
            let plain = infnode::node::e2e_decrypt(&data_key, &nonce, &buf)?;
            let nbytes = plain.len();
            std::fs::write(&out, &plain)?;
            println!("get ok: name={name} -> {} ({} bytes)", out.display(), nbytes);
        }
        Cmd::DhtFind { config, to: _, target } => {
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            let t = node.resolve(&target)?;
            let nodes = node.dht_find_node(&t).await;
            for n in nodes {
                println!("inf1:{} {} ed={}", hex::encode(n.id), n.endpoints.join(","), n.ed_hex);
            }
        }
        Cmd::DhtStore { config, to, key, value } => {
            use serde_json::json;
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            let _t = node.resolve(&to)?;
            // ключ -> target = blake3(key)
            let h = blake3::hash(key.as_bytes());
            let mut target = [0u8; 20];
            target.copy_from_slice(&h.as_bytes()[..20]);
            let closest = node.dht_find_node(&target).await;
            let payload = json!({ "key": key, "value": value }).to_string().into_bytes();
            let mut stored = 0usize;
            for n in closest {
                if node.ensure_dht_peer(&n).await.is_ok()
                    && node.request_to(n.id, "dht.store", payload.clone()).await.is_ok()
                {
                    stored += 1;
                }
            }
            println!("stored at {stored} nodes (k closest)");
        }
        Cmd::DhtGet { config, to, key } => {
            use serde_json::json;
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            let _t = node.resolve(&to)?;
            let h = blake3::hash(key.as_bytes());
            let mut target = [0u8; 20];
            target.copy_from_slice(&h.as_bytes()[..20]);
            let closest = node.dht_find_node(&target).await;
            let payload = json!({ "key": key }).to_string().into_bytes();
            let mut found = None;
            for n in closest {
                if node.ensure_dht_peer(&n).await.is_ok() {
                    if let Ok(resp) = node.request_to(n.id, "dht.find_value", payload.clone()).await {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                            if v["found"].as_bool().unwrap_or(false) {
                                found = v["value"].as_str().map(String::from);
                                break;
                            }
                        }
                    }
                }
            }
            match found {
                Some(v) => println!("value: {v}"),
                None => println!("not found"),
            }
        }
        Cmd::Find { config, to, node } => {
            use serde_json::json;
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node_obj = Node::new(cfg_obj, keys, data_dir, config_path).await?;
            let payload = json!({ "node": node }).to_string().into_bytes();
            let resp = node_obj.request(&to, "dht.lookup", payload).await?;
            println!("{}", String::from_utf8_lossy(&resp));
        }
        Cmd::Stats { config } => {
            // data-dir = рядом с конфигом (по умолчанию node.yaml в текущей папке)
            let data_dir = config
                .as_ref()
                .and_then(|c| c.parent().map(|p| p.to_path_buf()))
                .unwrap_or_else(|| PathBuf::from("."));
            // 1. kv.json
            let kv_path = data_dir.join("kv.json");
            let (kv_keys, kv_bytes) = match std::fs::read(&kv_path) {
                Ok(b) => {
                    let n = serde_json::from_slice::<serde_json::Value>(&b)
                        .ok()
                        .and_then(|v| v.as_object().map(|o| o.len()))
                        .unwrap_or(0);
                    (n, b.len())
                }
                Err(_) => (0, 0),
            };
            // 2. chunks mail/files
            let count_chunks = |sub: &str| -> usize {
                std::fs::read_dir(data_dir.join("chunks").join(sub))
                    .map(|rd| rd.filter_map(|e| e.ok()).count())
                    .unwrap_or(0)
            };
            let chunks_mail = count_chunks("mail");
            let chunks_files = count_chunks("files");
            // 3. rewards.json
            let rewards_nodes = std::fs::read_to_string(data_dir.join("rewards.json"))
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| v["nodes"].as_array().map(|a| a.len()))
                .unwrap_or(0);
            // 4. payout_ledger.json
            let payouts_entries = std::fs::read_to_string(data_dir.join("payout_ledger.json"))
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| v.as_array().map(|a| a.len()))
                .unwrap_or(0);
            println!("=== InfNode stats ===");
            println!("kv.json        : {} keys, {} bytes", kv_keys, kv_bytes);
            println!("chunks/mail    : {}", chunks_mail);
            println!("chunks/files   : {}", chunks_files);
            println!("rewards.nodes  : {}", rewards_nodes);
            println!("payouts entries: {}", payouts_entries);
        }
        Cmd::AuditKv { kv, find } => {
            let path = kv.unwrap_or_else(|| PathBuf::from("kv.json"));
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
            let root: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| anyhow::anyhow!("invalid JSON in {}: {e}", path.display()))?;
            let Some(obj) = root.as_object() else {
                anyhow::bail!("{} is not a JSON object", path.display());
            };
            if let Some(needle) = find {
                let keys: Vec<&String> = obj.keys().filter(|k| k.contains(&needle)).collect();
                println!("found {} keys matching '{}':", keys.len(), needle);
                for k in keys.iter().take(50) {
                    println!("  {k}");
                }
                if keys.len() > 50 {
                    println!("  ... and {} more", keys.len() - 50);
                }
            } else {
                println!("audit {}: {} keys, {} bytes", path.display(), obj.len(), raw.len());
                let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
                for k in obj.keys() {
                    let pref = k.split(':').next().unwrap_or(k).to_string();
                    *counts.entry(pref).or_default() += 1;
                }
                for (p, c) in counts {
                    println!("  {p:>14}: {c}");
                }
            }
        }
        Cmd::Consensus { config, hash_only } => {
            use serde_json::json;
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node = Node::new(cfg_obj.clone(), keys, data_dir.clone(), config_path).await?;
            // даём время на установление QUIC-связи с пирами (подписи шлются по установленным conn)
            let want = cfg_obj.peers.len();
            for _ in 0..20 {
                if node.known_peers().await.len() >= want && node.peers_ready().await >= want {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
            // хэш состояния: kv.json (манифесты/индексы/профили) — единый снимок.
            let state = std::fs::read_to_string(data_dir.join("kv.json")).unwrap_or_default();
            let state_hash = hex::encode(blake3::hash(state.as_bytes()).as_bytes());
            println!("=== Consensus (state signing) ===");
            println!("node_id    : {}", node.id_hex);
            println!("state_hash : {}", state_hash);
            println!("kv.json    : {} bytes", state.len());
            let validators = cfg_obj.validators.clone();
            let total = validators.len() + 1; // основной + суб-валидаторы
            let quorum = if total <= 1 { 1 } else { (total * 2).div_ceil(3) }; // ceil(2/3·N)
            println!("validators: {} (primary + {} sub)", total, validators.len());
            println!("quorum     : {} of {}", quorum, total);
            if hash_only {
                println!("hash_only  : true (signatures were not requested)");
                return Ok(());
            }
            // подпись мастера (всегда своя — секрет локальный)
            let my_sig = hex::encode(
                ed25519_dalek::Signer::sign(&node.keys.signing, state_hash.as_bytes()).to_bytes(),
            );
            let mut signatures: Vec<serde_json::Value> = vec![
                json!({ "node_id": node.id_hex, "signature": my_sig, "who": "primary" }),
            ];
            // запрос подписей у суб-валидаторов (все в cfg.validators)
            for vid in &validators {
                // node_id → pid (raw 20 байт)
                let raw = vid.strip_prefix("inf1:").unwrap_or(vid);
                if let Ok(bytes) = hex::decode(raw) {
                    if bytes.len() == 20 {
                        let mut pid = [0u8; 20];
                        pid.copy_from_slice(&bytes);
                        match node.request_to(pid, "consensus.sign", json!({ "state_hash": state_hash }).to_string().into_bytes()).await {
                            Ok(resp) => match serde_json::from_slice::<serde_json::Value>(&resp) {
                                Ok(v) if v["ok"].as_bool().unwrap_or(false) => {
                                    signatures.push(json!({
                                        "node_id": v["node_id"].clone(),
                                        "signature": v["signature"].clone(),
                                        "who": "sub",
                                    }));
                                    println!("  OK signature from {}", vid);
                                }
                                Ok(v) => println!("  ERR {}: {}", vid, v["err"].as_str().unwrap_or("rejected")),
                                Err(_) => println!("  ERR {}: malformed response", vid),
                            },
                            Err(e) => println!("  ❌ {}: {e}", vid),
                        }
                    }
                }
            }
            let got = signatures.len();
            let ok = got >= quorum;
            println!("signatures : {} (need {}) -> {}", got, quorum, if ok { "OK QUORUM REACHED" } else { "ERR NO QUORUM" });
            let rec = json!({
                "ts": infnode::proto::now_ms(),
                "state_hash": state_hash,
                "validators": total,
                "quorum": quorum,
                "signed": got,
                "ok": ok,
                "signatures": signatures,
            });
            std::fs::write(data_dir.join("consensus.json"), serde_json::to_string_pretty(&rec)?)?;
            println!("written   : {}/consensus.json", data_dir.display());
        }
        Cmd::Restore { config } => {
            let (cfg_obj, keys, data_dir, config_path) = load(&config)?;
            let node_id = keys.id_hex();
            let node = Node::new(cfg_obj, keys, data_dir.clone(), config_path).await?;
            println!("=== Validator restore from network ===");
            println!("node_id : {}", node_id);
            println!("peers   : {}", node.known_peers().await.len());
            // для каждого пира: catch_up_with (догоняющая репликация KV)
            let peers = node.known_peers().await;
            let mut restored = 0usize;
            for p in peers {
                if p.id == node.id {
                    continue;
                }
                println!("  sync with {} ...", hex::encode(&p.id[..6]));
                node.catch_up_with(p.id).await;
                restored += 1;
            }
            println!("  peers synced: {}", restored);
            println!("  KV restored from the network (manifests/indexes/account profiles).");
            println!("  WARNING: secrets (pw_hash/smtp_pass/e2e_secret) are NOT replicated.");
            println!("  Restore them from the validator's keys/ backup.");
            println!("  Check kv.json: {} keys", {
                // печатаем число ключей kv.json
                std::fs::read_to_string(data_dir.join("kv.json"))
                    .ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .and_then(|v| v.as_object().map(|o| o.len()))
                    .unwrap_or(0)
            });
        }
        Cmd::Announce { domain, advertise, config } => {
            // node_id + ed_pub валидатора из ключей
            let (cfg_obj, keys, _, _) = load(&config)?;
            let node_id = keys.id_hex();
            let ed_pub = keys.ed_hex();
            let ip = advertise.split(':').next().unwrap_or(&advertise).to_string();
            let msg = infnode::federation::announce_message(&node_id, &ed_pub, &domain, &ip);
            println!("{}", msg);
            println!("node_id : {}", node_id);
            println!("ed_pub  : {}", ed_pub);
            println!("domain  : {}", domain);
            println!("advertise: {}", advertise);
            let _ = cfg_obj;
        }
        Cmd::VerifyValidator { domain, node_id } => {
            match infnode::federation::verify_domain_validator(&domain, &node_id).await {
                Ok(true) => println!("OK VALIDATOR CONFIRMED: TXT of domain {domain} contains node_id {node_id}"),
                Ok(false) => println!("ERR NOT CONFIRMED: TXT of domain {domain} does not contain node_id {node_id}\n   (add record: infnode announce --domain {domain} --advertise <IP:port>)"),
                Err(e) => println!("WARN DNS check error: {e}"),
            }
        }
    }
    Ok(())
}
