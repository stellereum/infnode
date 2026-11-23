//! infmail-backend — webmail-сервис поверх сети infnode.
//!
//! Декомпозиция: `infnode serve` = чистый сетевой слой (QUIC+DHT+storage, web отключён),
//! `infmail-backend serve` = почтовый web-слой (auth, квоты, mail/files API, 2FA, подписки).
//!
//! Запуск: `infmail-backend serve --config /opt/infnode/node.yaml`
//! Конфиг должен содержать `web-listen` (например "127.0.0.1:3001").
//! Бинарник поднимает свою ноду (как peer сети) и web-API на ней.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use infnode::config;
use infnode::keyring::NodeKeys;
use infnode::node::Node;

#[derive(Parser)]
#[command(
    name = "infmail-backend",
    version,
    about = "InfMail webmail backend (REST API почты/файлов/планов) поверх infnode"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Запустить web-бэкенд (требует web-listen в node.yaml)
    Serve {
        #[arg(long, default_value = "node.yaml")]
        config: PathBuf,
    },
}

fn load(
    cfg: &Path,
) -> Result<(
    config::NodeConfig,
    NodeKeys,
    infnode::keyring::PqKeys,
    PathBuf,
    PathBuf,
)> {
    let cfg_obj = config::load(cfg)?;
    let keys_dir = cfg
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("keys");
    let keys = NodeKeys::load(&keys_dir)?;
    let pq = infnode::keyring::PqKeys::load_or_generate(&keys_dir)?;
    let data_dir = cfg
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();
    Ok((cfg_obj, keys, pq, data_dir, cfg.to_path_buf()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve { config } => {
            let (cfg_obj, keys, pq, data_dir, config_path) = load(&config)?;
            let rewards_dir = data_dir.clone();
            let node = Node::new(cfg_obj.clone(), keys, pq, data_dir, config_path)
                .await
                .context("создание ноды")?;
            let web_listen = node.cfg.web_listen.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "в конфиге нет web-listen — укажи его (например \"127.0.0.1:3001\")"
                )
            })?;
            let static_dir = node.cfg.web_static.clone().map(PathBuf::from);
            let node_web = node.clone();
            // web-слой в главном потоке, сеть — фоном
            let net_node = node.clone();
            let net = tokio::spawn(async move {
                let _ = net_node.serve().await;
            });
            // rewards (uptime × storage): запускается ТОЛЬКО если задан env (важно для валидатора,
            // storage-ноды (node1/aeza) обычно rewards не запускают — это у них минус нагрузка).
            // Защита от захвата сети: rewards как ВАЛИДАТОР может запустить только владелец,
            // который знает INFNODE_VALIDATOR_KEY (секрет валидатора). Чужая нода без этого
            // секрета не сможет поднять свой rewards-цикл и «раздавать» награды.
            if std::env::var("INFNODE_REWARDS").as_deref() == Ok("1") {
                let validator_key_ok = std::env::var("INFNODE_VALIDATOR_KEY")
                    .map(|k| !k.is_empty() && k.len() >= 16)
                    .unwrap_or(false);
                if !validator_key_ok {
                    eprintln!("[rewards] ВНИМАНИЕ: INFNODE_REWARDS=1, но INFNODE_VALIDATOR_KEY не задан — rewards отключён (защита от захвата). Задай INFNODE_VALIDATOR_KEY (>=16 символов) владельцу сети.");
                } else {
                    let rewards_node = node.clone();
                    let rewards_dir_r = rewards_dir.clone();
                    tokio::spawn(async move {
                        let _ = infnode::rewards::run(&rewards_node, &rewards_dir_r).await;
                    });
                    eprintln!("rewards tracker enabled (uptime × storage) [validator key OK]");
                }
            }
            // migration (chunk migration + integrity): по умолчанию ВЫКЛ (включается явно env
            // INFNODE_MIGRATION=1). Первый проход — через INFNODE_MIGRATION_INTERVAL_SECS (default 3600).
            if std::env::var("INFNODE_MIGRATION").as_deref() == Ok("1") {
                // migration::run сам создаёт dedicated thread + свой tokio runtime
                // (не блокирует основной), поэтому здесь просто запускаем его.
                infnode::migration::run(node.clone(), rewards_dir.clone());
                eprintln!(
                    "migration tracker enabled (chunk migration + integrity, dedicated thread)"
                );
            }
            infmail::web::run(node_web, &web_listen, static_dir)
                .await
                .context("web-бэкенд")?;
            net.abort();
            Ok(())
        }
    }
}
