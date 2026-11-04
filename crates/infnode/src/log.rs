//! Структурированные JSON-логи для диагностики в проде.
//! Формат: {"ts":..., "level":..., "event":..., "node":..., "trace":..., ...}
//!
//! R1 (performance patch A): `emit()` больше не делает синхронный `write(2)`
//! в stderr на каждом вызове. Строка кладётся в ограниченный `sync_channel`
//! (4096) и её пишет ОДИН выделенный поток `infnode-log`:
//!   * write(2) не блокирует async-воркер (на 1-vCPU стенде синхронный
//!     `eprintln!` на каждый запрос добавлял миллисекунды к resp);
//!   * при переполнении очереди строка ОТБРАСЫВАЕТСЯ и считается в
//!     `LOG_DROPPED` (лучше потерять лог, чем задержать запрос);
//!   * `LOG_WRITE_NS` — суммарное время, ушедшее непосредственно на запись
//!     строк (диагностика того, насколько дорогим был stderr);
//!   * порядок строк сохраняется (FIFO-канал + ровно один писатель), а `ts`
//!     берётся в момент EMIT, а не в момент записи — запись может запаздывать.

use serde_json::json;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static LEVEL: AtomicU8 = AtomicU8::new(2); // 0=err,1=warn,2=info,3=debug

/// Сколько строк потеряно из-за переполненной очереди логов (см. модуль).
pub static LOG_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Наносекунды, проведённые писательским потоком непосредственно в write(2).
pub static LOG_WRITE_NS: AtomicU64 = AtomicU64::new(0);

/// Ёмкость очереди логов. Осознанно ограничена: под нагрузкой на стенде
/// (load 4.4) лог-трафик не должен ни вытеснять память, ни держать
/// отправителя — при переполнении страдает лог, а не запрос.
const LOG_QUEUE_CAP: usize = 4096;

/// Тестовый кран: пока `true`, писательский поток не забирает строки из
/// очереди (заполняем её и проверяем счётчик `LOG_DROPPED`). В проде всегда false.
static HOLD: AtomicBool = AtomicBool::new(false);
/// Тестовый сброс: пока `true`, писатель забирает строки из очереди, но НЕ
/// пишет их в stderr (иначе тест переполнения вывалил бы в вывод ~4096 строк).
/// В проде всегда false.
static DISCARD: AtomicBool = AtomicBool::new(false);
/// Сколько строк писатель уже РАЗОБРАЛ (написал или сбросил) — тест ждёт этим,
/// когда можно снимать DISCARD, не потеряв хвост очереди в stderr.
static PROCESSED: AtomicU64 = AtomicU64::new(0);

static QUEUE: OnceLock<SyncSender<String>> = OnceLock::new();

fn queue() -> &'static SyncSender<String> {
    QUEUE.get_or_init(|| {
        let (tx, rx) = sync_channel::<String>(LOG_QUEUE_CAP);
        let spawned = std::thread::Builder::new()
            .name("infnode-log".into())
            .spawn(move || {
                while let Ok(line) = rx.recv() {
                    // Тестовый кран: не разбирать очередь, пока HOLD не снят.
                    // (Проверяется на каждой итерации, чтобы после снятия
                    // крана очередь сразу пошла вниз.)
                    while HOLD.load(Ordering::Acquire) {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    if DISCARD.load(Ordering::Acquire) {
                        PROCESSED.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let t0 = Instant::now();
                    // stderr блокируется на межпоточный мьютекс ВНУТРИ вызова,
                    // поэтому lock не держим между строками — иначе чужой
                    // eprintln! в другом потоке завис бы навсегда.
                    let _ = writeln!(std::io::stderr().lock(), "{line}");
                    LOG_WRITE_NS.fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
                    PROCESSED.fetch_add(1, Ordering::Relaxed);
                }
            });
        spawned.expect("spawn infnode-log writer thread");
        tx
    })
}

pub fn set_level(l: u8) {
    LEVEL.store(l, Ordering::Relaxed);
}

pub fn emit(
    level: u8,
    level_s: &str,
    node: &str,
    trace: u64,
    event: &str,
    fields: serde_json::Value,
) {
    if level > LEVEL.load(Ordering::Relaxed) {
        return;
    }
    // ts берётся ЗДЕСЬ, в момент emit: писательский поток запаздывает и не
    // должен сдвигать время события.
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let mut line = json!({
        "ts": ts,
        "level": level_s,
        "event": event,
    });
    if !node.is_empty() {
        line["node"] = json!(node);
    }
    if trace != 0 {
        line["trace"] = json!(trace);
    }
    if let Some(obj) = fields.as_object() {
        for (k, v) in obj {
            line[k] = v.clone();
        }
    }
    // Никакого блокирующего write(2) здесь: только try_send. Переполнение —
    // это DROP со счётчиком, а не ожидание (R1).
    match queue().try_send(line.to_string()) {
        Ok(()) => {}
        Err(_) => {
            LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[macro_export]
macro_rules! tlog {
    ($node:expr, $trace:expr, $event:expr) => {
        $crate::log::emit(2, "info", $node, $trace, $event, serde_json::json!({}))
    };
    ($node:expr, $trace:expr, $event:expr, $($k:ident = $v:expr),*) => {
        $crate::log::emit(2, "info", $node, $trace, $event, serde_json::json!({ $(stringify!($k): $v),* }))
    };
}

#[macro_export]
macro_rules! terr {
    ($node:expr, $trace:expr, $event:expr, $($k:ident = $v:expr),*) => {
        $crate::log::emit(0, "error", $node, $trace, $event, serde_json::json!({ $(stringify!($k): $v),* }))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_until(mut cond: impl FnMut() -> bool, ms: u64) -> bool {
        let deadline = Instant::now() + std::time::Duration::from_millis(ms);
        while !cond() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        true
    }

    /// R1-регрессия: при переполнении bounded-очереди строки отбрасываются и
    /// считаются в `LOG_DROPPED`, а писательский поток после снятия крана
    /// доразбирает накопленный хвост (PROCESSED растёт) и продолжает писать
    /// с учётом времени в `LOG_WRITE_NS`.
    #[test]
    fn log_queue_drops_on_overflow_and_counts_writes() {
        let dropped0 = LOG_DROPPED.load(Ordering::Relaxed);
        let processed0 = PROCESSED.load(Ordering::Relaxed);

        // DISCARD первым: разобранный в тесте хвост (~4096 строк) не должен
        // засорять вывод тестов — писатель сбросит его молча.
        DISCARD.store(true, Ordering::Release);
        // Кран: писатель перестаёт забирать строки, очередь замирает заполненной.
        HOLD.store(true, Ordering::Release);
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Больше ёмкости (4096): всё сверх неё обязано упасть в счётчик.
        // level=0 — чтобы сброс чужого set_level(0) в других тестах не
        // отфильтровал наши строки.
        for i in 0..(LOG_QUEUE_CAP + 1024) as u64 {
            emit(0, "error", "logtest", i, "drop_probe", json!({ "i": i }));
        }
        let dropped1 = LOG_DROPPED.load(Ordering::Relaxed);
        HOLD.store(false, Ordering::Release);

        // Ждём полного разбора хвоста (в очереди было ровно LOG_QUEUE_CAP
        // строк; чужие строки за это время только добавляются к счётчику),
        // и только потом снимаем DISCARD — иначе остаток ушёл бы в stderr.
        assert!(
            wait_until(
                || PROCESSED.load(Ordering::Relaxed) >= processed0 + LOG_QUEUE_CAP as u64,
                5_000
            ),
            "drain thread must consume the queued tail"
        );
        DISCARD.store(false, Ordering::Release);

        assert!(
            dropped1 - dropped0 >= 512,
            "overflow must be counted in LOG_DROPPED: before={dropped0} after={dropped1}"
        );

        // Писатель жив и пишет: одна маркерная строка двигает LOG_WRITE_NS
        // (ровно одна строка попадёт и в вывод теста — это осознанный минимум).
        let write1 = LOG_WRITE_NS.load(Ordering::Relaxed);
        emit(0, "error", "logtest", 0, "writer_alive", json!({}));
        assert!(
            wait_until(|| LOG_WRITE_NS.load(Ordering::Relaxed) > write1, 5_000),
            "drain thread must keep writing (and accounting write time)"
        );
    }
}
