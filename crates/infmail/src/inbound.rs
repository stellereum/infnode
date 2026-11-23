//! Входящий SMTP-мост: тянет письма из MTA (stalwart, IMAP) в webmail infnode.
//! Для каждого аккаунта с ящиком (smtp_pass) читает UNSEEN из INBOX и инжектит
//! письмо в storage.* + индекс ящика (как обычное входящее).

use anyhow::{anyhow, Result};
use base64::Engine;
use serde_json::json;
use std::sync::Arc;

use crate::web::AccountsDb;
use infnode::node::Node;

fn extract_header(raw: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    // заголовок может быть в самом начале сообщения (без ведущего \n)
    let needle = format!("{name}:");
    let pos = if text.starts_with(&needle) {
        0
    } else {
        let lower = text.to_lowercase();
        let lneedle = format!("\n{}:", name.to_lowercase());
        lower.find(&lneedle)? + 1
    };
    let rest = &text[pos + name.len() + 1..];
    let line_end = rest.find('\n').unwrap_or(rest.len());
    Some(rest[..line_end].trim().to_string())
}

/// Декод RFC 2047 encoded-words: =?UTF-8?B?base64?= или =?UTF-8?Q?quoted-printable?=
fn decode_mime_encoded(s: &str) -> String {
    if !s.contains("=?") {
        return s.to_string();
    }
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("=?") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find("?=") {
            let inner = &after[..end];
            let parts: Vec<&str> = inner.split('?').collect();
            if parts.len() >= 3 {
                let enc = parts[1].to_uppercase();
                let data = parts[2..].join("?");
                if enc == "B" {
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data) {
                        out.push_str(&String::from_utf8_lossy(&bytes));
                        rest = &after[end + 2..];
                        continue;
                    }
                } else if enc == "Q" {
                    out.push_str(&quoted_printable_decode(&data));
                    rest = &after[end + 2..];
                    continue;
                }
            }
        }
        break;
    }
    out.push_str(rest);
    out
}

fn quoted_printable_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4 | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

// ─────────────────────────────────────────────────────────────
// Разбор входящего MIME: тело + вложения.
// Вложения извлекаются из multipart и хранятся отдельными блобами
// в хранилище почты (считаются в квоту почты). Сырой MIME после
// разбора отбрасывается — письмо переживает только как структура.
// ─────────────────────────────────────────────────────────────

struct Attachment {
    name: String,
    mime: String,
    data: Vec<u8>,
}

struct ParsedMail {
    sender: String,
    subject: String,
    body: String,
    html: Option<String>,
    attachments: Vec<Attachment>,
}

/// Максимальный суммарный размер вложений одного входящего письма (безопасность памяти).
pub(crate) fn max_attach_total() -> usize {
    std::env::var("INFNODE_INBOUND_MAX_ATTACH")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(25 * 1024 * 1024)
}
pub(crate) const MAX_ATTACH_COUNT: usize = 50;
const MAX_FILENAME_LEN: usize = 200;
/// Лимит текстового тела письма (байт) — отдельный от вложений, защита от OOM.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Максимальная глубина вложенности `multipart/*` в одном письме.
///
/// MIME приходит от ВНЕШНЕГО отправителя (SMTP → MTA → IMAP), а разбор
/// рекурсивный: раньше вложенность не ограничивалась, поэтому письмо с
/// десятками тысяч вложенных `multipart` роняло процесс переполнением стека
/// (плюс квадратичный ре-скан разделителей). 16 уровней — с большим запасом
/// для любого реального клиента; глубже — часть игнорируется, письмо всё
/// равно разбирается до безопасной глубины.
const MAX_MIME_DEPTH: usize = 16;

/// Поиск последовательности байт в срезе.
fn find_seq(hay: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() || start >= hay.len() {
        return None;
    }
    hay[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

/// Разделить сообщение/часть на заголовки и тело (первая пустая строка).
fn split_headers_body(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(p) = find_seq(raw, b"\r\n\r\n", 0) {
        (&raw[..p], &raw[p + 4..])
    } else if let Some(p) = find_seq(raw, b"\n\n", 0) {
        (&raw[..p], &raw[p + 2..])
    } else {
        (raw, &[])
    }
}

/// Значение заголовка (без учёта регистра, с учётом folding-продолжений).
fn header_val(headers: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(headers);
    let lines: Vec<&str> = text.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
            i += 1;
            continue;
        }
        if let Some((n, v)) = line.split_once(':') {
            if n.trim().eq_ignore_ascii_case(name) {
                let mut val = v.trim().to_string();
                i += 1;
                while i < lines.len() {
                    let l = lines[i];
                    if l.starts_with(' ') || l.starts_with('\t') {
                        val.push(' ');
                        val.push_str(l.trim());
                        i += 1;
                    } else {
                        break;
                    }
                }
                return Some(val);
            }
        }
        i += 1;
    }
    None
}

/// "type/subtype; key=value; key2=value" → (mime, параметры).
fn parse_params(s: &str) -> (String, Vec<(String, String)>) {
    let mut parts = s.split(';');
    let mime = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let params = parts
        .filter_map(|p| {
            let p = p.trim();
            if p.is_empty() {
                return None;
            }
            match p.split_once('=') {
                Some((k, v)) => Some((
                    k.trim().to_ascii_lowercase(),
                    v.trim().trim_matches('"').to_string(),
                )),
                None => Some((p.to_ascii_lowercase(), String::new())),
            }
        })
        .collect();
    (mime, params)
}

fn param(params: &[(String, String)], name: &str) -> Option<String> {
    params
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// RFC 2231: filename*=UTF-8''<percent-encoded>
fn rfc2231_decode(v: &str) -> Option<String> {
    let rest = v.split("''").nth(1).unwrap_or(v);
    let bytes = pct_decode(rest);
    let s = String::from_utf8_lossy(&bytes).to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn pct_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4 | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Очистка имени файла: последний компонент пути, без управляющих символов и "..".
pub(crate) fn sanitize_filename(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    if base.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(base.len());
    for c in base.chars() {
        if c.is_control() {
            continue;
        }
        out.push(c);
        if out.len() >= MAX_FILENAME_LEN {
            break;
        }
    }
    let out = out.trim().trim_matches('.').to_string();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub(crate) fn sanitize_mime(mime: &str) -> String {
    let m: String = mime
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '/' || *c == '+' || *c == '-' || *c == '.')
        .collect();
    if m.is_empty() {
        "application/octet-stream".into()
    } else {
        m.to_ascii_lowercase()
    }
}

/// Quoted-Printable → байты (мягкие переносы =CRLF/=LF/=CR сворачиваются).
fn quoted_printable_bytes(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'=' {
            // мягкий перенос строки: =CRLF, =LF или =CR — просто удаляем
            if i + 2 < s.len() && s[i + 1] == b'\r' && s[i + 2] == b'\n' {
                i += 3;
                continue;
            }
            if i + 1 < s.len() && (s[i + 1] == b'\n' || s[i + 1] == b'\r') {
                i += 2;
                continue;
            }
            if i + 1 < s.len() && i + 2 < s.len() {
                let hi = (s[i + 1] as char).to_digit(16);
                let lo = (s[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4 | l) as u8);
                    i += 3;
                    continue;
                }
            }
            // одиночный '=' (оборванный перенос) — пропускаем
            i += 1;
            continue;
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Декод тела части по Content-Transfer-Encoding.
fn decode_cte(cte: &str, body: &[u8]) -> Option<Vec<u8>> {
    let cte = cte.to_ascii_lowercase();
    if cte.contains("base64") {
        let compact: Vec<u8> = body
            .iter()
            .copied()
            .filter(|&b| !b.is_ascii_whitespace())
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(&compact)
            .ok()
            .or_else(|| {
                base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(&compact)
                    .ok()
            })
    } else if cte.contains("quoted-printable") {
        Some(quoted_printable_bytes(body))
    } else {
        Some(body.to_vec())
    }
}

struct PartCtx {
    body: String,
    html: Option<String>,
    attachments: Vec<Attachment>,
    max_total: usize,
    total: usize,
}

/// Разобрать одну MIME-часть (рекурсивно для multipart).
fn parse_part(raw: &[u8], ctx: &mut PartCtx, depth: usize) {
    if depth > MAX_MIME_DEPTH {
        // Hostile deep nesting: stop descending instead of overflowing the
        // stack (the bounded outer part still contributes nothing).
        return;
    }
    let (headers, body) = split_headers_body(raw);
    let ct = header_val(headers, "Content-Type").unwrap_or_else(|| "text/plain".into());
    let (mime, params) = parse_params(&ct);
    let cd = header_val(headers, "Content-Disposition").unwrap_or_default();
    let (_, cd_params) = parse_params(&cd);
    let disposition = cd
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let cte = header_val(headers, "Content-Transfer-Encoding").unwrap_or_default();

    if let Some(boundary) = param(&params, "boundary") {
        parse_parts(body, &boundary, ctx, depth + 1);
        return;
    }

    if mime == "text/plain" && disposition != "attachment" {
        // основное тело письма (первое text/plain) — лимит отдельный от вложений,
        // чтобы гигантское тело не вызывало OOM (вложения лимитируются max_total).
        if let Some(decoded) = decode_cte(&cte, body) {
            if ctx.body.is_empty() {
                let limit = decoded.len().min(MAX_BODY_BYTES);
                ctx.body = String::from_utf8_lossy(&decoded[..limit]).to_string();
            }
        }
        return;
    }

    if mime == "text/html" && disposition != "attachment" {
        // HTML-версия тела (multipart/alternative): сохраняем отдельно, чтобы
        // не путать с plain-текстом и безопасно рендерить в веб-интерфейсе.
        if ctx.html.is_none() {
            if let Some(decoded) = decode_cte(&cte, body) {
                let limit = decoded.len().min(MAX_BODY_BYTES);
                ctx.html = Some(String::from_utf8_lossy(&decoded[..limit]).to_string());
            }
        }
        return;
    }

    // вложение: имя из Content-Disposition/Content-Type или явная диспозиция attachment
    let mut filename = param(&cd_params, "filename")
        .or_else(|| param(&cd_params, "filename*").and_then(|v| rfc2231_decode(&v)))
        .or_else(|| param(&params, "name"))
        .or_else(|| param(&params, "name*").and_then(|v| rfc2231_decode(&v)))
        .and_then(|n| sanitize_filename(&n));
    if filename.is_none() && disposition == "attachment" {
        filename = Some(format!("attachment_{}", ctx.attachments.len()));
    }
    let Some(name) = filename else { return };
    if ctx.attachments.len() >= MAX_ATTACH_COUNT {
        return;
    }
    let remain = ctx.max_total.saturating_sub(ctx.total);
    if remain == 0 {
        return;
    }
    // прикидка ДО декодирования, чтобы не держать в памяти гигантские буферы
    let est = if cte.to_ascii_lowercase().contains("base64") {
        body.len() * 3 / 4 + 8
    } else {
        body.len()
    };
    if est > remain {
        eprintln!(
            "[inbound] вложение {name} слишком большое ({est} Б > остаток {remain} Б), пропущено"
        );
        return;
    }
    if let Some(decoded) = decode_cte(&cte, body) {
        ctx.total += decoded.len();
        ctx.attachments.push(Attachment {
            name,
            mime: sanitize_mime(&mime),
            data: decoded,
        });
    }
}

/// Пройти по multipart-частям по разделителям boundary.
fn parse_parts(body: &[u8], boundary: &str, ctx: &mut PartCtx, depth: usize) {
    if depth > MAX_MIME_DEPTH {
        return;
    }
    let delim = format!("--{boundary}");
    let delim_bytes = delim.as_bytes();
    let mut search = 0usize;
    loop {
        let Some(start) = find_seq(body, delim_bytes, search) else {
            break;
        };
        let mut pos = start + delim_bytes.len();
        if body.get(pos..pos + 2) == Some(b"--") {
            break; // закрывающий разделитель --boundary--
        }
        while pos < body.len() && (body[pos] == b'\r' || body[pos] == b'\n') {
            pos += 1;
        }
        let next = find_seq(body, delim_bytes, pos);
        let end = next.unwrap_or(body.len());
        let mut part_end = end;
        while part_end > pos && (body[part_end - 1] == b'\r' || body[part_end - 1] == b'\n') {
            part_end -= 1;
        }
        if part_end > pos {
            parse_part(&body[pos..part_end], ctx, depth);
        }
        if next.is_none() {
            break;
        }
        search = pos;
    }
}

/// Разбор входящего письма: sender, subject, тело и вложения.
fn parse_inbound(raw: &[u8]) -> ParsedMail {
    parse_inbound_limit(raw, max_attach_total())
}

fn parse_inbound_limit(raw: &[u8], max_total: usize) -> ParsedMail {
    let sender = extract_header(raw, "From")
        .map(|f| {
            f.rsplit('<')
                .next()
                .unwrap_or(&f)
                .trim_end_matches('>')
                .trim()
                .to_string()
        })
        .unwrap_or_else(|| "unknown@external".into());
    let sender = decode_mime_encoded(&sender);
    let subject = decode_mime_encoded(&extract_header(raw, "Subject").unwrap_or_default());
    let mut ctx = PartCtx {
        body: String::new(),
        html: None,
        attachments: Vec::new(),
        max_total,
        total: 0,
    };
    let (headers, body) = split_headers_body(raw);
    let ct = header_val(headers, "Content-Type").unwrap_or_else(|| "text/plain".into());
    let (_, params) = parse_params(&ct);
    if let Some(boundary) = param(&params, "boundary") {
        parse_parts(body, &boundary, &mut ctx, 0);
    } else {
        // однострочное (не multipart) письмо — тело целиком по CTE
        let cte = header_val(headers, "Content-Transfer-Encoding").unwrap_or_default();
        let decoded = decode_cte(&cte, body).unwrap_or_else(|| body.to_vec());
        let text = String::from_utf8_lossy(&decoded).to_string();
        let limit = text.len().min(MAX_BODY_BYTES);
        let text = text[..limit].to_string();
        if ct.to_ascii_lowercase().contains("text/html") {
            ctx.html = Some(text);
        } else {
            ctx.body = text;
        }
    }
    ParsedMail {
        sender,
        subject,
        body: ctx.body,
        html: ctx.html,
        attachments: ctx.attachments,
    }
}

/// Синхронизировать входящие письма одного аккаунта (IMAP).
/// `max_bytes` — свободное место в почтовой квоте: письма сверх лимита не инжектятся
/// (остаются UNSEEN в ящике MTA и доставятся после освобождения места).
#[allow(clippy::too_many_arguments)] // GATE: IMAP sync needs full account context
pub fn sync_account_imap(
    email: &str,
    smtp_pass: &str,
    node: &Arc<Node>,
    handle: tokio::runtime::Handle,
    host: &str,
    port: u16,
    max_bytes: u64,
    owner_x_pub: Option<String>,
) -> Result<(usize, u64)> {
    let mut tls_builder = native_tls::TlsConnector::builder();
    // Верифицировать сертификат, если IMAP-сервер НЕ локальный (loopback).
    // На loopback MitM невозможен (трафик не покидает машину), поэтому для 127.0.0.1/localhost
    // допускаем самоподписанный сертификат (типичный случай stalwart с localhost-сертификатом).
    let is_loopback = host == "127.0.0.1" || host == "::1" || host == "localhost";
    if is_loopback {
        tls_builder.danger_accept_invalid_certs(true);
    }
    let tls = tls_builder.build()?;
    let client =
        imap::connect((host, port), host, &tls).map_err(|e| anyhow!("imap connect: {e:?}"))?;
    let mut session = client
        .login(email, smtp_pass)
        .map_err(|(e, _)| anyhow!("imap login: {e}"))?;
    let mut injected = 0usize;
    let mut injected_bytes = 0u64;
    // внешние письма могут попадать в Junk (спам-фильтр MTA) — синкаем оба ящика
    for folder in ["INBOX", "Junk"] {
        if session.select(folder).is_err() {
            continue;
        }
        // UID, а не sequence numbers (seq съезжают при expunge -> дубли/чужие флаги).
        // Лимит на цикл против флуда (HIGH-3): больше — следующим циклом.
        let mut ids: Vec<u32> = session
            .uid_search("UNSEEN")
            .unwrap_or_default()
            .into_iter()
            .collect();
        ids.sort_unstable();
        const MAX_PER_CYCLE: usize = 100;
        if ids.len() > MAX_PER_CYCLE {
            eprintln!(
                "[inbound] {email}/{folder}: {} unseen, беру первые {MAX_PER_CYCLE}",
                ids.len()
            );
            ids.truncate(MAX_PER_CYCLE);
        }
        for id in ids {
            let uid = id.to_string();
            if let Ok(fetch) = session.uid_fetch(&uid, "(RFC822)") {
                if let Some(msg) = fetch.iter().next() {
                    if let Some(raw) = msg.body() {
                        // защита от OOM: пропускаем письма больше лимита целиком (raw ≤ max + запас)
                        if raw.len() > max_attach_total() + 8 * 1024 * 1024 {
                            // ВАЖНО: полный флаг "+FLAGS (\\Seen)" — голый "+FLAGS" сервер
                            // отвергает, письмо перечитывалось вечно (дубли + флуд квоты).
                            if let Err(e) = session.uid_store(&uid, "+FLAGS (\\Seen)") {
                                eprintln!("[inbound] {email}: uid_store Seen failed: {e:?}");
                            }
                            continue;
                        }
                        let parsed = parse_inbound(raw);
                        let at = infnode::proto::now_ms();
                        // СТАБИЛЬНЫЙ mid: хэш содержимого, а не времени. Раньше в mid входило
                        // at=now_ms -> каждое перечитывание давало новый id: дубли в индексе
                        // и бесконечный рост квоты при неснятом SEEN.
                        let mid = hex::encode(
                            blake3::hash(
                                format!("{email}:in:{}", hex::encode(blake3::hash(raw).as_bytes()))
                                    .as_bytes(),
                            )
                            .as_bytes(),
                        );
                        // сначала вложения (конверт не должен ссылаться на отсутствующие блобы)
                        let mut att_meta: Vec<serde_json::Value> = Vec::new();
                        let mut att_bytes = 0u64;
                        for a in parsed.attachments.iter() {
                            att_meta.push(json!({
                                "name": a.name,
                                "mime": a.mime,
                                "size": a.data.len(),
                            }));
                            att_bytes += a.data.len() as u64;
                        }
                        // Proton-модель: если у получателя есть публичный X25519 — тело и html
                        // шифруются случайным ключом, ключ box-заворачивается на x_pub получателя.
                        // Сервер/ноды видят только метаданные (sender/subject/date), прочитать
                        // тело может только владелец приватного X25519 (браузер).
                        let (body_field, html_field) = match &owner_x_pub {
                            Some(xpub) if !xpub.is_empty() => {
                                let body_enc = infnode::node::proton_box_body(xpub, &parsed.body);
                                let html_enc = parsed
                                    .html
                                    .as_deref()
                                    .map(|h| infnode::node::proton_box_body(xpub, h));
                                (
                                    body_enc
                                        .unwrap_or_else(|| json!(parsed.body.clone()).to_string()),
                                    html_enc.map(|s| {
                                        s.unwrap_or_else(|| {
                                            json!(parsed.html.clone().unwrap_or_default())
                                                .to_string()
                                        })
                                    }),
                                )
                            }
                            _ => (
                                json!(parsed.body.clone()).to_string(),
                                parsed.html.as_deref().map(|h| json!(h).to_string()),
                            ),
                        };
                        let envelope = json!({
                            "sender": parsed.sender,
                            "to": email,
                            "at": at,
                            "subject": parsed.subject,
                            "body": body_field,
                            "html": html_field,
                            "attachments": att_meta,
                        })
                        .to_string()
                        .into_bytes();
                        let msg_bytes = envelope.len() as u64 + att_bytes;
                        // квота: не превышать лимит почты аккаунта (письмо остаётся в MTA UNSEEN)
                        if injected_bytes + msg_bytes > max_bytes {
                            eprintln!(
                            "[inbound] {email}: пропуск письма {mid} (квота исчерпана, {}+{}>{} байт)",
                            injected_bytes, msg_bytes, max_bytes
                        );
                            continue;
                        }
                        let name = format!("mail:{mid}");
                        injected_bytes += msg_bytes;
                        let node_c = node.clone();
                        let name_c = name.clone();
                        let blob_c = envelope.clone();
                        handle.block_on(async move {
                            node_c.store_blob("mail", &name_c, &blob_c).await;
                        });
                        // вложения пишем после проверки квоты (иначе orphan-блобы при отказе).
                        // Proton-модель: если у получателя есть x_pub — вложение шифруется (XSalsa20,
                        // ключ box на x_pub), сервер/ноды видят только шифротекст; браузер расшифрует.
                        for (i, a) in parsed.attachments.iter().enumerate() {
                            let aname = format!("mail:{mid}:att:{i}");
                            let node_c = node.clone();
                            let aname_c = aname.clone();
                            let data = if let Some(xpub) =
                                owner_x_pub.as_ref().filter(|p| !p.is_empty())
                            {
                                infnode::node::proton_box_data(xpub, &a.data)
                                    .map(|s| s.into_bytes())
                                    .unwrap_or_else(|| a.data.clone())
                            } else {
                                a.data.clone()
                            };
                            handle.block_on(async move {
                                node_c.store_blob("mail", &aname_c, &data).await;
                            });
                        }
                        // Junk (спам-фильтр MTA) → папка Spam, а не Inbox. Индексы раздельные.
                        let key = if folder == "Junk" {
                            format!("mail:{email}:spam-index")
                        } else {
                            format!("mail:{email}:index")
                        };
                        let mut ids_list: Vec<String> = handle
                            .block_on(node.get_local_kv(&key))
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default();
                        if !ids_list.iter().any(|x| x == &mid) {
                            ids_list.push(mid.clone());
                        }
                        let serialized = serde_json::to_string(&ids_list).unwrap_or("[]".into());
                        let node_c = node.clone();
                        let key_c = key.clone();
                        handle.block_on(
                            async move { node_c.kv_store_local(&key_c, &serialized).await },
                        );
                        injected += 1;
                        if let Err(e) = session.uid_store(&uid, "+FLAGS (\\Seen)") {
                            eprintln!("[inbound] {email}: uid_store Seen failed: {e:?}");
                        }
                    }
                }
            }
        }
    }
    session.logout().map_err(|_| anyhow!("imap logout"))?;
    Ok((injected, injected_bytes))
}

/// Мгновенный синк одного аккаунта (при открытии ящика). Не блокирует дольше таймаута.
/// Возвращает (кол-во инжектированных писем, добавленные байты) — для однократного учёта квоты.
pub async fn inbound_sync_one(
    node: &Arc<Node>,
    email: &str,
    smtp_pass: &str,
    max_bytes: u64,
    owner_x_pub: Option<String>,
) -> (usize, u64) {
    let host = std::env::var("INFNODE_IMAP_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("INFNODE_IMAP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(993);
    let node = node.clone();
    let email = email.to_string();
    let sp = smtp_pass.to_string();
    let host = host.clone();
    let handle = tokio::runtime::Handle::current();
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            sync_account_imap(
                &email,
                &sp,
                &node,
                handle,
                &host,
                port,
                max_bytes,
                owner_x_pub,
            )
        }),
    )
    .await
    {
        Ok(Ok(Ok((n, bytes)))) => (n, bytes),
        _ => (0, 0),
    }
}

/// Синхронизировать входящие письма ВСЕХ аккаунтов с ящиком в MTA.
pub async fn inbound_sync_all(
    node: &Arc<Node>,
    db: &AccountsDb,
) -> Result<(Vec<(String, u64)>, Vec<String>)> {
    let host = std::env::var("INFNODE_IMAP_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("INFNODE_IMAP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(993);
    let handle = tokio::runtime::Handle::current();
    let mut results = Vec::new();
    let mut failed = Vec::new();
    for (email, acc) in &db.accounts {
        let Some(sp) = acc.smtp_pass.clone() else {
            continue;
        };
        // почтовая квота аккаунта (та же логика, что effective_mail_quota в web.rs)
        let paid = acc.paid_until_ms > infnode::proto::now_ms();
        let quota = if paid {
            3 * 1024 * 1024 * 1024
        } else {
            acc.quota_limit.min(1024 * 1024 * 1024)
        };
        let free = quota.saturating_sub(acc.bytes_used);
        // Proton-модель: публичный X25519-ключ аккаунта — для шифрования тела входящих писем
        let owner_x_pub = acc.x_pub.clone();
        let node = node.clone();
        let email = email.clone();
        let email_log = email.clone();
        let host = host.clone();
        let handle = handle.clone();
        match tokio::task::spawn_blocking(move || {
            sync_account_imap(&email, &sp, &node, handle, &host, port, free, owner_x_pub)
        })
        .await
        {
            Ok(Ok((n, bytes))) => {
                if n > 0 {
                    eprintln!("[web] inbound: {n} писем для {email_log}");
                }
                results.push((email_log, bytes));
            }
            Ok(Err(e)) => {
                failed.push(email_log.clone());
                eprintln!("[web] inbound imap {email_log}: {e}");
            }
            Err(e) => {
                failed.push(email_log.clone());
                eprintln!("[web] inbound task {email_log}: {e}");
            }
        }
    }
    Ok((results, failed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    #[test]
    fn parses_multipart_body_and_attachments() {
        let png: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3];
        let raw = format!(
            "From: \"Alice\" <alice@example.com>\r\n\
             Subject: =?UTF-8?B?{}?=\r\n\
             Content-Type: multipart/mixed; boundary=\"BND\"\r\n\
             MIME-Version: 1.0\r\n\r\n\
             --BND\r\n\
             Content-Type: text/plain; charset=UTF-8\r\n\r\n\
             Привет мир!\r\n\
             --BND\r\n\
             Content-Type: image/png; name=\"photo.png\"\r\n\
             Content-Disposition: attachment; filename=\"photo.png\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n\
             {}\r\n\
             --BND--\r\n",
            b64("Смета".as_bytes()),
            b64(&png)
        );
        let m = parse_inbound(raw.as_bytes());
        assert_eq!(m.sender, "alice@example.com");
        assert_eq!(m.subject, "Смета");
        assert!(m.body.contains("Привет мир"));
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].name, "photo.png");
        assert_eq!(m.attachments[0].mime, "image/png");
        assert_eq!(m.attachments[0].data, png);
    }

    #[test]
    fn multipart_alternative_uses_plain_not_html() {
        let raw = "From: x@example.com\r\nSubject: alt\r\nContent-Type: multipart/alternative; boundary=B\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\n\r\nplain body\r\n\
                   --B\r\nContent-Type: text/html\r\n\r\n<b>html body</b>\r\n\
                   --B--\r\n";
        let m = parse_inbound(raw.as_bytes());
        assert_eq!(m.body, "plain body");
        assert_eq!(m.html.as_deref(), Some("<b>html body</b>"));
        assert!(m.attachments.is_empty());
    }

    #[test]
    fn html_only_message_goes_to_html_not_body() {
        let raw = "From: x@example.com\r\nSubject: html-only\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<!DOCTYPE html><html><body>Hi</body></html>";
        let m = parse_inbound(raw.as_bytes());
        assert!(m.body.is_empty());
        assert!(m.html.as_deref().unwrap_or("").contains("<html>"));
    }

    #[test]
    fn steam_style_alternative_keeps_html_in_plain_like_steam() {
        // Steam шлёт text/plain, который на самом деле HTML-разметка (оба альтернатива HTML).
        // Парсер должен сохранить оба: body (raw) и html.
        let raw = "From: noreply@steampowered.com\r\nSubject: guard\r\nContent-Type: multipart/alternative; boundary=B\r\n\r\n\
                   --B\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\r\n\
                   --B\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<!DOCTYPE html><html>g</html>\r\n\
                   --B--\r\n";
        let m = parse_inbound(raw.as_bytes());
        assert!(m.body.contains("<!DOCTYPE html"));
        assert!(m
            .html
            .as_deref()
            .unwrap_or("")
            .contains("<!DOCTYPE html><html>"));
    }

    #[test]
    fn base64_attachment_does_not_leak_into_body() {
        // не multipart, base64 картинка без имени — не тело и не вложение (регрессия старого бага)
        let raw = format!(
            "From: x@example.com\r\nSubject: img\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
            b64(&[1, 2, 3, 4])
        );
        let m = parse_inbound(raw.as_bytes());
        assert!(m.attachments.is_empty());
        // тело не должно быть base64-мусором
        assert!(!m.body.contains("AQIDBA"));
    }

    #[test]
    fn nested_multipart_mixed_with_inline_image() {
        let raw = "From: x@example.com\r\nSubject: nest\r\nContent-Type: multipart/mixed; boundary=O\r\n\r\n\
                   --O\r\nContent-Type: multipart/alternative; boundary=I\r\n\r\n\
                   --I\r\nContent-Type: text/plain\r\n\r\ninner\r\n\
                   --I--\r\n\
                   --O\r\nContent-Type: image/png; name=\"logo.png\"\r\nContent-Disposition: inline; filename=\"logo.png\"\r\nContent-Transfer-Encoding: base64\r\n\r\nAAlQ\r\n\
                   --O--\r\n";
        let m = parse_inbound(raw.as_bytes());
        assert_eq!(m.body, "inner");
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].name, "logo.png");
    }

    #[test]
    fn filename_sanitized_from_path_traversal() {
        let raw = "From: x@example.com\r\nSubject: evil\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n\
                   --B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"../../etc/passwd\"\r\nContent-Transfer-Encoding: base64\r\n\r\nYWFhYQ==\r\n\
                   --B--\r\n";
        let m = parse_inbound(raw.as_bytes());
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].name, "passwd");
    }

    #[test]
    fn rfc2231_encoded_filename() {
        let raw = "From: x@example.com\r\nSubject: f\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n\
                   --B\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename*=UTF-8''%D0%BE%D1%82%D1%87%D0%B5%D1%82.txt\r\nContent-Transfer-Encoding: base64\r\n\r\ndGVzdA==\r\n\
                   --B--\r\n";
        let m = parse_inbound(raw.as_bytes());
        assert_eq!(m.attachments[0].name, "отчет.txt");
        assert_eq!(m.attachments[0].data, b"test");
    }

    #[test]
    fn quoted_printable_body_decoded() {
        let raw = "From: x@example.com\r\nSubject: qp\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nПривет=20мир=\r\n";
        let m = parse_inbound(raw.as_bytes());
        assert_eq!(m.body, "Привет мир");
    }

    #[test]
    fn oversized_attachment_is_skipped() {
        let big = vec![b'x'; 1024];
        let raw = format!(
            "From: x@example.com\r\nSubject: big\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n\
             --B\r\nContent-Type: text/plain\r\n\r\nsmall body\r\n\
             --B\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"big.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n\
             --B--\r\n",
            b64(&big)
        );
        let m = parse_inbound_limit(raw.as_bytes(), 4);
        assert_eq!(m.body, "small body");
        assert!(m.attachments.is_empty());
    }

    /// SEC-S1: hostile MIME nesting must not overflow the stack.
    ///
    /// A remote sender can nest `multipart/*` arbitrarily deep; the recursive
    /// parser used to descend without a bound, so a few megabytes of input
    /// killed the process (stack overflow) before any size/quota check. The
    /// parser now stops at `MAX_MIME_DEPTH` and still returns a bounded mail.
    #[test]
    fn deeply_nested_multipart_is_depth_bounded_not_a_stack_overflow() {
        const DEPTH: usize = 25_000;
        let mut raw = String::new();
        for i in 0..DEPTH {
            raw.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=bb{i}\r\n\r\n--bb{i}\r\n"
            ));
        }
        raw.push_str("Content-Type: text/plain\r\n\r\nnested body\r\n");
        for i in (0..DEPTH).rev() {
            raw.push_str(&format!("--bb{i}--\r\n"));
        }
        let m = parse_inbound(raw.as_bytes());
        assert!(
            m.body.len() <= MAX_BODY_BYTES,
            "body must stay bounded even for hostile nesting"
        );
        assert!(m.attachments.is_empty(), "no attachments in this fixture");
    }
}
