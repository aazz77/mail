use anyhow::{Context, Result};
use base64::Engine;
use mail_parser::MessageParser;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::models::AppState;

pub async fn run(listener: TcpListener, state: Arc<AppState>) -> Result<()> {
    tracing::info!("SMTP server listening on {}", listener.local_addr()?);
    loop {
        let (socket, addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(socket, addr, state).await {
                tracing::debug!("SMTP connection from {} ended: {}", addr, e);
            }
        });
    }
}

struct SmtpSession {
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    data_lines: Vec<String>,
    in_data: bool,
}

impl SmtpSession {
    fn new() -> Self {
        Self {
            mail_from: None,
            rcpt_to: Vec::new(),
            data_lines: Vec::new(),
            in_data: false,
        }
    }

    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data_lines.clear();
        self.in_data = false;
    }
}

async fn handle(socket: TcpStream, _addr: std::net::SocketAddr, state: Arc<AppState>) -> Result<()> {
    let (read_half, mut write_half) = socket.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    write_half
        .write_all(format!("220 {} ESMTP\r\n", smtp_hostname()).as_bytes())
        .await?;

    let mut session = SmtpSession::new();

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            return Ok(());
        }

        let cmd = line.trim_end_matches("\r\n").trim_end_matches('\n');
        let upper = cmd.to_uppercase();

        if session.in_data {
            if cmd == "." {
                session.in_data = false;
                let raw = session.data_lines.join("\n");
                match process_email(&state, &session.mail_from, &session.rcpt_to, &raw).await {
                    Ok(_) => {
                        write_half.write_all(b"250 OK\r\n").await?;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to process email: {}", e);
                        write_half.write_all(b"451 Temporary failure\r\n").await?;
                    }
                }
                session.reset();
            } else {
                // RFC 5321 4.5.2: leading dot is escaped as two dots
                let unescaped = if let Some(stripped) = cmd.strip_prefix("..") {
                    stripped
                } else {
                    cmd
                };
                session.data_lines.push(unescaped.to_string());
            }
            continue;
        }

        if upper.starts_with("HELO") || upper.starts_with("EHLO") {
            write_half.write_all(b"250 cloud-mail\r\n").await?;
        } else if upper.starts_with("MAIL FROM:") {
            session.mail_from = Some(extract_address(&cmd[10..]));
            write_half.write_all(b"250 OK\r\n").await?;
        } else if upper.starts_with("RCPT TO:") {
            let address = extract_address(&cmd[8..]);
            if state.config.domain_allowed(&address) {
                session.rcpt_to.push(address);
                write_half.write_all(b"250 OK\r\n").await?;
            } else {
                write_half.write_all(b"550 Relaying denied\r\n").await?;
            }
        } else if upper == "DATA" {
            if session.mail_from.is_none() || session.rcpt_to.is_empty() {
                write_half.write_all(b"503 Bad sequence of commands\r\n").await?;
            } else {
                session.in_data = true;
                write_half
                    .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    .await?;
            }
        } else if upper == "QUIT" {
            write_half.write_all(b"221 Bye\r\n").await?;
            return Ok(());
        } else if upper == "RSET" {
            session.reset();
            write_half.write_all(b"250 OK\r\n").await?;
        } else if upper == "NOOP" {
            write_half.write_all(b"250 OK\r\n").await?;
        } else {
            write_half.write_all(b"500 Unknown command\r\n").await?;
        }
    }
}

fn extract_address(raw: &str) -> String {
    let raw = raw.trim();
    if let Some(start) = raw.find('<') {
        if let Some(end) = raw[start..].find('>') {
            return raw[start + 1..start + end].to_string();
        }
    }
    raw.split_whitespace()
        .next()
        .unwrap_or("")
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

fn smtp_hostname() -> String {
    std::env::var("SMTP_HOSTNAME").unwrap_or_else(|_| "cloud-mail".to_string())
}

async fn process_email(
    state: &Arc<AppState>,
    mail_from: &Option<String>,
    rcpt_to: &[String],
    raw: &str,
) -> Result<()> {
    let message = MessageParser::default()
        .parse(raw.as_bytes())
        .context("failed to parse MIME message")?;

    let subject = message.subject().unwrap_or("").to_string();
    let (from_addr, from_name) = extract_header_address(message.from());
    let message_id = message.message_id().unwrap_or("").to_string();
    let text_body = message.body_text(0).unwrap_or_default().to_string();
    let html_body = message.body_html(0).unwrap_or_default().to_string();

    let sender = mail_from
        .as_deref()
        .or(from_addr.as_deref())
        .unwrap_or("")
        .to_string();

    for recipient in rcpt_to {
        let account: Option<(i64, i64)> = sqlx::query_as(
            "SELECT account_id, user_id FROM account WHERE email = ? COLLATE NOCASE AND is_del = 0",
        )
        .bind(recipient)
        .fetch_optional(&state.pool)
        .await?;

        let Some((account_id, user_id)) = account else {
            tracing::debug!("No account found for recipient {}, skipping", recipient);
            continue;
        };

        let recipient_json =
            serde_json::json!([{ "address": recipient, "name": "" }]).to_string();
        let result = sqlx::query(
            "INSERT INTO email(send_email,name,sender_email,account_id,user_id,subject,text,content,recipient,to_email,to_name,in_reply_to,message_id,type,status,unread,create_time) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,1,0,datetime('now'))"
        )
        .bind(&sender)
        .bind(&from_name)
        .bind(&sender)
        .bind(account_id)
        .bind(user_id)
        .bind(&subject)
        .bind(&text_body)
        .bind(&html_body)
        .bind(&recipient_json)
        .bind(recipient)
        .bind("")
        .bind("")
        .bind(&message_id)
        .execute(&state.pool)
        .await?;

        let email_id = result.last_insert_rowid();

        // Store attachments
        for attachment in message.attachments() {
            let body: Vec<u8> = match &attachment.body {
                mail_parser::PartType::Binary(b) => b.to_vec(),
                mail_parser::PartType::InlineBinary(b) => b.to_vec(),
                mail_parser::PartType::Text(t) => t.as_bytes().to_vec(),
                mail_parser::PartType::Html(h) => h.as_bytes().to_vec(),
                _ => continue,
            };

            let filename = find_header(&attachment.headers, |n| matches!(n, mail_parser::HeaderName::ContentDisposition))
                .and_then(|v| match v {
                    mail_parser::HeaderValue::ContentType(ct) => ct.attributes.as_ref()
                        .and_then(|attrs| attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case("filename")))
                        .map(|(_, v)| v.to_string()),
                    mail_parser::HeaderValue::Text(t) => extract_filename_from_disposition(t),
                    _ => None,
                })
                .unwrap_or_else(|| "attachment".to_string());

            let mime_type = find_header(&attachment.headers, |n| matches!(n, mail_parser::HeaderName::ContentType))
                .and_then(|v| match v {
                    mail_parser::HeaderValue::ContentType(ct) => Some(match ct.c_subtype.as_ref() {
                        Some(sub) => format!("{}/{}", ct.c_type, sub),
                        None => ct.c_type.to_string(),
                    }),
                    _ => None,
                })
                .unwrap_or_else(|| "application/octet-stream".to_string());

            let size = body.len() as i64;

            let key = format!(
                "attachments/{}.{}",
                hash_bytes(&body),
                extension(&filename)
            );
            crate::storage::put_object(&state.config.storage_dir, &key, &body).await?;

            let disposition = "attachment".to_string();

            sqlx::query(
                "INSERT INTO attachments(user_id,email_id,account_id,key,filename,mime_type,size,status,type,disposition,related,content_id,encoding) VALUES(?,?,?,?,?,?,?,0,0,?,?,?,?)"
            )
            .bind(user_id)
            .bind(email_id)
            .bind(account_id)
            .bind(&key)
            .bind(&filename)
            .bind(&mime_type)
            .bind(size)
            .bind(&disposition)
            .bind("")
            .bind("")
            .bind("")
            .execute(&state.pool)
            .await?;
        }

        tracing::info!(
            "Received email {} for account {} (user {}) from {}",
            email_id,
            account_id,
            user_id,
            sender
        );
    }

    Ok(())
}

fn find_header<'a, F>(
    headers: &'a [mail_parser::Header<'a>],
    pred: F,
) -> Option<&'a mail_parser::HeaderValue<'a>>
where
    F: Fn(&mail_parser::HeaderName) -> bool,
{
    headers.iter().find(|h| pred(&h.name)).map(|h| &h.value)
}

fn extract_header_address(addr: Option<&mail_parser::Address>) -> (Option<String>, Option<String>) {
    match addr {
        Some(mail_parser::Address::List(addrs)) => {
            addrs.first().map_or((None, None), |a| {
                (
                    a.address.as_ref().map(|s| s.to_string()),
                    a.name.as_ref().map(|s| s.to_string()),
                )
            })
        }
        Some(mail_parser::Address::Group(groups)) => groups
            .first()
            .and_then(|g| g.addresses.first())
            .map_or((None, None), |a| {
                (
                    a.address.as_ref().map(|s| s.to_string()),
                    a.name.as_ref().map(|s| s.to_string()),
                )
            }),
        None => (None, None),
    }
}

fn extract_filename_from_disposition(value: &str) -> Option<String> {
    for part in value.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("filename=") {
            return Some(rest.trim_matches('"').to_string());
        }
        if let Some(rest) = part.strip_prefix("filename*=UTF-8''") {
            return Some(rest.trim_matches('"').to_string());
        }
    }
    None
}

fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

fn extension(filename: &str) -> String {
    filename
        .rsplit('.')
        .next()
        .unwrap_or("bin")
        .chars()
        .take(16)
        .collect()
}

/// Read the raw email from a SMTP socket, used for testing.
#[allow(dead_code)]
pub async fn receive_test_email(
    host: &str,
    port: u16,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<String> {
    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    let (rd, mut wr) = stream.split();
    let mut rd = BufReader::new(rd);
    let mut response = String::new();

    read_response(&mut rd, &mut response).await?;

    send_line(&mut wr, &format!("HELO test-client")).await?;
    read_response(&mut rd, &mut response).await?;

    send_line(&mut wr, &format!("MAIL FROM:<{}>", from)).await?;
    read_response(&mut rd, &mut response).await?;

    send_line(&mut wr, &format!("RCPT TO:<{}>", to)).await?;
    read_response(&mut rd, &mut response).await?;

    send_line(&mut wr, "DATA").await?;
    read_response(&mut rd, &mut response).await?;

    let email = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n.\r\n",
        from, to, subject, body
    );
    wr.write_all(email.as_bytes()).await?;
    read_response(&mut rd, &mut response).await?;

    send_line(&mut wr, "QUIT").await?;

    Ok(response)
}

async fn send_line<W: AsyncWriteExt + Unpin>(writer: &mut W, line: &str) -> Result<()> {
    writer
        .write_all(format!("{}\r\n", line).as_bytes())
        .await?;
    Ok(())
}

async fn read_response<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buffer: &mut String,
) -> Result<String> {
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let trimmed = line.trim_end().to_string();
    buffer.push_str(&trimmed);
    buffer.push('\n');
    Ok(trimmed)
}
