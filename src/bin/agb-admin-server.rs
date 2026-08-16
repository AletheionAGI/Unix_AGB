use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct Request {
    token: String,
    operation: String,
    operator: String,
}

#[derive(Serialize)]
struct Response {
    ok: bool,
    reason: String,
    operator: String,
}

fn handle(
    mut stream: UnixStream,
    cache: &PathBuf,
    audit: &PathBuf,
    requests: &mut VecDeque<Instant>,
) {
    let line = BufReader::new(stream.try_clone().unwrap())
        .lines()
        .next()
        .unwrap_or(Ok(String::new()))
        .unwrap_or_default();
    let request: Result<Request, _> = serde_json::from_str(&line);
    let now = Instant::now();
    while requests
        .front()
        .is_some_and(|time| now.duration_since(*time) > Duration::from_secs(60))
    {
        requests.pop_front();
    }
    let operator = request
        .as_ref()
        .ok()
        .map(|r| r.operator.clone())
        .unwrap_or_else(|| "unknown".into());
    let response = if requests.len() >= 5 {
        Response {
            ok: false,
            reason: "rate-limit".into(),
            operator,
        }
    } else {
        requests.push_back(now);
        let expected = env::var("AGB_ADMIN_TOKEN").unwrap_or_default();
        match request {
            Ok(request) if !expected.is_empty() && request.token == expected => {
                let result = match request.operation.as_str() {
                    "list" => true,
                    "rotate" => {
                        let rotated = format!("{}.rotated", cache.display());
                        !cache.exists() || std::fs::rename(cache, rotated).is_ok()
                    }
                    _ => false,
                };
                let reason = if result {
                    "admin-ok"
                } else {
                    "unsupported-operation"
                };
                Response {
                    ok: result,
                    reason: reason.into(),
                    operator: request.operator,
                }
            }
            _ => Response {
                ok: false,
                reason: "invalid-token-or-request".into(),
                operator,
            },
        }
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit)
    {
        let _ = serde_json::to_writer(&mut file, &response);
        let _ = file.write_all(b"\n");
    }
    let _ = serde_json::to_writer(&mut stream, &response);
    let _ = stream.write_all(b"\n");
}

fn main() -> Result<(), String> {
    let socket = PathBuf::from(
        env::args()
            .nth(1)
            .unwrap_or_else(|| "var/agb-admin.sock".into()),
    );
    let cache = PathBuf::from(
        env::args()
            .nth(2)
            .unwrap_or_else(|| "var/policy-cache.jsonl".into()),
    );
    let audit = PathBuf::from(
        env::args()
            .nth(3)
            .unwrap_or_else(|| "var/admin-audit.jsonl".into()),
    );
    if socket.exists() {
        std::fs::remove_file(&socket).map_err(|e| e.to_string())?;
    }
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
    let mut requests = VecDeque::new();
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            handle(stream, &cache, &audit, &mut requests);
        }
    }
    Ok(())
}
