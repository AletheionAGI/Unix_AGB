use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct Request {
    token: String,
    operation: String,
}

#[derive(Serialize)]
struct Response {
    ok: bool,
    reason: String,
    operator: String,
    authorization_revision: String,
}

fn peer_credentials(stream: &UnixStream) -> Option<libc::ucred> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result == 0 { Some(credentials) } else { None }
}

fn peer_allowed(credentials: Option<libc::ucred>) -> bool {
    let Some(credentials) = credentials else {
        return false;
    };
    let mut configured = false;
    for (name, value) in [
        ("AGB_ADMIN_UIDS", credentials.uid),
        ("AGB_ADMIN_GIDS", credentials.gid),
    ] {
        if let Ok(allowlist) = env::var(name) {
            configured = true;
            if !allowlist
                .split(',')
                .filter_map(|item| item.trim().parse::<u32>().ok())
                .any(|item| item == value)
            {
                return false;
            }
        }
    }
    configured || env::var("AGB_ADMIN_FAIL_CLOSED_CONFIG").ok().as_deref() != Some("1")
}

fn admin_token() -> String {
    env::var("AGB_ADMIN_TOKEN_FILE")
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|token| token.trim_end().to_owned())
        .or_else(|| env::var("AGB_ADMIN_TOKEN").ok())
        .unwrap_or_default()
}

fn handle(
    mut stream: UnixStream,
    cache: &PathBuf,
    audit: &PathBuf,
    requests: &mut HashMap<String, VecDeque<Instant>>,
) {
    let authorization_revision =
        env::var("AGB_ADMIN_AUTHZ_REVISION").unwrap_or_else(|_| "default-v1".into());
    let line = BufReader::new(stream.try_clone().unwrap())
        .lines()
        .next()
        .unwrap_or(Ok(String::new()))
        .unwrap_or_default();
    let request: Result<Request, _> = serde_json::from_str(&line);
    let credentials = peer_credentials(&stream);
    let peer = credentials
        .map(|c| format!("pid:{}:uid:{}:gid:{}", c.pid, c.uid, c.gid))
        .unwrap_or_else(|| "peer:unknown".into());
    let now = Instant::now();
    let rate_window = env::var("AGB_ADMIN_RATE_WINDOW_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60);
    let peer_requests = requests.entry(peer.clone()).or_default();
    while peer_requests
        .front()
        .is_some_and(|time| now.duration_since(*time) > Duration::from_secs(rate_window))
    {
        peer_requests.pop_front();
    }
    let operator = peer.clone();
    let response = if !peer_allowed(credentials) {
        Response {
            ok: false,
            reason: "peer-not-allowlisted".into(),
            operator: peer.clone(),
            authorization_revision: authorization_revision.clone(),
        }
    } else if peer_requests.len() >= 5 {
        Response {
            ok: false,
            reason: "rate-limit".into(),
            operator,
            authorization_revision: authorization_revision.clone(),
        }
    } else {
        peer_requests.push_back(now);
        let expected = admin_token();
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
                    operator: operator.clone(),
                    authorization_revision: authorization_revision.clone(),
                }
            }
            _ => Response {
                ok: false,
                reason: "invalid-token-or-request".into(),
                operator,
                authorization_revision,
            },
        }
    };
    let audit_result = (|| -> Result<(), String> {
        if let Some(parent) = audit.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(audit)
            .map_err(|e| e.to_string())?;
        serde_json::to_writer(&mut file, &response).map_err(|e| e.to_string())?;
        file.write_all(b"\n").map_err(|e| e.to_string())?;
        file.flush().map_err(|e| e.to_string())?;
        file.sync_data().map_err(|e| e.to_string())
    })();
    let response = if audit_result.is_ok() {
        response
    } else {
        Response {
            ok: false,
            reason: "audit-persistence-unavailable".into(),
            operator: peer,
            authorization_revision: env::var("AGB_ADMIN_AUTHZ_REVISION")
                .unwrap_or_else(|_| "default-v1".into()),
        }
    };
    let _ = serde_json::to_writer(&mut stream, &response);
    let _ = stream.write_all(b"\n");
    let _ = stream.flush();
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
    if let Some(parent) = audit.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit)
        .and_then(|file| file.sync_data())
        .map_err(|e| format!("admin audit unavailable: {e}"))?;
    let mut requests = HashMap::new();
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            handle(stream, &cache, &audit, &mut requests);
        }
    }
    Ok(())
}
