use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct Request {
    #[serde(rename = "type", default)]
    request_type: Option<String>,
    namespace_id: String,
    resource: String,
    policy_revision: String,
    requested_effect: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    operation: Option<String>,
}

#[derive(Debug, Serialize)]
struct Response {
    schema_version: &'static str,
    effect: String,
    backend: &'static str,
    applied: bool,
    cache_hit: bool,
    fallback: bool,
    policy_revision: String,
    reason: String,
}

#[derive(Clone)]
struct Cached {
    effect: String,
    policy_revision: String,
    expires: Instant,
}

#[derive(Debug, Deserialize, Serialize)]
struct PersistedCache {
    format_version: u32,
    key: String,
    effect: String,
    policy_revision: String,
    expires_epoch: u64,
    checksum: String,
}

fn cache_checksum(key: &str, effect: &str, revision: &str, expires: u64) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(key.as_bytes());
    payload.push(0);
    payload.extend_from_slice(effect.as_bytes());
    payload.push(0);
    payload.extend_from_slice(revision.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&expires.to_le_bytes());
    if let Ok(secret) = std::env::var("AGB_CACHE_KEY") {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys");
        mac.update(&payload);
        format!("hmac-sha256:{:x}", mac.finalize().into_bytes())
    } else {
        format!("sha256:{:x}", Sha256::digest(&payload))
    }
}

struct Broker {
    cache: HashMap<String, Cached>,
    ttl: Duration,
    audit_path: PathBuf,
    cache_path: PathBuf,
}

impl Broker {
    fn decide(&mut self, request: Result<Request, serde_json::Error>) -> Response {
        let request = match request {
            Ok(request) => request,
            _ => return Self::fallback("invalid request"),
        };
        if request.request_type.as_deref() == Some("admin") {
            let expected = std::env::var("AGB_ADMIN_TOKEN").unwrap_or_default();
            if expected.is_empty() || request.token.as_deref() != Some(expected.as_str()) {
                return Self::fallback("invalid admin token");
            }
            return match request.operation.as_deref() {
                Some("list") => self.record(Response {
                    schema_version: "1.0",
                    effect: "ALLOW".into(),
                    backend: "seccomp-user-notify",
                    applied: false,
                    cache_hit: false,
                    fallback: false,
                    policy_revision: "policy:admin".into(),
                    reason: "admin-list-ok".into(),
                }),
                Some("rotate") => {
                    let rotated = format!("{}.rotated", self.cache_path.display());
                    let result = if self.cache_path.exists() {
                        std::fs::rename(&self.cache_path, rotated).is_ok()
                    } else {
                        true
                    };
                    self.cache.clear();
                    self.record(Response {
                        schema_version: "1.0",
                        effect: if result { "ALLOW" } else { "DENY" }.into(),
                        backend: "seccomp-user-notify",
                        applied: result,
                        cache_hit: false,
                        fallback: !result,
                        policy_revision: "policy:admin".into(),
                        reason: if result {
                            "admin-rotate-ok"
                        } else {
                            "admin-rotate-failed"
                        }
                        .into(),
                    })
                }
                _ => Self::fallback("unsupported admin operation"),
            };
        }
        if request.namespace_id.is_empty() || request.resource.is_empty() {
            return Self::fallback("invalid request");
        }
        if request.request_type.as_deref() == Some("health") {
            return self.record(Response {
                schema_version: "1.0",
                effect: "ALLOW".into(),
                backend: "seccomp-user-notify",
                applied: false,
                cache_hit: false,
                fallback: false,
                policy_revision: "policy:health-probe".into(),
                reason: "health-ok".into(),
            });
        }
        let key = format!("{}|{}", request.namespace_id, request.resource);
        if let Some(cached) = self.cache.get(&key).cloned() {
            if cached.expires > Instant::now() && cached.policy_revision == request.policy_revision
            {
                return self.record(Response {
                    schema_version: "1.0",
                    effect: cached.effect,
                    backend: "seccomp-user-notify",
                    applied: true,
                    cache_hit: true,
                    fallback: false,
                    policy_revision: request.policy_revision,
                    reason: "versioned-cache-hit".into(),
                });
            }
        }
        let effect = match request.requested_effect.as_str() {
            "ALLOW" => "ALLOW",
            "DENY" => "DENY",
            _ => return Self::fallback("unsupported requested effect"),
        };
        self.cache.insert(
            key.clone(),
            Cached {
                effect: effect.into(),
                policy_revision: request.policy_revision.clone(),
                expires: Instant::now() + self.ttl,
            },
        );
        let expires_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + self.ttl.as_secs();
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.cache_path)
        {
            let _ = serde_json::to_writer(
                &mut file,
                &PersistedCache {
                    format_version: 1,
                    key: key.clone(),
                    effect: effect.into(),
                    policy_revision: request.policy_revision.clone(),
                    expires_epoch,
                    checksum: cache_checksum(&key, effect, &request.policy_revision, expires_epoch),
                },
            );
            let _ = file.write_all(b"\n");
        }
        self.record(Response {
            schema_version: "1.0",
            effect: effect.into(),
            backend: "seccomp-user-notify",
            applied: true,
            cache_hit: false,
            fallback: false,
            policy_revision: request.policy_revision,
            reason: "gateway-decision".into(),
        })
    }

    fn fallback(reason: &str) -> Response {
        Response {
            schema_version: "1.0",
            effect: "DENY".into(),
            backend: "seccomp-user-notify",
            applied: true,
            cache_hit: false,
            fallback: true,
            policy_revision: "policy:fallback-fail-closed".into(),
            reason: reason.into(),
        }
    }

    fn record(&self, response: Response) -> Response {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_path)
        {
            let _ = serde_json::to_writer(&mut file, &response);
            let _ = file.write_all(b"\n");
        }
        response
    }
}

fn handle(mut stream: UnixStream, broker: &mut Broker) {
    let reader = match stream.try_clone() {
        Ok(stream) => BufReader::new(stream),
        Err(_) => return,
    };
    for line in reader.lines() {
        let response = broker.decide(serde_json::from_str::<Request>(&line.unwrap_or_default()));
        if serde_json::to_writer(&mut stream, &response).is_err() {
            return;
        }
        let _ = stream.write_all(b"\n");
        let _ = stream.flush();
    }
}

fn main() -> Result<(), String> {
    let socket = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "var/agb-policy.sock".into());
    let audit = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "var/enforcement.jsonl".into());
    let cache_path = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "var/policy-cache.jsonl".into());
    if std::env::var("AGB_CACHE_ROTATE").as_deref() == Ok("1") {
        let rotated = format!("{}.rotated", cache_path);
        if PathBuf::from(&cache_path).exists() {
            std::fs::rename(&cache_path, rotated).map_err(|e| e.to_string())?;
        }
    }
    let socket_path = PathBuf::from(&socket);
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).map_err(|e| e.to_string())?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(&socket_path).map_err(|e| e.to_string())?;
    let mut cache = HashMap::new();
    if let Ok(file) = std::fs::File::open(&cache_path) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if let Ok(entry) = serde_json::from_str::<PersistedCache>(&line) {
                if entry.format_version == 1
                    && entry.checksum
                        == cache_checksum(
                            &entry.key,
                            &entry.effect,
                            &entry.policy_revision,
                            entry.expires_epoch,
                        )
                    && entry.expires_epoch > now
                {
                    cache.insert(
                        entry.key,
                        Cached {
                            effect: entry.effect,
                            policy_revision: entry.policy_revision,
                            expires: Instant::now()
                                + Duration::from_secs(entry.expires_epoch - now),
                        },
                    );
                }
            }
        }
    }
    if !cache.is_empty() {
        let compact_path = format!("{}.compact", cache_path);
        if let Ok(mut compact) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&compact_path)
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            for (key, entry) in &cache {
                let persisted = PersistedCache {
                    format_version: 1,
                    key: key.clone(),
                    effect: entry.effect.clone(),
                    policy_revision: entry.policy_revision.clone(),
                    expires_epoch: now
                        + entry
                            .expires
                            .saturating_duration_since(Instant::now())
                            .as_secs(),
                    checksum: cache_checksum(
                        key,
                        &entry.effect,
                        &entry.policy_revision,
                        now + entry
                            .expires
                            .saturating_duration_since(Instant::now())
                            .as_secs(),
                    ),
                };
                let _ = serde_json::to_writer(&mut compact, &persisted);
                let _ = compact.write_all(b"\n");
            }
            let _ = compact.flush();
            if compact.sync_all().is_ok() && std::fs::rename(&compact_path, &cache_path).is_ok() {
                if let Some(parent) = PathBuf::from(&cache_path).parent() {
                    if let Ok(directory) = std::fs::File::open(parent) {
                        let _ = directory.sync_all();
                    }
                }
            }
        }
    }
    let mut broker = Broker {
        cache,
        ttl: Duration::from_secs(2),
        audit_path: PathBuf::from(audit),
        cache_path: PathBuf::from(cache_path),
    };
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle(stream, &mut broker),
            Err(error) => eprintln!("broker accept: {error}"),
        }
    }
    let _ = SystemTime::now().duration_since(UNIX_EPOCH);
    Ok(())
}
