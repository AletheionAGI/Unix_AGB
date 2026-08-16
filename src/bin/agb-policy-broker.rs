use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct Request {
    namespace_id: String,
    resource: String,
    policy_revision: String,
    requested_effect: String,
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

struct Broker {
    cache: HashMap<String, Cached>,
    ttl: Duration,
    audit_path: PathBuf,
}

impl Broker {
    fn decide(&mut self, request: Result<Request, serde_json::Error>) -> Response {
        let request = match request {
            Ok(request) if !request.namespace_id.is_empty() && !request.resource.is_empty() => {
                request
            }
            _ => return Self::fallback("invalid request"),
        };
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
            key,
            Cached {
                effect: effect.into(),
                policy_revision: request.policy_revision.clone(),
                expires: Instant::now() + self.ttl,
            },
        );
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
    let socket_path = PathBuf::from(&socket);
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).map_err(|e| e.to_string())?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(&socket_path).map_err(|e| e.to_string())?;
    let mut broker = Broker {
        cache: HashMap::new(),
        ttl: Duration::from_secs(2),
        audit_path: PathBuf::from(audit),
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
