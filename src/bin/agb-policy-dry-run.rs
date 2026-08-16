use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use unix_agb::policy::{
    CompiledDecisionCache, Gate3AuditLog, Gate3Policy, Gate3Profile, gate3_cache_key,
};
use unix_agb::{PolicyDecision, SecurityEvent, SecurityStateSummary};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    event: SecurityEvent,
    state: SecurityStateSummary,
}

#[derive(Serialize)]
struct Response {
    decision: PolicyDecision,
    cache_key: String,
    enforcement_applied: bool,
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

fn main() -> Result<(), String> {
    let audit_path = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "var/gate3-decisions.jsonl".into()),
    );
    let cache_path = PathBuf::from(
        std::env::args()
            .nth(2)
            .unwrap_or_else(|| "var/gate3-cache.json".into()),
    );
    let profile = Gate3Profile {
        policy_revision: required_env("AGB_GATE3_POLICY_REVISION")?,
        minimum_confidence: std::env::var("AGB_GATE3_MIN_CONFIDENCE")
            .unwrap_or_else(|_| "0.8".into())
            .parse()
            .map_err(|_| "AGB_GATE3_MIN_CONFIDENCE must be numeric".to_string())?,
        ttl_seconds: std::env::var("AGB_GATE3_TTL_SECONDS")
            .unwrap_or_else(|_| "2".into())
            .parse()
            .map_err(|_| "AGB_GATE3_TTL_SECONDS must be an integer".to_string())?,
    };
    profile.validate()?;
    let secret = required_env("AGB_GATE3_CACHE_KEY")?;
    let audit_group_size = std::env::var("AGB_GATE3_AUDIT_GROUP_SIZE")
        .unwrap_or_else(|_| "64".into())
        .parse::<usize>()
        .map_err(|_| "AGB_GATE3_AUDIT_GROUP_SIZE must be an integer".to_string())?;
    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let mut cache = if cache_path.exists() {
        CompiledDecisionCache::load_authenticated(
            &cache_path,
            &profile.policy_revision,
            secret.as_bytes(),
            now_epoch,
        )?
    } else {
        CompiledDecisionCache::default()
    };
    let mut audit = Gate3AuditLog::open(&audit_path, audit_group_size)?;

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for (line_number, line) in stdin.lock().lines().enumerate() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Request = serde_json::from_str(&line)
            .map_err(|error| format!("invalid request at line {}: {error}", line_number + 1))?;
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs();
        let cache_key = gate3_cache_key(&request.event);
        let decision = Gate3Policy::evaluate_grouped_audit_and_compile(
            &request.event,
            &request.state,
            &profile,
            now_epoch,
            &mut audit,
            &mut cache,
        );
        if decision.effect == "DENY" {
            cache.save_authenticated(&cache_path, &profile.policy_revision, secret.as_bytes())?;
        }
        serde_json::to_writer(
            &mut stdout,
            &Response {
                decision,
                cache_key,
                enforcement_applied: false,
            },
        )
        .map_err(|error| error.to_string())?;
        stdout.write_all(b"\n").map_err(|error| error.to_string())?;
        stdout.flush().map_err(|error| error.to_string())?;
    }
    audit.sync()?;
    Ok(())
}
