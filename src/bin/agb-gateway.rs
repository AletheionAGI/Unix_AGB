use serde_json::json;
use std::env;
use std::io::{self, BufRead};
use unix_agb::SecurityEvent;
use unix_agb::enforcer::FakeEnforcer;
use unix_agb::policy::AuditPolicy;
use unix_agb::state::FakeStateEngine;
use unix_agb::store::CanonicalStore;

const DEFAULT_STORE: &str = "var/events.jsonl";
const MAX_EVENT_BYTES: usize = 64 * 1024;

fn store_arg() -> String {
    let args: Vec<String> = env::args().collect();
    args.windows(2)
        .find(|pair| pair[0] == "--store")
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| DEFAULT_STORE.into())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("agb-gateway: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut store = CanonicalStore::open(store_arg())?;
    let mut state_engine = FakeStateEngine::default();

    for (line_number, line) in io::stdin().lock().lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > MAX_EVENT_BYTES {
            return Err(format!(
                "line {} exceeds {} bytes",
                line_number + 1,
                MAX_EVENT_BYTES
            ));
        }
        let event: SecurityEvent = serde_json::from_str(&line)
            .map_err(|e| format!("line {} is not a SecurityEvent: {e}", line_number + 1))?;
        event
            .validate()
            .map_err(|e| format!("line {} failed validation: {e}", line_number + 1))?;
        store.append(&event)?;
        let state = state_engine.update(&event);
        let decision = AuditPolicy::evaluate(&event, &state);
        let enforcement = FakeEnforcer::record(&decision);
        let output = json!({
            "event_id": event.event_id,
            "state": state,
            "decision": decision,
            "enforcement": enforcement
        });
        println!(
            "{}",
            serde_json::to_string(&output).map_err(|e| e.to_string())?
        );
    }
    Ok(())
}
