use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use unix_agb::SecurityEvent;
use unix_agb::enforcer::FakeEnforcer;
use unix_agb::policy::AuditPolicy;
use unix_agb::state::FakeStateEngine;

#[derive(Serialize)]
struct Outcome {
    terminal_operation: String,
    terminal_resource: serde_json::Value,
    trajectory_signals: Vec<String>,
    causal_evidence_ids: Vec<String>,
    shadow_effect: String,
    enforcement_applied: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("agb-causal-proof: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fixtures/events/causal-pair.jsonl".into());
    let reader = BufReader::new(File::open(path).map_err(|error| error.to_string())?);
    let mut engine = FakeStateEngine::default();
    let mut outcomes = BTreeMap::new();

    for line in reader.lines() {
        let event: SecurityEvent = serde_json::from_str(&line.map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        event.validate()?;
        let state = engine.update(&event);
        let decision = AuditPolicy::evaluate(&event, &state);
        let enforcement = FakeEnforcer::record(&decision);
        if event
            .provenance
            .attributes
            .get("terminal")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            let case = event
                .provenance
                .attributes
                .get("case")
                .and_then(serde_json::Value::as_str)
                .ok_or("terminal event has no case")?;
            outcomes.insert(
                case.to_owned(),
                Outcome {
                    terminal_operation: event.operation,
                    terminal_resource: serde_json::to_value(event.resource)
                        .map_err(|error| error.to_string())?,
                    trajectory_signals: state.signals,
                    causal_evidence_ids: decision.evidence_ids,
                    shadow_effect: decision.effect,
                    enforcement_applied: enforcement.applied,
                },
            );
        }
    }

    let benign = outcomes.get("benign").ok_or("missing benign outcome")?;
    let suspicious = outcomes
        .get("suspicious")
        .ok_or("missing suspicious outcome")?;
    if benign.terminal_operation != suspicious.terminal_operation
        || benign.terminal_resource != suspicious.terminal_resource
    {
        return Err("terminal actions are not identical".into());
    }
    if benign.shadow_effect != "ALLOW" || suspicious.shadow_effect != "DENY" {
        return Err("causal policy did not produce ALLOW versus DENY".into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&outcomes).map_err(|error| error.to_string())?
    );
    Ok(())
}
