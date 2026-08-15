use std::collections::BTreeMap;
use unix_agb::SecurityEvent;
use unix_agb::enforcer::FakeEnforcer;
use unix_agb::policy::AuditPolicy;
use unix_agb::state::FakeStateEngine;

#[test]
fn identical_terminal_actions_diverge_due_to_prior_trajectory() {
    let fixture = include_str!("../fixtures/events/causal-pair.jsonl");
    let mut engine = FakeStateEngine::default();
    let mut terminal = BTreeMap::new();

    for line in fixture.lines() {
        let event: SecurityEvent = serde_json::from_str(line).unwrap();
        event.validate().unwrap();
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
            let case = event.provenance.attributes["case"].as_str().unwrap();
            terminal.insert(
                case.to_owned(),
                (event.operation, event.resource, decision, enforcement),
            );
        }
    }

    let benign = &terminal["benign"];
    let suspicious = &terminal["suspicious"];
    assert_eq!(benign.0, suspicious.0);
    assert_eq!(benign.1, suspicious.1);
    assert_eq!(benign.2.effect, "ALLOW");
    assert_eq!(suspicious.2.effect, "DENY");
    assert_eq!(
        suspicious.2.evidence_ids,
        [
            "evt:suspicious-exec",
            "evt:suspicious-egress",
            "evt:suspicious-final"
        ]
    );
    assert!(!benign.3.applied);
    assert!(!suspicious.3.applied);
}
