use crate::contracts::{PolicyDecision, SCHEMA_VERSION, SecurityEvent, SecurityStateSummary};

pub struct AuditPolicy;

impl AuditPolicy {
    pub fn evaluate(event: &SecurityEvent, state: &SecurityStateSummary) -> PolicyDecision {
        let elevated = state.risk_band == "elevated";
        PolicyDecision {
            schema_version: SCHEMA_VERSION.into(),
            decision_id: format!("dec:{}", event.event_id.trim_start_matches("evt:")),
            namespace_id: event.namespace_id.clone(),
            policy_revision: event.policy_revision.clone(),
            state_revision: state.state_revision,
            mode: "audit".into(),
            effect: if elevated { "DENY" } else { "ALLOW" }.into(),
            scope: if elevated {
                "trajectory.elevated"
            } else {
                "trajectory.normal"
            }
            .into(),
            reason_codes: vec![
                if elevated {
                    "CAUSAL_TRAJECTORY_ELEVATED"
                } else {
                    "NO_RESTRICTING_TRAJECTORY"
                }
                .into(),
            ],
            evidence_ids: state.evidence_ids.clone(),
            fail_closed: false,
            created_at: event.occurred_at.clone(),
            expires_at: None,
        }
    }
}
