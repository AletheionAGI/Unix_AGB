use crate::contracts::{EnforcementRecord, PolicyDecision, SCHEMA_VERSION};

pub struct FakeEnforcer;

impl FakeEnforcer {
    pub fn record(decision: &PolicyDecision) -> EnforcementRecord {
        EnforcementRecord {
            schema_version: SCHEMA_VERSION.into(),
            decision_id: decision.decision_id.clone(),
            backend: "fake".into(),
            requested_effect: decision.effect.clone(),
            applied: false,
            latency_us: Some(0),
            policy_revision: decision.policy_revision.clone(),
            recorded_at: decision.created_at.clone(),
        }
    }
}
