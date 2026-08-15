use crate::contracts::{SCHEMA_VERSION, SecurityEvent, SecurityStateSummary};
use std::collections::HashMap;

#[derive(Debug, Default)]
struct NamespaceState {
    revision: u64,
    saw_exec: bool,
    saw_network_after_exec: bool,
    exec_event_id: Option<String>,
    network_event_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct FakeStateEngine {
    namespaces: HashMap<String, NamespaceState>,
}

impl FakeStateEngine {
    pub fn update(&mut self, event: &SecurityEvent) -> SecurityStateSummary {
        let state = self
            .namespaces
            .entry(event.namespace_id.clone())
            .or_default();
        state.revision += 1;

        if event.operation == "process.exec" {
            state.saw_exec = true;
            state.exec_event_id = Some(event.event_id.clone());
        }
        if event.operation == "network.connect" && state.saw_exec {
            state.saw_network_after_exec = true;
            state.network_event_id = Some(event.event_id.clone());
        }

        let sensitive_access = event.operation == "file.open"
            && event.labels.iter().any(|label| label == "credential");
        let elevated = state.saw_network_after_exec && sensitive_access;
        let mut signals = Vec::new();
        if state.saw_exec {
            signals.push("exec_observed".into());
        }
        if state.saw_network_after_exec {
            signals.push("network_after_exec".into());
        }
        if sensitive_access {
            signals.push("credential_access".into());
        }
        if elevated {
            signals.push("exec_network_credential_chain".into());
        }
        let mut evidence_ids = Vec::new();
        if let Some(event_id) = &state.exec_event_id {
            evidence_ids.push(event_id.clone());
        }
        if let Some(event_id) = &state.network_event_id {
            evidence_ids.push(event_id.clone());
        }
        if !evidence_ids.contains(&event.event_id) {
            evidence_ids.push(event.event_id.clone());
        }

        SecurityStateSummary {
            schema_version: SCHEMA_VERSION.into(),
            namespace_id: event.namespace_id.clone(),
            state_revision: state.revision,
            risk_band: if elevated { "elevated" } else { "normal" }.into(),
            confidence: None,
            signals,
            evidence_ids,
            engine: "fake".into(),
            checkpoint_fingerprint: None,
            updated_at: event.occurred_at.clone(),
        }
    }

    pub fn namespace_count(&self) -> usize {
        self.namespaces.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::sample_event;

    #[test]
    fn pid_reuse_does_not_share_state() {
        let mut engine = FakeStateEngine::default();
        engine.update(&sample_event("evt:a", 1, 42, 100));
        engine.update(&sample_event("evt:b", 1, 42, 200));
        assert_eq!(engine.namespace_count(), 2);
    }
}
