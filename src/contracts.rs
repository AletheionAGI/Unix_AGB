use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub boot_id: String,
    pub start_time_ns: u64,
    pub exe: String,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub container_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Resource {
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(flatten)]
    pub attributes: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Provenance {
    pub source: String,
    #[serde(flatten)]
    pub attributes: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub schema_version: String,
    pub event_id: String,
    pub sequence: u64,
    pub occurred_at: String,
    pub monotonic_ns: u64,
    pub host_id: String,
    pub namespace_id: String,
    pub subject: Subject,
    pub operation: String,
    pub resource: Resource,
    pub result: String,
    pub policy_revision: String,
    pub labels: Vec<String>,
    pub provenance: Provenance,
}

impl SecurityEvent {
    pub fn expected_process_namespace(&self) -> String {
        format!(
            "process:{}:{}:{}",
            self.subject.boot_id, self.subject.pid, self.subject.start_time_ns
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported schema_version".into());
        }
        if !valid_prefixed_id(&self.event_id, "evt:", 128) {
            return Err("invalid event_id".into());
        }
        if self.sequence == 0 {
            return Err("sequence must be positive".into());
        }
        if self.subject.pid == 0 || self.subject.start_time_ns == 0 {
            return Err("process identity requires pid and start_time_ns".into());
        }
        if self.namespace_id != self.expected_process_namespace() {
            return Err("namespace does not match stable process identity".into());
        }
        if !valid_prefixed_id(&self.host_id, "host:", 160) {
            return Err("invalid host_id".into());
        }
        if self.namespace_id.len() > 512
            || self.subject.boot_id.is_empty()
            || self.subject.boot_id.len() > 128
            || self.subject.exe.len() > 4096
            || self.subject.service.as_ref().is_some_and(|v| v.len() > 256)
            || self
                .subject
                .container_id
                .as_ref()
                .is_some_and(|v| v.len() > 256)
            || self
                .subject
                .agent_id
                .as_ref()
                .is_some_and(|v| v.len() > 256)
            || self.policy_revision.is_empty()
            || self.policy_revision.len() > 128
        {
            return Err("field length exceeds contract".into());
        }
        if !matches!(
            self.operation.as_str(),
            "process.exec" | "process.exit" | "file.open" | "network.connect" | "identity.change"
        ) {
            return Err("unsupported operation".into());
        }
        if !matches!(
            self.result.as_str(),
            "requested" | "allowed" | "denied" | "failed"
        ) {
            return Err("unsupported result".into());
        }
        if !matches!(
            self.provenance.source.as_str(),
            "synthetic" | "ptrace" | "bpf" | "audit" | "agent-broker"
        ) {
            return Err("unsupported provenance source".into());
        }
        if self.resource.resource_type.is_empty()
            || self.resource.resource_type.len() > 64
            || self.subject.exe.is_empty()
        {
            return Err("resource type and executable are required".into());
        }
        if self.labels.len() > 32
            || self.labels.iter().any(|label| label.len() > 64)
            || !all_unique(&self.labels)
        {
            return Err("invalid labels".into());
        }
        Ok(())
    }
}

fn valid_prefixed_id(value: &str, prefix: &str, max_len: usize) -> bool {
    value.len() <= max_len
        && value.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
}

fn all_unique(values: &[String]) -> bool {
    let mut seen = std::collections::HashSet::new();
    values.iter().all(|value| seen.insert(value))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityStateSummary {
    pub schema_version: String,
    pub namespace_id: String,
    pub state_revision: u64,
    pub risk_band: String,
    pub confidence: Option<f64>,
    pub signals: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub engine: String,
    pub checkpoint_fingerprint: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub namespace_id: String,
    pub policy_revision: String,
    pub state_revision: u64,
    pub mode: String,
    pub effect: String,
    pub scope: String,
    pub reason_codes: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub fail_closed: bool,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnforcementRecord {
    pub schema_version: String,
    pub decision_id: String,
    pub backend: String,
    pub requested_effect: String,
    pub applied: bool,
    pub latency_us: Option<u64>,
    pub policy_revision: String,
    pub recorded_at: String,
}

#[cfg(test)]
pub fn sample_event(event_id: &str, sequence: u64, pid: u32, start: u64) -> SecurityEvent {
    SecurityEvent {
        schema_version: SCHEMA_VERSION.into(),
        event_id: event_id.into(),
        sequence,
        occurred_at: "2026-08-15T20:00:00Z".into(),
        monotonic_ns: sequence * 1_000,
        host_id: "host:test".into(),
        namespace_id: format!("process:boot-test:{pid}:{start}"),
        subject: Subject {
            pid,
            uid: 1000,
            gid: 1000,
            boot_id: "boot-test".into(),
            start_time_ns: start,
            exe: "/usr/bin/test".into(),
            service: None,
            container_id: None,
            agent_id: None,
        },
        operation: "process.exec".into(),
        resource: Resource {
            resource_type: "process".into(),
            attributes: BTreeMap::new(),
        },
        result: "allowed".into(),
        policy_revision: "policy:gate0".into(),
        labels: vec![],
        provenance: Provenance {
            source: "synthetic".into(),
            attributes: BTreeMap::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_matches_identifier_and_label_contracts() {
        let mut event = sample_event("evt:valid-1", 1, 10, 20);
        assert!(event.validate().is_ok());
        event.event_id = "evt:invalid/value".into();
        assert_eq!(event.validate().unwrap_err(), "invalid event_id");

        let mut event = sample_event("evt:valid-2", 1, 10, 20);
        event.labels = vec!["duplicate".into(), "duplicate".into()];
        assert_eq!(event.validate().unwrap_err(), "invalid labels");
    }
}
