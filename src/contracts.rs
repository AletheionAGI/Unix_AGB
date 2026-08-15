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
        if !self.event_id.starts_with("evt:") || self.event_id.len() > 128 {
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
        if !self.host_id.starts_with("host:") {
            return Err("invalid host_id".into());
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
        if self.resource.resource_type.is_empty() || self.subject.exe.is_empty() {
            return Err("resource type and executable are required".into());
        }
        Ok(())
    }
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
