use crate::contracts::{PolicyDecision, SCHEMA_VERSION, SecurityEvent, SecurityStateSummary};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

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

pub const GATE3_CACHE_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct Gate3Profile {
    pub policy_revision: String,
    pub minimum_confidence: f64,
    pub ttl_seconds: u64,
}

impl Gate3Profile {
    pub fn validate(&self) -> Result<(), String> {
        if self.policy_revision.is_empty() || self.policy_revision.len() > 128 {
            return Err("invalid Gate 3 policy revision".into());
        }
        if !(0.0..=1.0).contains(&self.minimum_confidence) {
            return Err("minimum confidence must be between zero and one".into());
        }
        if self.ttl_seconds == 0 || self.ttl_seconds > 3600 {
            return Err("Gate 3 cache TTL must be between 1 and 3600 seconds".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompiledDecision {
    pub cache_key: String,
    pub decision_id: String,
    pub namespace_id: String,
    pub operation: String,
    pub resource_sha256: String,
    pub effect: String,
    pub policy_revision: String,
    pub state_revision: u64,
    pub evidence_sha256: String,
    pub expires_epoch: u64,
}

impl CompiledDecision {
    fn validate(&self) -> Result<(), String> {
        let digest =
            |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
        if self.cache_key.is_empty()
            || self.cache_key.len() > 1024
            || !self.decision_id.starts_with("dec:")
            || self.decision_id.len() > 128
            || self.namespace_id.is_empty()
            || self.namespace_id.len() > 512
            || !matches!(
                self.operation.as_str(),
                "process.exec"
                    | "process.exit"
                    | "file.open"
                    | "network.connect"
                    | "identity.change"
            )
            || !digest(&self.resource_sha256)
            || !digest(&self.evidence_sha256)
            || self.effect != "DENY"
            || self.policy_revision.is_empty()
            || self.policy_revision.len() > 128
            || self.state_revision == 0
            || self.expires_epoch == 0
        {
            return Err("invalid compiled Gate 3 decision".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheLookup {
    pub effect: String,
    pub decision_id: Option<String>,
    pub reason_code: String,
}

impl CacheLookup {
    fn abstain(reason_code: &str) -> Self {
        Self {
            effect: "ABSTAIN".into(),
            decision_id: None,
            reason_code: reason_code.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheSnapshot {
    format_version: u32,
    policy_revision: String,
    entries: Vec<CompiledDecision>,
    hmac_sha256: String,
}

#[derive(Debug, Default)]
pub struct CompiledDecisionCache {
    entries: BTreeMap<String, CompiledDecision>,
}

impl CompiledDecisionCache {
    pub fn put(
        &mut self,
        decision: CompiledDecision,
        active_policy_revision: &str,
    ) -> Result<(), String> {
        if decision.policy_revision != active_policy_revision {
            return Err("compiled decision policy revision mismatch".into());
        }
        decision.validate()?;
        self.entries.insert(decision.cache_key.clone(), decision);
        Ok(())
    }

    pub fn lookup(
        &mut self,
        cache_key: &str,
        policy_revision: &str,
        minimum_state_revision: u64,
        now_epoch: u64,
    ) -> CacheLookup {
        let Some(entry) = self.entries.get(cache_key).cloned() else {
            return CacheLookup::abstain("CACHE_MISS");
        };
        if entry.expires_epoch <= now_epoch {
            self.entries.remove(cache_key);
            return CacheLookup::abstain("CACHE_EXPIRED");
        }
        if entry.policy_revision != policy_revision {
            return CacheLookup::abstain("POLICY_REVISION_MISMATCH");
        }
        if entry.state_revision < minimum_state_revision {
            return CacheLookup::abstain("STATE_REVISION_STALE");
        }
        CacheLookup {
            effect: entry.effect,
            decision_id: Some(entry.decision_id),
            reason_code: "VERSIONED_CACHE_HIT".into(),
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn save_authenticated(
        &self,
        path: impl AsRef<Path>,
        policy_revision: &str,
        secret: &[u8],
    ) -> Result<(), String> {
        if secret.is_empty() {
            return Err("cache authentication key is required".into());
        }
        let entries: Vec<_> = self.entries.values().cloned().collect();
        let hmac_sha256 = snapshot_hmac(policy_revision, &entries, secret)?;
        let snapshot = CacheSnapshot {
            format_version: GATE3_CACHE_FORMAT_VERSION,
            policy_revision: policy_revision.into(),
            entries,
            hmac_sha256,
        };
        atomic_write_json(path.as_ref(), &snapshot)
    }

    pub fn load_authenticated(
        path: impl AsRef<Path>,
        expected_policy_revision: &str,
        secret: &[u8],
        now_epoch: u64,
    ) -> Result<Self, String> {
        if secret.is_empty() {
            return Err("cache authentication key is required".into());
        }
        let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
        let snapshot: CacheSnapshot =
            serde_json::from_slice(&bytes).map_err(|_| "invalid Gate 3 cache snapshot")?;
        if snapshot.format_version != GATE3_CACHE_FORMAT_VERSION {
            return Err("unsupported Gate 3 cache snapshot version".into());
        }
        if snapshot.policy_revision != expected_policy_revision {
            return Err("Gate 3 cache policy revision mismatch".into());
        }
        let expected = snapshot_hmac(&snapshot.policy_revision, &snapshot.entries, secret)?;
        if !constant_time_equal(expected.as_bytes(), snapshot.hmac_sha256.as_bytes()) {
            return Err("Gate 3 cache authentication failed".into());
        }
        let mut cache = Self::default();
        for entry in snapshot.entries {
            if entry.expires_epoch > now_epoch {
                cache.put(entry, expected_policy_revision)?;
            }
        }
        Ok(cache)
    }
}

pub struct Gate3Policy;

impl Gate3Policy {
    pub fn evaluate(
        event: &SecurityEvent,
        state: &SecurityStateSummary,
        profile: &Gate3Profile,
        _now_epoch: u64,
    ) -> PolicyDecision {
        let mut effect = "ABSTAIN";
        let mut reason = "STATE_UNKNOWN";
        let mut fail_closed = true;

        if profile.validate().is_err() {
            reason = "POLICY_CONFIGURATION_INVALID";
        } else if event.validate().is_err() {
            reason = "EVENT_CONTRACT_INVALID";
        } else if state.validate().is_err() {
            reason = "STATE_CONTRACT_INVALID";
        } else if event.policy_revision != profile.policy_revision {
            reason = "POLICY_REVISION_MISMATCH";
        } else if state.namespace_id != event.namespace_id {
            reason = "NAMESPACE_MISMATCH";
        } else if state.state_revision != event.sequence {
            reason = "STATE_REVISION_MISMATCH";
        } else if matches!(state.risk_band.as_str(), "restricted" | "quarantined") {
            effect = "DENY";
            reason = "STATIC_RESTRICTION_INVARIANT";
            fail_closed = false;
        } else if state.risk_band == "elevated" {
            if state.evidence_ids.is_empty() {
                reason = "CAUSAL_EVIDENCE_MISSING";
            } else if state
                .confidence
                .is_none_or(|value| value < profile.minimum_confidence)
            {
                reason = "MODEL_CONFIDENCE_INSUFFICIENT";
            } else if state.engine == "asm-cm" && state.checkpoint_fingerprint.is_none() {
                reason = "MODEL_REVISION_MISSING";
            } else {
                effect = "DENY";
                reason = "CAUSAL_RISK_ELEVATED";
                fail_closed = false;
            }
        } else if matches!(state.risk_band.as_str(), "normal" | "monitor") {
            effect = "ALLOW";
            reason = "NO_RESTRICTING_INVARIANT";
            fail_closed = false;
        } else if !matches!(state.risk_band.as_str(), "unknown") {
            reason = "RISK_BAND_UNSUPPORTED";
        }

        let decision_id = decision_id(event, state, &profile.policy_revision);
        PolicyDecision {
            schema_version: SCHEMA_VERSION.into(),
            decision_id,
            namespace_id: event.namespace_id.clone(),
            policy_revision: profile.policy_revision.clone(),
            state_revision: state.state_revision,
            mode: "audit".into(),
            effect: effect.into(),
            scope: format!("{}:{}", event.operation, event.resource.resource_type),
            reason_codes: vec![reason.into()],
            evidence_ids: state.evidence_ids.clone(),
            fail_closed,
            created_at: event.occurred_at.clone(),
            expires_at: None,
        }
    }

    pub fn compile(
        event: &SecurityEvent,
        decision: &PolicyDecision,
        profile: &Gate3Profile,
        now_epoch: u64,
    ) -> Option<CompiledDecision> {
        if decision.effect != "DENY"
            || decision.policy_revision != profile.policy_revision
            || decision.namespace_id != event.namespace_id
            || profile.validate().is_err()
            || event.validate().is_err()
            || decision.validate().is_err()
        {
            return None;
        }
        let resource_sha256 = resource_sha256(event);
        let cache_key = cache_key(event, &resource_sha256);
        let evidence_sha256 = sha256_json(&decision.evidence_ids);
        Some(CompiledDecision {
            cache_key,
            decision_id: decision.decision_id.clone(),
            namespace_id: event.namespace_id.clone(),
            operation: event.operation.clone(),
            resource_sha256,
            effect: decision.effect.clone(),
            policy_revision: decision.policy_revision.clone(),
            state_revision: decision.state_revision,
            evidence_sha256,
            expires_epoch: now_epoch.saturating_add(profile.ttl_seconds),
        })
    }

    pub fn evaluate_audit_and_compile(
        event: &SecurityEvent,
        state: &SecurityStateSummary,
        profile: &Gate3Profile,
        now_epoch: u64,
        audit_path: impl AsRef<Path>,
        cache: &mut CompiledDecisionCache,
    ) -> PolicyDecision {
        let decision = Self::evaluate(event, state, profile, now_epoch);
        if append_audit(audit_path.as_ref(), &decision).is_err() {
            return PolicyDecision {
                effect: "ABSTAIN".into(),
                reason_codes: vec!["AUDIT_PERSISTENCE_UNAVAILABLE".into()],
                fail_closed: true,
                ..decision
            };
        }
        if let Some(compiled) = Self::compile(event, &decision, profile, now_epoch) {
            if cache.put(compiled, &profile.policy_revision).is_err() {
                return PolicyDecision {
                    effect: "ABSTAIN".into(),
                    reason_codes: vec!["CACHE_COMPILATION_FAILED".into()],
                    fail_closed: true,
                    ..decision
                };
            }
        }
        decision
    }
}

pub fn gate3_cache_key(event: &SecurityEvent) -> String {
    cache_key(event, &resource_sha256(event))
}

fn resource_sha256(event: &SecurityEvent) -> String {
    sha256_json(&event.resource)
}

fn cache_key(event: &SecurityEvent, resource_sha256: &str) -> String {
    format!(
        "{}|{}|{}",
        event.namespace_id, event.operation, resource_sha256
    )
}

fn decision_id(event: &SecurityEvent, state: &SecurityStateSummary, revision: &str) -> String {
    let payload = format!(
        "{}\0{}\0{}\0{}",
        event.event_id, event.namespace_id, state.state_revision, revision
    );
    format!("dec:{:x}", Sha256::digest(payload.as_bytes()))
}

fn sha256_json(value: &impl Serialize) -> String {
    let encoded = serde_json::to_vec(value).expect("serializable Gate 3 value");
    format!("{:x}", Sha256::digest(encoded))
}

fn snapshot_hmac(
    policy_revision: &str,
    entries: &[CompiledDecision],
    secret: &[u8],
) -> Result<String, String> {
    let payload = serde_json::to_vec(&(GATE3_CACHE_FORMAT_VERSION, policy_revision, entries))
        .map_err(|error| error.to_string())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|error| error.to_string())?;
    mac.update(&payload);
    Ok(format!("{:x}", mac.finalize().into_bytes()))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn append_audit(path: &Path, decision: &PolicyDecision) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    serde_json::to_writer(&mut file, decision).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.flush().map_err(|error| error.to_string())?;
    file.sync_data().map_err(|error| error.to_string())
}

fn atomic_write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = temporary_path(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        serde_json::to_writer(&mut file, value).map_err(|error| error.to_string())?;
        file.write_all(b"\n").map_err(|error| error.to_string())?;
        file.flush().map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        std::fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{}.tmp", std::process::id()));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::sample_event;

    fn profile() -> Gate3Profile {
        Gate3Profile {
            policy_revision: "policy:gate0".into(),
            minimum_confidence: 0.8,
            ttl_seconds: 10,
        }
    }

    fn state(event: &SecurityEvent, risk_band: &str) -> SecurityStateSummary {
        SecurityStateSummary {
            schema_version: SCHEMA_VERSION.into(),
            namespace_id: event.namespace_id.clone(),
            state_revision: event.sequence,
            risk_band: risk_band.into(),
            confidence: Some(0.95),
            signals: vec!["configured-causal-relation".into()],
            evidence_ids: vec![event.event_id.clone()],
            engine: "asm-cm".into(),
            checkpoint_fingerprint: Some("sha256:model".into()),
            updated_at: event.occurred_at.clone(),
        }
    }

    #[test]
    fn elevated_evidence_compiles_to_expiring_deny() {
        let event = sample_event("evt:gate3-deny", 1, 77, 100);
        let state = state(&event, "elevated");
        let decision = Gate3Policy::evaluate(&event, &state, &profile(), 1000);
        assert_eq!(decision.effect, "DENY");
        assert_eq!(decision.reason_codes, ["CAUSAL_RISK_ELEVATED"]);
        assert!(decision.validate().is_ok());
        let compiled = Gate3Policy::compile(&event, &decision, &profile(), 1000).unwrap();
        assert_eq!(compiled.expires_epoch, 1010);
        let mut forbidden_allow = compiled.clone();
        forbidden_allow.effect = "ALLOW".into();
        assert!(
            CompiledDecisionCache::default()
                .put(forbidden_allow, "policy:gate0")
                .is_err()
        );
        let mut cache = CompiledDecisionCache::default();
        cache.put(compiled.clone(), "policy:gate0").unwrap();
        assert_eq!(
            cache
                .lookup(&compiled.cache_key, "policy:gate0", 1, 1001)
                .effect,
            "DENY"
        );
        assert_eq!(
            cache
                .lookup(&compiled.cache_key, "policy:gate0", 1, 1010)
                .reason_code,
            "CACHE_EXPIRED"
        );
    }

    #[test]
    fn invariants_abstain_and_never_compile_permission() {
        let event = sample_event("evt:gate3-abstain", 1, 78, 100);
        let mut low_confidence = state(&event, "elevated");
        low_confidence.confidence = Some(0.2);
        let decision = Gate3Policy::evaluate(&event, &low_confidence, &profile(), 1000);
        assert_eq!(decision.effect, "ABSTAIN");
        assert!(decision.fail_closed);
        assert!(Gate3Policy::compile(&event, &decision, &profile(), 1000).is_none());

        let mut mismatch = state(&event, "normal");
        mismatch.namespace_id.push_str(":other");
        let decision = Gate3Policy::evaluate(&event, &mismatch, &profile(), 1000);
        assert_eq!(decision.effect, "ABSTAIN");
        assert_eq!(decision.reason_codes, ["NAMESPACE_MISMATCH"]);

        let restricted = state(&event, "restricted");
        let decision = Gate3Policy::evaluate(&event, &restricted, &profile(), 1000);
        assert_eq!(decision.effect, "DENY");
        assert_eq!(decision.reason_codes, ["STATIC_RESTRICTION_INVARIANT"]);

        let normal = state(&event, "normal");
        let decision = Gate3Policy::evaluate(&event, &normal, &profile(), 1000);
        assert_eq!(decision.effect, "ALLOW");
        assert!(Gate3Policy::compile(&event, &decision, &profile(), 1000).is_none());
    }

    #[test]
    fn audit_failure_abstains_without_populating_cache() {
        let directory = tempfile::tempdir().unwrap();
        let audit_path = directory.path().join("audit-directory");
        std::fs::create_dir(&audit_path).unwrap();
        let event = sample_event("evt:gate3-audit", 1, 79, 100);
        let mut cache = CompiledDecisionCache::default();
        let decision = Gate3Policy::evaluate_audit_and_compile(
            &event,
            &state(&event, "normal"),
            &profile(),
            1000,
            audit_path,
            &mut cache,
        );
        assert_eq!(decision.effect, "ABSTAIN");
        assert_eq!(decision.reason_codes, ["AUDIT_PERSISTENCE_UNAVAILABLE"]);
        assert!(cache.is_empty());
    }

    #[test]
    fn authenticated_restart_corruption_revision_and_namespace_isolation() {
        let directory = tempfile::tempdir().unwrap();
        let snapshot = directory.path().join("gate3-cache.json");
        let first = sample_event("evt:gate3-first", 1, 80, 100);
        let second = sample_event("evt:gate3-second", 1, 80, 200);
        let mut cache = CompiledDecisionCache::default();
        for event in [&first, &second] {
            let decision =
                Gate3Policy::evaluate(event, &state(event, "restricted"), &profile(), 1000);
            cache
                .put(
                    Gate3Policy::compile(event, &decision, &profile(), 1000).unwrap(),
                    "policy:gate0",
                )
                .unwrap();
        }
        assert_eq!(cache.len(), 2);
        cache
            .save_authenticated(&snapshot, "policy:gate0", b"test-secret")
            .unwrap();
        let mut restored = CompiledDecisionCache::load_authenticated(
            &snapshot,
            "policy:gate0",
            b"test-secret",
            1001,
        )
        .unwrap();
        assert_eq!(restored.len(), 2);
        let first_key = gate3_cache_key(&first);
        let second_key = gate3_cache_key(&second);
        assert_ne!(first_key, second_key);
        assert_eq!(
            restored
                .lookup(&first_key, "policy:new", 1, 1001)
                .reason_code,
            "POLICY_REVISION_MISMATCH"
        );
        assert_eq!(
            restored
                .lookup(&second_key, "policy:gate0", 2, 1001)
                .reason_code,
            "STATE_REVISION_STALE"
        );

        let mut corrupted: CacheSnapshot =
            serde_json::from_slice(&std::fs::read(&snapshot).unwrap()).unwrap();
        let replacement = if corrupted.hmac_sha256.starts_with('0') {
            "1"
        } else {
            "0"
        };
        corrupted.hmac_sha256.replace_range(0..1, replacement);
        std::fs::write(&snapshot, serde_json::to_vec(&corrupted).unwrap()).unwrap();
        assert!(
            CompiledDecisionCache::load_authenticated(
                &snapshot,
                "policy:gate0",
                b"test-secret",
                1001
            )
            .unwrap_err()
            .contains("authentication")
        );
        restored.clear();
        assert!(restored.is_empty());
    }
}
