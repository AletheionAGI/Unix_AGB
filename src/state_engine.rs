use crate::{SecurityEvent, SecurityStateSummary};

/// Replaceable boundary for deterministic baselines and future ASM-CM adapters.
///
/// Implementations must isolate state by the complete namespace identifier and
/// return an error rather than infer permissive state after restore or sequence
/// failures.
pub trait StateEngine {
    fn name(&self) -> &'static str;
    fn update(&mut self, event: &SecurityEvent) -> Result<SecurityStateSummary, String>;
}

impl StateEngine for crate::state::FakeStateEngine {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn update(&mut self, event: &SecurityEvent) -> Result<SecurityStateSummary, String> {
        Ok(crate::state::FakeStateEngine::update(self, event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::sample_event;

    #[test]
    fn fake_engine_is_available_behind_replaceable_trait() {
        let mut engine: Box<dyn StateEngine> = Box::new(crate::state::FakeStateEngine::default());
        let summary = engine
            .update(&sample_event("evt:trait", 1, 42, 100))
            .unwrap();
        assert_eq!(engine.name(), "fake");
        assert_eq!(summary.state_revision, 1);
    }
}
