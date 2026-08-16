import unittest

from run_gate3_asm_pipeline import asm_decision_to_state


class Gate3AsmStateTests(unittest.TestCase):
    def event(self):
        return {
            "namespace_id": "process:boot:7:9",
            "occurred_at": "2026-08-16T12:00:00Z",
        }

    def result(self, effect):
        return {
            "effect": effect,
            "reason": "ASM_CM_SELECTED_CAUSAL_EVIDENCE",
            "evidence_ids": ["evt:a", "evt:b", "evt:b"],
            "confidence": 0.97,
            "state_revision": 4,
            "checkpoint_fingerprint": "a" * 64,
            "model_inference_performed": True,
        }

    def test_deny_becomes_elevated_state_with_exact_evidence(self):
        state = asm_decision_to_state(self.event(), self.result("DENY"))
        self.assertEqual(state["risk_band"], "elevated")
        self.assertEqual(state["engine"], "asm-cm")
        self.assertEqual(state["evidence_ids"], ["evt:a", "evt:b"])

    def test_allow_is_only_normal_state_and_abstain_is_unknown(self):
        self.assertEqual(
            asm_decision_to_state(self.event(), self.result("ALLOW"))["risk_band"],
            "normal",
        )
        self.assertEqual(
            asm_decision_to_state(self.event(), self.result("ABSTAIN"))["risk_band"],
            "unknown",
        )


if __name__ == "__main__":
    unittest.main()
