import unittest

from run_gate3_asm_pipeline import asm_decision_to_state, parse_ensemble_checkpoint


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

    def test_ensemble_disagreement_is_explicit_in_state_signals(self):
        result = self.result("ABSTAIN")
        result["ensemble"] = {"disagreement": True}
        state = asm_decision_to_state(self.event(), result)
        self.assertEqual(state["engine"], "asm-cm")
        self.assertIn("asm-cm-ensemble", state["signals"])
        self.assertIn("asm-cm-member-disagreement", state["signals"])

    def test_ensemble_checkpoint_parser_preserves_colons_in_path(self):
        member, path, fingerprint = parse_ensemble_checkpoint(
            "seed-1:/tmp/checkpoints:canonical/model.pt:" + "a" * 64
        )
        self.assertEqual(member, "seed-1")
        self.assertEqual(str(path), "/tmp/checkpoints:canonical/model.pt")
        self.assertEqual(fingerprint, "a" * 64)


if __name__ == "__main__":
    unittest.main()
