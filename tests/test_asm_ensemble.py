import unittest

from agb_fake_asm import DecisionEnsemble, EnsemblePolicy


class StubEngine:
    def __init__(self, name, effects):
        self.name = name
        self.effects = iter(effects)

    def update(self, event):
        effect = next(self.effects)
        return {
            "effect": effect,
            "evidence_ids": [f"{self.name}:{event['event_id']}"],
            "confidence": 0.9,
            "state_revision": event["sequence"],
            "checkpoint_fingerprint": self.name * 8,
            "model_inference_performed": True,
        }


class DecisionEnsembleTests(unittest.TestCase):
    def event(self, sequence=1):
        return {
            "namespace_id": "process:boot:7:9",
            "event_id": f"evt:{sequence}",
            "sequence": sequence,
        }

    def engines(self, effects):
        return [StubEngine(f"seed-{index}", [effect]) for index, effect in enumerate(effects, 1)]

    def test_unanimous_deny_is_returned_and_counted(self):
        ensemble = DecisionEnsemble(self.engines(["DENY", "DENY", "DENY"]))
        result = ensemble.update(self.event())
        self.assertEqual(result["effect"], "DENY")
        self.assertFalse(result["ensemble"]["disagreement"])
        self.assertEqual(ensemble.telemetry["disagreements"], 0)
        self.assertEqual(ensemble.telemetry["total_member_inferences"], 3)
        self.assertEqual(
            ensemble.telemetry["member_inference_counts"],
            {"seed-1": 1, "seed-2": 1, "seed-3": 1},
        )

    def test_operational_default_abstains_on_split_vote(self):
        ensemble = DecisionEnsemble(self.engines(["DENY", "DENY", "ALLOW"]))
        result = ensemble.update(self.event())
        self.assertEqual(result["effect"], "ABSTAIN")
        self.assertEqual(result["ensemble"]["majority_effect"], "DENY")
        self.assertEqual(ensemble.telemetry["disagreement_rate"], 1.0)

    def test_explicit_majority_mode_matches_v5_rule(self):
        policy = EnsemblePolicy(deny_votes_required=2, disagreement_action="majority")
        ensemble = DecisionEnsemble(self.engines(["DENY", "DENY", "ALLOW"]), policy=policy)
        self.assertEqual(ensemble.update(self.event())["effect"], "DENY")

    def test_parallel_scheduling_preserves_member_order_and_vote(self):
        ensemble = DecisionEnsemble(
            self.engines(["DENY", "DENY", "ALLOW"]),
            policy=EnsemblePolicy(disagreement_action="majority"),
            parallel_members=True,
        )
        result = ensemble.update(self.event())
        self.assertEqual(result["effect"], "DENY")
        self.assertEqual(result["ensemble"]["member_effects"], ["DENY", "DENY", "ALLOW"])
        self.assertTrue(ensemble.telemetry["parallel_members"])

    def test_member_abstention_can_never_become_allow(self):
        policy = EnsemblePolicy(deny_votes_required=2, disagreement_action="majority")
        ensemble = DecisionEnsemble(
            self.engines(["ABSTAIN", "ABSTAIN", "ABSTAIN"]), policy=policy
        )
        result = ensemble.update(self.event())
        self.assertEqual(result["effect"], "ABSTAIN")
        self.assertEqual(result["reason"], "ENSEMBLE_MEMBER_ABSTAINED")

    def test_member_revision_mismatch_is_rejected(self):
        engines = self.engines(["ALLOW", "ALLOW", "ALLOW"])
        original = engines[2].update
        engines[2].update = lambda event: {**original(event), "state_revision": 99}
        with self.assertRaisesRegex(RuntimeError, "state revisions"):
            DecisionEnsemble(engines).update(self.event())


if __name__ == "__main__":
    unittest.main()
