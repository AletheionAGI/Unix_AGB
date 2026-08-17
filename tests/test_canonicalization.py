import copy
import unittest

from agb_fake_asm import CanonicalEntityEncoder, canonicalize_trajectories
from agb_gate2b.diagnostics import canonicalize_entity_ids as frozen_v4_canonicalizer


class CanonicalizationTests(unittest.TestCase):
    def test_control_tokens_pass_and_entities_are_local_first_occurrence(self):
        self.assertEqual(
            CanonicalEntityEncoder().encode([1, 40, 2, 99, 40, 99]),
            [1, 32, 2, 33, 32, 33],
        )

    def test_each_trajectory_has_an_independent_mapping_and_input_is_untouched(self):
        items = [{"tokens": [50, 51]}, {"tokens": [200, 50]}]
        original = copy.deepcopy(items)
        result = canonicalize_trajectories(items)
        self.assertEqual([item["tokens"] for item in result], [[32, 33], [32, 33]])
        self.assertEqual(items, original)

    def test_operational_component_matches_frozen_v4_implementation(self):
        items = [
            {"trajectory_id": "a", "label": "benign", "tokens": [1, 44, 3, 44, 200]},
            {"trajectory_id": "b", "label": "malicious", "tokens": [31, 255, 90, 255]},
        ]
        self.assertEqual(canonicalize_trajectories(items), frozen_v4_canonicalizer(items))

    def test_entity_budget_overflow_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "budget"):
            CanonicalEntityEncoder(token_limit=34).encode([50, 51, 52])


if __name__ == "__main__":
    unittest.main()
