import json
import unittest
from pathlib import Path

from evaluate_gate4_formal_campaign import percentile


ROOT = Path(__file__).resolve().parents[1]


class Gate4FormalCampaignTests(unittest.TestCase):
    def test_frozen_profile_preregisters_matrix_groups_and_budgets(self):
        profile = json.loads((ROOT / "fixtures/benchmark/gate4-campaign-formal-profile.json").read_text())
        self.assertEqual(profile["ubuntu_releases"], ["24.04", "26.04"])
        self.assertEqual(sum(profile["workload_counts"].values()), 32)
        self.assertGreaterEqual(len(profile["workload_counts"]), 3)
        self.assertEqual(profile["duration_seconds"], 28_800)
        self.assertEqual(set(profile["budgets"]["probe_latency_ms"]), {"p50", "p95", "p99"})
        self.assertEqual(profile["controls"]["protected_external"], "EACCES")

    def test_percentiles_use_nearest_rank_and_require_samples(self):
        self.assertIsNone(percentile([], .99))
        self.assertEqual(percentile(list(range(1, 101)), .50), 50)
        self.assertEqual(percentile(list(range(1, 101)), .95), 95)
        self.assertEqual(percentile(list(range(1, 101)), .99), 99)


if __name__ == "__main__":
    unittest.main()
