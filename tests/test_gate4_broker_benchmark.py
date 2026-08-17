import unittest

from benchmark_gate4_egress_broker import latency_summary, percentile


class Gate4BrokerBenchmarkTests(unittest.TestCase):
    def test_percentile_uses_nearest_rank(self):
        self.assertEqual(percentile([4, 1, 3, 2], 0.50), 2)
        self.assertEqual(percentile([4, 1, 3, 2], 0.95), 4)

    def test_empty_latency_summary_is_explicit(self):
        self.assertEqual(latency_summary([]), {"count": 0, "min": 0, "p50": 0, "p95": 0, "p99": 0, "max": 0})

    def test_latency_summary_preserves_count_and_tail(self):
        summary = latency_summary(list(range(1, 101)))
        self.assertEqual(summary["count"], 100)
        self.assertEqual(summary["p50"], 50)
        self.assertEqual(summary["p95"], 95)
        self.assertEqual(summary["p99"], 99)


if __name__ == "__main__":
    unittest.main()
