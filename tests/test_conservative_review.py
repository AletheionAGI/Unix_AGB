from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "scripts"))

from audit_reviews_conservatively import audit_reviews


def candidate(result: str = "allowed", address: str = "127.0.0.1") -> dict:
    return {
        "trajectory_id": "candidate:a",
        "events": [{
            "operation": "network.connect",
            "result": result,
            "subject": {"exe": "/usr/bin/example"},
            "resource": {"address": address, "port": 443},
        }],
    }


def review(label: str = "benign", confidence: str = "high") -> dict:
    return {
        "trajectory_id": "candidate:a",
        "label": label,
        "label_source": "human-review:test",
        "family": "example",
        "review_confidence": confidence,
    }


class ConservativeReviewTests(unittest.TestCase):
    def test_complete_high_confidence_benign_evidence_is_preserved(self) -> None:
        self.assertEqual(audit_reviews([candidate()], [review()])[0]["label"], "benign")

    def test_requested_only_network_evidence_is_excluded(self) -> None:
        result = audit_reviews([candidate("requested")], [review()])[0]
        self.assertEqual(result["label"], "inconclusive")
        self.assertIn("outcome", result["review_reason"])

    def test_pending_network_evidence_is_excluded(self) -> None:
        result = audit_reviews([candidate("pending", "198.51.100.4")], [review()])[0]
        self.assertEqual(result["label"], "inconclusive")

    def test_natural_malicious_review_is_never_accepted_automatically(self) -> None:
        result = audit_reviews([candidate()], [review("malicious")])[0]
        self.assertEqual(result["label"], "inconclusive")
        self.assertIn("intent", result["review_reason"])


if __name__ == "__main__":
    unittest.main()
