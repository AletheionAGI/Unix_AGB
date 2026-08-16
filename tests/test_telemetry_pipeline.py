from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "scripts"))

from agb_fake_asm.independent_corpus import IndependentCorpusError
from agb_fake_asm.telemetry_pipeline import apply_reviews, build_candidates, summarize_candidate
from generate_synthetic_events import event


def observed(namespace: str, sequence: int) -> dict[str, object]:
    item = event(sequence, "process.exec", [])
    item["event_id"] = f"evt:{namespace}:{sequence}"
    item["namespace_id"] = namespace
    item["provenance"] = {"source": "bpf", "collector": "test"}
    return item


class TelemetryPipelineTests(unittest.TestCase):
    def test_candidates_are_grouped_and_split_before_review(self) -> None:
        events = [
            observed("process:boot-a:10:100", 2),
            observed("process:boot-a:10:100", 1),
            observed("process:boot-b:11:101", 1),
        ]
        first = build_candidates(events, collector_revision="revision:test")
        second = build_candidates(list(reversed(events)), collector_revision="revision:test")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 2)
        self.assertTrue(all(item["status"] == "pending-review" for item in first))
        self.assertTrue(all("label" not in item for item in first))
        self.assertTrue(all(item["subject_scope"] == "external" for item in first))

    def test_reviews_are_joined_without_changing_split(self) -> None:
        candidates = build_candidates(
            [observed("process:boot-a:10:100", 1)], collector_revision="revision:test"
        )
        candidate = candidates[0]
        corpus = apply_reviews(
            candidates,
            [
                {
                    "trajectory_id": candidate["trajectory_id"],
                    "label": "benign",
                    "label_source": "review:test-case",
                    "family": "developer-build",
                }
            ],
        )
        self.assertEqual(corpus[0]["split"], candidate["split"])
        self.assertEqual(corpus[0]["label"], "benign")
        self.assertEqual(corpus[0]["review_confidence"], "high")
        self.assertEqual(corpus[0]["evaluation_purpose"], "false-positive-monitoring")

    def test_exact_protected_executable_selects_security_efficacy(self) -> None:
        item = observed("process:boot-a:10:100", 1)
        executable = str(item["subject"]["exe"])
        candidate = build_candidates(
            [item],
            collector_revision="revision:test",
            protected_executables={executable},
        )[0]
        self.assertEqual(candidate["subject_scope"], "protected")
        self.assertEqual(candidate["evaluation_purpose"], "security-efficacy")

    def test_external_processes_can_be_excluded_from_protected_corpus(self) -> None:
        item = observed("process:boot-a:10:100", 1)
        executable = str(item["subject"]["exe"])
        other = observed("process:boot-b:11:101", 1)
        other["subject"] = {**other["subject"], "exe": "/usr/bin/unrelated"}
        candidates = build_candidates(
            [item, other],
            collector_revision="revision:test",
            protected_executables={executable},
            include_external=False,
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["subject_scope"], "protected")

    def test_long_processes_are_windowed_without_cross_split_leakage(self) -> None:
        namespace = "process:boot-a:10:100"
        candidates = build_candidates(
            [observed(namespace, sequence) for sequence in range(1, 6)],
            collector_revision="revision:test",
            max_events=2,
        )
        self.assertEqual([len(item["events"]) for item in candidates], [2, 2, 1])
        self.assertEqual(len({item["split"] for item in candidates}), 1)
        self.assertEqual(
            [[event["sequence"] for event in item["events"]] for item in candidates],
            [[1, 2], [1, 2], [1]],
        )
        self.assertEqual(candidates[1]["events"][0]["provenance"]["source_sequence"], 3)

    def test_every_candidate_requires_an_independent_review(self) -> None:
        candidates = build_candidates(
            [observed("process:boot-a:10:100", 1)], collector_revision="revision:test"
        )
        with self.assertRaisesRegex(IndependentCorpusError, "pending review"):
            apply_reviews(candidates, [])

    def test_review_summary_is_bounded_and_traceable(self) -> None:
        namespace = "process:boot-a:10:100"
        candidates = build_candidates(
            [observed(namespace, sequence) for sequence in range(1, 4)],
            collector_revision="revision:test",
        )
        summary = summarize_candidate(candidates[0], max_resources=1)
        self.assertEqual(summary["event_count"], 3)
        self.assertEqual(summary["source_sequence_first"], 1)
        self.assertEqual(summary["source_sequence_last"], 3)
        self.assertLessEqual(len(summary["resource_samples"]), 1)

    def test_sequence_gaps_and_synthetic_events_are_rejected(self) -> None:
        with self.assertRaisesRegex(IndependentCorpusError, "sequence gap"):
            build_candidates(
                [observed("process:boot-a:10:100", 2)], collector_revision="revision:test"
            )
        synthetic = observed("process:boot-a:10:100", 1)
        synthetic["provenance"] = {"source": "synthetic"}
        with self.assertRaisesRegex(IndependentCorpusError, "not independent telemetry"):
            build_candidates([synthetic], collector_revision="revision:test")


if __name__ == "__main__":
    unittest.main()
