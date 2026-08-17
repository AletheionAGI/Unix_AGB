from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from agb_fake_asm import ValidationProtocolError, freeze_validation_bundle


def trajectory(
    identifier: str,
    *,
    family: str,
    label: str,
    subject_scope: str,
    split: str = "test",
) -> dict:
    namespace = f"process:boot-{identifier}:{abs(hash(identifier)) % 10000 + 10}:100"
    return {
        "trajectory_id": identifier,
        "label": label,
        "label_source": "independent-review:test",
        "family": family,
        "split": split,
        "collector_revision": "collector:test-v1",
        "coverage_scope": "system-wide",
        "coverage_config_sha256": "a" * 64,
        "subject_scope": subject_scope,
        "evaluation_purpose": (
            "security-efficacy" if subject_scope == "protected" else "false-positive-monitoring"
        ),
        "events": [
            {
                "schema_version": "1.0",
                "event_id": f"evt:{identifier}:1",
                "namespace_id": namespace,
                "sequence": 1,
                "operation": "process.exec",
                "labels": [],
                "subject": {},
                "resource": {},
                "occurred_at": "2026-08-16T12:00:00Z",
                "policy_revision": "policy:test",
                "provenance": {"source": "bpf", "collector": "test"},
            }
        ],
    }


class Gate3ValidationProtocolTests(unittest.TestCase):
    def write_jsonl(self, path: Path, items: list[dict]) -> None:
        path.write_text("".join(json.dumps(item) + "\n" for item in items))

    def checkpoint(self, root: Path, member: str) -> tuple[str, Path, str]:
        path = root / f"{member}.pt"
        path.write_bytes(member.encode())
        return member, path, hashlib.sha256(path.read_bytes()).hexdigest()

    def corpora(self, root: Path) -> tuple[Path, Path]:
        natural = root / "natural.jsonl"
        controlled = root / "controlled.jsonl"
        self.write_jsonl(
            natural,
            [trajectory("natural-1", family="desktop-natural", label="benign", subject_scope="external")],
        )
        controlled_items = []
        for index, family in enumerate(("novel-a", "novel-b", "novel-c"), 1):
            controlled_items.extend(
                [
                    trajectory(f"controlled-{index}-b", family=family, label="benign", subject_scope="protected"),
                    trajectory(f"controlled-{index}-m", family=family, label="malicious", subject_scope="protected"),
                ]
            )
        self.write_jsonl(controlled, controlled_items)
        return natural, controlled

    def test_fresh_natural_and_controlled_inputs_are_frozen_before_evaluation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            natural, controlled = self.corpora(root)
            checkpoints = [self.checkpoint(root, f"seed-{seed}") for seed in (1, 2, 3)]
            bundle = freeze_validation_bundle(
                natural,
                controlled,
                checkpoints,
                minimum_natural_test=1,
                minimum_controlled_per_class=1,
            )
            self.assertFalse(bundle["test_evaluated"])
            self.assertEqual(bundle["controlled_corpus"]["test_malicious"], 3)
            self.assertEqual(bundle["ensemble"]["disagreement_action"], "abstain")

    def test_previously_observed_controlled_families_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            natural, controlled = self.corpora(root)
            items = [json.loads(line) for line in controlled.read_text().splitlines()]
            items[0]["family"] = "protected-credential-egress"
            self.write_jsonl(controlled, items)
            checkpoints = [self.checkpoint(root, f"seed-{seed}") for seed in (1, 2, 3)]
            with self.assertRaisesRegex(ValidationProtocolError, "already observed"):
                freeze_validation_bundle(
                    natural,
                    controlled,
                    checkpoints,
                    minimum_natural_test=1,
                    minimum_controlled_per_class=1,
                )

    def test_checkpoint_fingerprint_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            natural, controlled = self.corpora(root)
            checkpoints = [self.checkpoint(root, f"seed-{seed}") for seed in (1, 2, 3)]
            checkpoints[1] = (checkpoints[1][0], checkpoints[1][1], "0" * 64)
            with self.assertRaisesRegex(ValidationProtocolError, "fingerprint mismatch"):
                freeze_validation_bundle(
                    natural,
                    controlled,
                    checkpoints,
                    minimum_natural_test=1,
                    minimum_controlled_per_class=1,
                )


if __name__ == "__main__":
    unittest.main()
