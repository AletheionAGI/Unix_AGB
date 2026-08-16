from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "scripts"))

from agb_fake_asm import IndependentCorpusError, freeze_manifest, load_independent_corpus
from generate_synthetic_events import event


def trajectory(
    trajectory_id: str,
    namespace: str,
    split: str,
    label: str,
    *,
    source: str = "bpf",
    subject_scope: str = "protected",
) -> dict[str, object]:
    observed = event(1, "process.exec", [])
    observed["event_id"] = f"evt:{trajectory_id}:1"
    observed["namespace_id"] = namespace
    observed["subject"]["boot_id"] = namespace.split(":")[1]  # type: ignore[index]
    observed["subject"]["pid"] = int(namespace.split(":")[2])  # type: ignore[index]
    observed["subject"]["start_time_ns"] = int(namespace.split(":")[3])  # type: ignore[index]
    observed["provenance"] = {"source": source, "collector": "test-fixture"}
    return {
        "trajectory_id": trajectory_id,
        "label": label,
        "label_source": "independent-review:test",
        "family": "test-family",
        "split": split,
        "collector_revision": "collector:test-v1",
        "coverage_scope": "system-wide",
        "coverage_config_sha256": "a" * 64,
        "subject_scope": subject_scope,
        "evaluation_purpose": (
            "security-efficacy" if subject_scope == "protected" else "false-positive-monitoring"
        ),
        "events": [observed],
    }


class IndependentCorpusTests(unittest.TestCase):
    def write(self, items: list[dict[str, object]], directory: str) -> Path:
        path = Path(directory) / "corpus.jsonl"
        path.write_text("".join(json.dumps(item) + "\n" for item in items))
        return path

    def test_valid_external_corpus_freezes_digest_and_splits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                [
                    trajectory("cal-1", "process:boot-a:10:100", "calibration", "benign"),
                    trajectory("test-1", "process:boot-b:11:101", "test", "malicious"),
                ],
                directory,
            )
            manifest = freeze_manifest(path)
            self.assertEqual(manifest["calibration"]["trajectories"], 1)
            self.assertEqual(manifest["test"]["trajectories"], 1)
            self.assertFalse(manifest["promotion_eligible"])
            self.assertEqual(manifest["evaluation"]["security_efficacy"]["trajectories"], 2)
            self.assertEqual(len(load_independent_corpus(path, split="test")), 1)

    def test_external_telemetry_is_counted_but_cannot_promote(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                [
                    trajectory(
                        "external-cal",
                        "process:boot-a:10:100",
                        "calibration",
                        "benign",
                        subject_scope="external",
                    ),
                    trajectory(
                        "external-test",
                        "process:boot-b:11:101",
                        "test",
                        "benign",
                        subject_scope="external",
                    ),
                ],
                directory,
            )
            manifest = freeze_manifest(path)
            self.assertEqual(
                manifest["evaluation"]["false_positive_monitoring"]["trajectories"], 2
            )
            self.assertEqual(manifest["evaluation"]["security_efficacy"]["trajectories"], 0)
            self.assertFalse(manifest["promotion_eligible"])

    def test_synthetic_provenance_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                [trajectory("bad", "process:boot-a:10:100", "test", "benign", source="synthetic")],
                directory,
            )
            with self.assertRaisesRegex(IndependentCorpusError, "not independent telemetry"):
                load_independent_corpus(path)

    def test_namespace_leakage_between_splits_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            namespace = "process:boot-a:10:100"
            path = self.write(
                [
                    trajectory("cal", namespace, "calibration", "benign"),
                    trajectory("test", namespace, "test", "malicious"),
                ],
                directory,
            )
            with self.assertRaisesRegex(IndependentCorpusError, "namespace leakage"):
                load_independent_corpus(path)


if __name__ == "__main__":
    unittest.main()
