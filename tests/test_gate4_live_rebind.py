import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from agb_fake_asm.independent_corpus import load_independent_corpus


ROOT = Path(__file__).resolve().parents[1]


class Gate4LiveRebindTests(unittest.TestCase):
    def test_rebound_trajectory_is_explicit_and_loadable(self):
        namespace = "process:boot-live:4242:9000000"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.jsonl"
            output = Path(directory) / "corpus.jsonl"
            source.write_text(json.dumps({
                "trajectory_id": "candidate:template",
                "label": "malicious",
                "label_source": "controlled:test",
                "family": "protected-credential-egress-delayed",
                "split": "test",
                "collector_revision": "test",
                "coverage_scope": "allowlist",
                "coverage_config_sha256": "a" * 64,
                "subject_scope": "protected",
                "evaluation_purpose": "security-efficacy",
                "events": [{
                    "event_id": "evt:test:1",
                    "namespace_id": "process:old:1:1",
                    "sequence": 1,
                    "monotonic_ns": 1,
                    "occurred_at": "2026-08-17T00:00:00Z",
                    "operation": "file.open",
                    "policy_revision": "policy:bpf-observer-v1",
                    "subject": {"boot_id": "old", "pid": 1, "start_time_ns": 1},
                    "resource": {"type": "file", "path": "/controlled", "access": "read"},
                    "labels": ["credential"],
                    "result": "requested",
                    "schema_version": "1.0",
                    "host_id": "host:test",
                    "provenance": {"source": "bpf", "raw": "test"},
                }],
            }) + "\n")
            subprocess.run([
                "python3", str(ROOT / "scripts/rebind_gate3_service_trajectory.py"),
                "--source", str(source),
                "--namespace", namespace,
                "--output", str(output),
            ], check=True, capture_output=True, text=True)
            trajectories = load_independent_corpus(output, split="test", evaluation_purpose="security-efficacy")
            self.assertEqual(len(trajectories), 1)
            events = trajectories[0]["events"]
            self.assertTrue(all(event["namespace_id"] == namespace for event in events))
            self.assertTrue(all(event["provenance"]["source"] == "agent-broker" for event in events))
            document = json.loads(output.read_text())
            self.assertTrue(document["label_source"].startswith("controlled-replay:"))


if __name__ == "__main__":
    unittest.main()
