import hashlib
import json
import subprocess
import tempfile
import urllib.request
import unittest
from pathlib import Path

from run_gate4_automated_campaign import TARGET_DOMAINS, validate_manifest
from verify_gate4_automated_campaign import verify
from gate4_campaign_gui import CampaignGui


class Gate4AutomatedCampaignTests(unittest.TestCase):
    def manifest(self, artifact: str, workloads=1):
        return {
            "protocol": "unix-agb-gate4-automated-campaign-v1",
            "artifact_path": artifact,
            "artifact_sha256": hashlib.sha256(Path(artifact).read_bytes()).hexdigest() if Path(artifact).is_file() else "a" * 64,
            "policy_revision": "policy:bpf-observer-v2",
            "domains": sorted(TARGET_DOMAINS),
            "application_classes": ["service", "cli", "daemon"],
            "setup": [["/usr/bin/true"]],
            "workloads": [
                {"id": f"w{i}", "class": "service", "command": ["/usr/bin/sleep", "3"],
                 "allow_early_exit": False} for i in range(workloads)
            ],
            "probes": [["/usr/bin/true"]],
            "teardown": [["/usr/bin/true"]],
            "artifacts": [artifact],
        }

    def test_formal_mode_refuses_short_or_small_campaign(self):
        with self.assertRaisesRegex(ValueError, "eight hours"):
            validate_manifest(self.manifest("/tmp/a"), "formal", 60)
        with self.assertRaisesRegex(ValueError, "32 workload"):
            validate_manifest(self.manifest("/tmp/a"), "formal", 28_800)

    def test_smoke_run_writes_verifiable_hash_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); artifact = root / "artifact"; artifact.write_text("evidence\n")
            manifest = root / "manifest.json"; manifest.write_text(json.dumps(self.manifest(str(artifact))))
            output = root / "output"
            result = subprocess.run([
                "python3", "scripts/run_gate4_automated_campaign.py", "--manifest", str(manifest),
                "--mode", "smoke", "--duration-seconds", "1", "--interval-seconds", "0.1",
                "--output-dir", str(output),
            ], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((output / "summary.json").read_text())
            self.assertTrue(summary["complete"])
            self.assertFalse(summary["promotion_eligible"])
            self.assertTrue(verify(manifest, output)["valid"])

    def test_gui_is_local_read_only_and_serves_product_brand(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "live-status.json").write_text('{"running":true,"failures":[]}')
            gui = CampaignGui(root, 0)
            gui.start()
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{gui.port}/", timeout=2) as response:
                    page = response.read().decode()
                    self.assertIn("Aletheion Guard Bridge", page)
                    self.assertIn("--cyan:#079ab6", page)
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                with urllib.request.urlopen(f"http://127.0.0.1:{gui.port}/api/status", timeout=2) as response:
                    self.assertTrue(json.loads(response.read())["running"])
            finally:
                gui.stop()


if __name__ == "__main__":
    unittest.main()
