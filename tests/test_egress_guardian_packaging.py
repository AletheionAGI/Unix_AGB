import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class EgressGuardianPackagingTests(unittest.TestCase):
    def test_package_is_opt_in_and_disabled_by_default(self):
        unit = (ROOT / "deploy/unix-agb-egress-guardian.service").read_text()
        config = json.loads((ROOT / "deploy/egress-guardian.json.example").read_text())
        manifest = json.loads((ROOT / "deploy/egress-guardian.install-manifest.json").read_text())
        self.assertIn("ConditionPathExists=/etc/unix-agb/egress-guardian.enabled", unit)
        self.assertIn("KillMode=control-group", unit)
        self.assertIn("StartLimitBurst=3", unit)
        self.assertNotIn("ExecStartPost=", unit)
        self.assertFalse(config["enabled"])
        self.assertIsNone(config["protected_cgroup"])
        self.assertFalse(manifest["enabled_by_default"])
        self.assertTrue(manifest["installed_by_this_repository"])
        self.assertEqual(manifest["status"], "laboratory-lifecycle-package")
        self.assertFalse(manifest["enforcement_active"])

    def test_package_declares_hardening_and_exact_revision(self):
        unit = (ROOT / "deploy/unix-agb-egress-guardian.service").read_text()
        config = json.loads((ROOT / "deploy/egress-guardian.json.example").read_text())
        for directive in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "ProtectControlGroups=yes"):
            self.assertIn(directive, unit)
        self.assertEqual(config["policy_revision"], "policy:gate4-egress-guardian-v1")

    def test_runtime_rejects_disabled_configuration(self):
        runtime = ROOT / "deploy/agb-egress-guardian"
        config = ROOT / "deploy/egress-guardian.json.example"
        result = subprocess.run(["python3", str(runtime), "--config", str(config)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 78)
        self.assertIn("not enabled", result.stderr)

    def test_debian_package_contains_reversible_lifecycle_files(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["python3", str(ROOT / "scripts/build_gate4_deb.py"), "--output-dir", directory], check=True, capture_output=True, text=True)
            package = next(Path(directory).glob("*.deb"))
            listing = subprocess.run(["dpkg-deb", "--contents", str(package)], check=True, capture_output=True, text=True).stdout
            for path in ("./etc/unix-agb/egress-guardian.json", "./usr/lib/systemd/system/unix-agb-egress-guardian.service", "./usr/libexec/unix-agb/agb-egress-guardian"):
                self.assertIn(path, listing)


if __name__ == "__main__":
    unittest.main()
