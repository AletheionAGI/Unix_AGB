import json
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
        self.assertFalse(config["enabled"])
        self.assertIsNone(config["protected_cgroup"])
        self.assertFalse(manifest["enabled_by_default"])
        self.assertFalse(manifest["installed_by_this_repository"])
        self.assertEqual(manifest["status"], "laboratory-packaging-scaffold")

    def test_package_declares_hardening_and_exact_revision(self):
        unit = (ROOT / "deploy/unix-agb-egress-guardian.service").read_text()
        config = json.loads((ROOT / "deploy/egress-guardian.json.example").read_text())
        for directive in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "ProtectControlGroups=yes"):
            self.assertIn(directive, unit)
        self.assertEqual(config["policy_revision"], "policy:gate4-egress-guardian-v1")


if __name__ == "__main__":
    unittest.main()
