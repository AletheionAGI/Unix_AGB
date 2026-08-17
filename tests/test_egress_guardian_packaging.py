import json
import hashlib
import hmac
import importlib.machinery
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class EgressGuardianPackagingTests(unittest.TestCase):
    @staticmethod
    def guardian_module():
        path = ROOT / "deploy/agb-egress-guardian"
        loader = importlib.machinery.SourceFileLoader("agb_egress_guardian_test", str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        module.NONCES.clear()
        return module
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
        self.assertTrue(manifest["enforcement_active"])

    def test_package_declares_hardening_and_exact_revision(self):
        unit = (ROOT / "deploy/unix-agb-egress-guardian.service").read_text()
        config = json.loads((ROOT / "deploy/egress-guardian.json.example").read_text())
        for directive in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "ProtectControlGroups=yes"):
            self.assertIn(directive, unit)
        self.assertEqual(config["policy_revision"], "policy:gate4-egress-guardian-v2")

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
            for path in ("./etc/unix-agb/egress-guardian.json", "./usr/lib/systemd/system/unix-agb-egress-guardian.service", "./usr/libexec/unix-agb/agb-egress-guardian", "./usr/libexec/unix-agb/agb-egress-launch"):
                self.assertIn(path, listing)

    def test_handoff_rejects_replay_stale_revision_and_bad_hmac(self):
        guardian = self.guardian_module()
        secret = b"x" * 32
        base = {"pid": 42, "target_pid": 99, "protected_pgid": 42, "policy_revision": guardian.REVISION, "nonce": "one", "expires_ns": 200, "crash_after": None, "crash_all": False}
        def sign(message):
            return {**message, "hmac_sha256": hmac.new(secret, guardian.encode(message), hashlib.sha256).hexdigest()}
        valid = sign(base)
        self.assertEqual(guardian.authenticate(valid, 42, 0, 0, secret, 100), (True, "HANDOFF_AUTHENTICATED"))
        self.assertEqual(guardian.authenticate(valid, 42, 0, 0, secret, 100)[1], "HANDOFF_REPLAY")
        stale = sign({**base, "nonce": "two", "policy_revision": "policy:stale"})
        self.assertEqual(guardian.authenticate(stale, 42, 0, 0, secret, 100)[1], "POLICY_REVISION_MISMATCH")
        bad = {**sign({**base, "nonce": "three"}), "hmac_sha256": "0" * 64}
        self.assertEqual(guardian.authenticate(bad, 42, 0, 0, secret, 100)[1], "HANDOFF_HMAC_INVALID")


if __name__ == "__main__":
    unittest.main()
