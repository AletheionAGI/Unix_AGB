import hashlib
import hmac
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("agb_gate3_runtime", ROOT / "deploy/agb_gate3_runtime.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)
Gate3CacheError = MODULE.Gate3CacheError
Gate3RuntimePolicy = MODULE.Gate3RuntimePolicy


class Gate4RuntimePolicyTests(unittest.TestCase):
    revision = "policy:gate3-service-v1"
    secret = b"gate3-service-test-secret-32-bytes!!"

    def entry(self, namespace="process:test", expires=200):
        return {
            "cache_key": f"{namespace}|network.connect|" + "a" * 64,
            "decision_id": "dec:test",
            "namespace_id": namespace,
            "operation": "network.connect",
            "resource_sha256": "a" * 64,
            "effect": "DENY",
            "policy_revision": self.revision,
            "state_revision": 1,
            "evidence_sha256": "b" * 64,
            "expires_epoch": expires,
        }

    def snapshot(self, entries):
        encoded = json.dumps([1, self.revision, entries], separators=(",", ":")).encode()
        return json.dumps({
            "format_version": 1,
            "policy_revision": self.revision,
            "entries": entries,
            "hmac_sha256": hmac.new(self.secret, encoded, hashlib.sha256).hexdigest(),
        }, separators=(",", ":")).encode()

    def policy(self, directory, entries):
        root = Path(directory)
        cache, key = root / "cache.json", root / "cache.key"
        cache.write_bytes(self.snapshot(entries))
        key.write_bytes(self.secret)
        return Gate3RuntimePolicy(cache, key, self.revision), cache

    def test_active_exact_namespace_deny_is_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, _ = self.policy(directory, [self.entry()])
            self.assertEqual(policy.decide("process:test", 100), (True, "ACTIVE_GATE3_TRAJECTORY_DENY", "dec:test"))
            self.assertEqual(policy.decide("process:other", 100)[0], False)
            self.assertEqual(policy.decide("process:test", 200)[1], "NO_ACTIVE_GATE3_DENY")

    def test_invalid_initial_cache_refuses_to_start(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, cache = self.policy(directory, [self.entry()])
            cache.write_bytes(b"{}")
            with self.assertRaises(Gate3CacheError):
                policy.reload(required=True)

    def test_bad_reload_retains_last_authenticated_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, cache = self.policy(directory, [self.entry()])
            self.assertTrue(policy.decide("process:test", 100)[0])
            cache.write_bytes(b'{"tampered":true}')
            self.assertTrue(policy.decide("process:test", 100)[0])
            self.assertNotEqual(policy.last_reload_reason, "CACHE_AUTHENTICATED")

    def test_authenticated_empty_rotation_removes_deny(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, cache = self.policy(directory, [self.entry()])
            self.assertTrue(policy.decide("process:test", 100)[0])
            cache.write_bytes(self.snapshot([]))
            self.assertFalse(policy.decide("process:test", 100)[0])


if __name__ == "__main__":
    unittest.main()
