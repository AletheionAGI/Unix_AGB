import unittest

import hashlib
import hmac
import json

from agb_fake_asm.gate4_promotion import PROMOTION_PROTOCOL, REQUIRED_DOMAINS, authorize_gate3_deny, evaluate_matrix, sign_evidence, verify_evidence


class Gate4PromotionTests(unittest.TestCase):
    secret = b"gate4-test-secret-that-is-long-enough"
    revision = "policy:gate4-promotion-v1"

    def evidence(self, domain):
        return sign_evidence({
            "protocol": PROMOTION_PROTOCOL,
            "domain": domain,
            "policy_revision": self.revision,
            "artifact_sha256": "a" * 64,
            "protected_fail_open": 0,
            "cross_scope_effects": 0,
            "supported": True,
        }, self.secret)

    def test_missing_domains_cannot_promote(self):
        result = evaluate_matrix([], self.secret, self.revision)
        self.assertFalse(result["supported"])
        self.assertEqual(result["gate4_status"], "controlled-prototype")
        self.assertTrue(all(item["reason"] == "EVIDENCE_MISSING" for item in result["domains"].values()))

    def test_all_authenticated_domains_promote(self):
        result = evaluate_matrix([self.evidence(domain) for domain in REQUIRED_DOMAINS], self.secret, self.revision)
        self.assertTrue(result["supported"])
        self.assertEqual(result["gate4_status"], "promoted")

    def test_tampering_revision_and_fail_open_are_rejected(self):
        signed = self.evidence(REQUIRED_DOMAINS[0])
        tampered = {**signed, "supported": False}
        self.assertEqual(verify_evidence(tampered, self.secret, self.revision)[1], "EVIDENCE_SIGNATURE_INVALID")
        wrong_revision = sign_evidence({**signed, "policy_revision": "policy:other"}, self.secret)
        self.assertEqual(verify_evidence(wrong_revision, self.secret, self.revision)[1], "POLICY_REVISION_MISMATCH")
        fail_open = sign_evidence({**signed, "protected_fail_open": 1}, self.secret)
        self.assertEqual(verify_evidence(fail_open, self.secret, self.revision)[1], "PROTECTED_FAIL_OPEN")

    def test_mixed_artifacts_cannot_promote(self):
        records = [self.evidence(domain) for domain in REQUIRED_DOMAINS]
        records[-1] = sign_evidence({**records[-1], "artifact_sha256": "b" * 64}, self.secret)
        result = evaluate_matrix(records, self.secret, self.revision)
        self.assertFalse(result["supported"])
        self.assertFalse(result["artifact_consistent"])

    def gate3_snapshot(self, expires=200):
        entry = {
            "cache_key": "process:test|network.connect|" + "a" * 64,
            "decision_id": "dec:test",
            "namespace_id": "process:test",
            "operation": "network.connect",
            "resource_sha256": "a" * 64,
            "effect": "DENY",
            "policy_revision": self.revision,
            "state_revision": 1,
            "evidence_sha256": "b" * 64,
            "expires_epoch": expires,
        }
        payload = json.dumps([1, self.revision, [entry]], separators=(",", ":")).encode()
        return {"format_version": 1, "policy_revision": self.revision, "entries": [entry], "hmac_sha256": hmac.new(self.secret, payload, hashlib.sha256).hexdigest()}

    def test_gate3_cache_authorizes_only_authenticated_current_network_deny(self):
        snapshot = self.gate3_snapshot()
        key = snapshot["entries"][0]["cache_key"]
        self.assertTrue(authorize_gate3_deny(snapshot, self.secret, self.revision, key, 100)[0])
        self.assertEqual(authorize_gate3_deny(snapshot, self.secret, self.revision, key, 200)[1], "DECISION_EXPIRED")
        tampered = json.loads(json.dumps(snapshot))
        tampered["entries"][0]["effect"] = "ALLOW"
        self.assertEqual(authorize_gate3_deny(tampered, self.secret, self.revision, key, 100)[1], "CACHE_AUTHENTICATION_FAILED")


if __name__ == "__main__":
    unittest.main()
