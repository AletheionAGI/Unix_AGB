import unittest

from agb_fake_asm.guardian_resilience import HandoffAuthenticator, RestartBudget


class GuardianResilienceTests(unittest.TestCase):
    def test_restart_budget_is_bounded_and_recovers_after_window(self):
        budget = RestartBudget(2, 10)
        self.assertTrue(budget.consume(100))
        self.assertTrue(budget.consume(101))
        self.assertFalse(budget.consume(102))
        self.assertTrue(budget.consume(111))

    def authenticator(self):
        return HandoffAuthenticator(b"k" * 32, "policy:gate4:v1", 1000, 1000)

    def test_handoff_binds_peer_revision_expiry_and_nonce(self):
        auth = self.authenticator()
        message = auth.sign(pid=42, uid=1000, gid=1000, nonce="n1", expires_ns=200)
        self.assertEqual(auth.verify(message, peer_pid=42, peer_uid=1000, peer_gid=1000, now_ns=100), (True, "HANDOFF_AUTHENTICATED"))
        self.assertEqual(auth.verify(message, peer_pid=42, peer_uid=1000, peer_gid=1000, now_ns=100)[1], "HANDOFF_REPLAY")

    def test_handoff_rejects_revision_peer_expiry_and_tampering(self):
        for mutation, reason in (
            ({"policy_revision": "policy:wrong"}, "POLICY_REVISION_MISMATCH"),
            ({"expires_ns": 50}, "HANDOFF_EXPIRED"),
            ({"hmac_sha256": "0" * 64}, "HANDOFF_HMAC_INVALID"),
        ):
            auth = self.authenticator()
            message = auth.sign(pid=42, uid=1000, gid=1000, nonce="n1", expires_ns=200)
            message.update(mutation)
            self.assertEqual(auth.verify(message, peer_pid=42, peer_uid=1000, peer_gid=1000, now_ns=100)[1], reason)
        auth = self.authenticator()
        message = auth.sign(pid=42, uid=1000, gid=1000, nonce="n1", expires_ns=200)
        self.assertEqual(auth.verify(message, peer_pid=42, peer_uid=999, peer_gid=1000, now_ns=100)[1], "PEER_NOT_ALLOWLISTED")


if __name__ == "__main__":
    unittest.main()
