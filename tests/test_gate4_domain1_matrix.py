import time
import unittest

from agb_fake_asm.gate4_promotion import authorize_gate3_deny
from run_gate4_domain1_matrix import REVISION, denial, signed_snapshot


class Gate4Domain1MatrixTests(unittest.TestCase):
    def test_signed_current_exact_deny_is_authorized(self):
        secret = b"domain-one-test-key-that-is-long-enough"
        namespace = "process:boot:42:9000"
        entry = denial(namespace, int(time.time()) + 60)
        snapshot = signed_snapshot([entry], secret)
        allowed, reason, _ = authorize_gate3_deny(
            snapshot, secret, REVISION, entry["cache_key"], int(time.time())
        )
        self.assertTrue(allowed)
        self.assertEqual(reason, "GATE3_DENY_AUTHORIZED")

    def test_expired_and_cross_namespace_denies_do_not_authorize_target(self):
        secret = b"domain-one-test-key-that-is-long-enough"
        namespace = "process:boot:42:9000"
        expired = denial(namespace, int(time.time()) - 1)
        snapshot = signed_snapshot([expired], secret)
        self.assertFalse(authorize_gate3_deny(
            snapshot, secret, REVISION, expired["cache_key"], int(time.time())
        )[0])
        other = denial(namespace + ":other", int(time.time()) + 60)
        snapshot = signed_snapshot([other], secret)
        self.assertFalse(authorize_gate3_deny(
            snapshot, secret, REVISION, "missing-target-key", int(time.time())
        )[0])


if __name__ == "__main__":
    unittest.main()
