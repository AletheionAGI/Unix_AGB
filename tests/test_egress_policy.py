import unittest

from agb_fake_asm.egress_policy import ExecutableEgressPolicy


def event(address="198.51.100.7", port=443, *, exe="/usr/bin/curl", result="allowed", family="AF_INET"):
    return {
        "operation": "network.connect",
        "result": result,
        "subject": {"exe": exe},
        "resource": {"family": family, "address": address, "port": port},
    }


class EgressPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = ExecutableEgressPolicy("/usr/bin/curl")

    def test_denies_external_network_for_exact_executable(self):
        self.assertEqual(self.policy.evaluate(event())["effect"], "DENY")

    def test_allows_loopback_and_out_of_scope_executable(self):
        self.assertEqual(self.policy.evaluate(event("127.0.0.1", 8080))["effect"], "ALLOW")
        self.assertEqual(self.policy.evaluate(event(exe="/usr/bin/git"))["effect"], "ALLOW")

    def test_unresolved_or_pending_destination_never_becomes_allow(self):
        self.assertEqual(self.policy.evaluate(event("0.0.0.0", 0))["effect"], "ABSTAIN")
        self.assertEqual(self.policy.evaluate(event(result="pending"))["effect"], "ABSTAIN")

    def test_local_unix_socket_is_not_external_network(self):
        local = event(None, None, family="AF_UNIX")
        self.assertEqual(self.policy.evaluate(local)["effect"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
