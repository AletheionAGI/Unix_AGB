import unittest

from agb_fake_asm.recovery_supervisor import RecoveringPolicyWorker


class RecoverySupervisorTests(unittest.TestCase):
    def test_crashed_worker_fails_closed_and_next_decision_uses_replacement(self):
        worker = RecoveringPolicyWorker(timeout_ms=100)
        try:
            first_generation = worker.generation
            failed = worker.decide("ALLOW", target=True, crash=True)
            self.assertEqual(failed.effect, "DENY")
            self.assertTrue(failed.worker_restarted)
            self.assertGreater(failed.generation, first_generation)
            recovered = worker.decide("DENY", target=True)
            self.assertEqual(recovered.effect, "DENY")
            self.assertFalse(recovered.worker_restarted)
            self.assertEqual(recovered.generation, failed.generation)
        finally:
            worker.close()

    def test_out_of_scope_request_never_reaches_or_restarts_worker(self):
        worker = RecoveringPolicyWorker(timeout_ms=100)
        try:
            generation = worker.generation
            decision = worker.decide("DENY", target=False, crash=True)
            self.assertEqual(decision.effect, "ALLOW")
            self.assertEqual(decision.reason, "EXECUTABLE_OUT_OF_SCOPE")
            self.assertFalse(decision.worker_restarted)
            self.assertEqual(worker.generation, generation)
        finally:
            worker.close()


if __name__ == "__main__":
    unittest.main()
