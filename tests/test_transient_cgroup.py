import unittest
from unittest import mock

from run_gate4_transient_cgroup import wait_for


class TransientCgroupTests(unittest.TestCase):
    def test_wait_for_accepts_success_without_delay(self):
        wait_for(lambda: True, 0.1, "unused")

    @mock.patch("run_gate4_transient_cgroup.time.sleep", return_value=None)
    @mock.patch("run_gate4_transient_cgroup.time.monotonic", side_effect=[0.0, 0.0, 0.2])
    def test_wait_for_has_bounded_failure(self, _clock, _sleep):
        with self.assertRaisesRegex(TimeoutError, "bounded"):
            wait_for(lambda: False, 0.1, "bounded")


if __name__ == "__main__":
    unittest.main()
