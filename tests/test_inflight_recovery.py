import unittest
from unittest import mock

from run_gate4_inflight_crash import respond_to_lease


class InflightRecoveryTests(unittest.TestCase):
    @mock.patch("run_gate4_inflight_crash.fcntl.ioctl")
    @mock.patch("run_gate4_inflight_crash.notification_is_valid", return_value=False)
    def test_invalid_lease_is_never_answered(self, _valid, ioctl):
        self.assertEqual(respond_to_lease(7, {"notification_id": 1, "notified_tid": 42}, 42), "INVALID")
        ioctl.assert_not_called()

    @mock.patch("run_gate4_inflight_crash.process_tgid", return_value=42)
    @mock.patch("run_gate4_inflight_crash.fcntl.ioctl")
    @mock.patch("run_gate4_inflight_crash.notification_is_valid", return_value=True)
    def test_valid_target_lease_is_denied(self, _valid, ioctl, _tgid):
        self.assertEqual(respond_to_lease(7, {"notification_id": 1, "notified_tid": 99}, 42), "DENY")
        ioctl.assert_called_once()

    @mock.patch("run_gate4_inflight_crash.process_tgid", return_value=99)
    @mock.patch("run_gate4_inflight_crash.fcntl.ioctl")
    @mock.patch("run_gate4_inflight_crash.notification_is_valid", return_value=True)
    def test_valid_out_of_scope_lease_continues(self, _valid, ioctl, _tgid):
        self.assertEqual(respond_to_lease(7, {"notification_id": 1, "notified_tid": 99}, 42), "ALLOW")
        ioctl.assert_called_once()

    @mock.patch("run_gate4_inflight_crash.process_tgid", side_effect=OSError("gone"))
    @mock.patch("run_gate4_inflight_crash.fcntl.ioctl")
    @mock.patch("run_gate4_inflight_crash.notification_is_valid", return_value=True)
    def test_unresolved_identity_is_not_answered(self, _valid, ioctl, _tgid):
        self.assertEqual(respond_to_lease(7, {"notification_id": 1, "notified_tid": 99}, 42), "UNRESOLVED")
        ioctl.assert_not_called()


if __name__ == "__main__":
    unittest.main()
