import sys
import errno
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_egress_seccomp_pilot import NOTIFICATION, notification_is_valid


class EgressSeccompPilotTests(unittest.TestCase):
    def test_linux_seccomp_notification_abi_is_80_bytes(self):
        self.assertEqual(NOTIFICATION.size, 80)
        values = NOTIFICATION.unpack(bytes(80))
        self.assertEqual(len(values[6:]), 6)

    @patch("run_egress_seccomp_pilot.fcntl.ioctl")
    def test_notification_id_is_checked_with_kernel_before_response(self, ioctl):
        self.assertTrue(notification_is_valid(7, 123))
        ioctl.assert_called_once()
        self.assertEqual(bytes(ioctl.call_args.args[2]), (123).to_bytes(8, "little"))

    @patch("run_egress_seccomp_pilot.fcntl.ioctl")
    def test_stale_notification_id_is_not_valid(self, ioctl):
        ioctl.side_effect = OSError(errno.ENOENT, "stale")
        self.assertFalse(notification_is_valid(7, 123))


if __name__ == "__main__":
    unittest.main()
