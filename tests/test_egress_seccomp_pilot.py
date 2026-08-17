import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_egress_seccomp_pilot import NOTIFICATION


class EgressSeccompPilotTests(unittest.TestCase):
    def test_linux_seccomp_notification_abi_is_80_bytes(self):
        self.assertEqual(NOTIFICATION.size, 80)
        values = NOTIFICATION.unpack(bytes(80))
        self.assertEqual(len(values[6:]), 6)


if __name__ == "__main__":
    unittest.main()
