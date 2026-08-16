from __future__ import annotations

import os
import unittest


class IdentityProbeTests(unittest.TestCase):
    def test_process_identity_is_nonzero(self) -> None:
        self.assertGreater(os.getuid(), -1)
        self.assertGreater(os.getgid(), -1)

