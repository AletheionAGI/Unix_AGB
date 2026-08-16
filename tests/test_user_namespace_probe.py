from __future__ import annotations

import os
import unittest


class UserNamespaceProbeTests(unittest.TestCase):
    def test_host_uid_is_not_virtual_root(self) -> None:
        self.assertNotEqual(os.getuid(), 0)

