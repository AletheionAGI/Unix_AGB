from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from bpf_to_events import normalize


class BpfNormalizerTests(unittest.TestCase):
    def test_normalizes_real_current_process_identity(self) -> None:
        sequences: dict[str, int] = {}
        event = normalize(f"AGB_BPF|process.exec|pid={os.getpid()}|exe=/usr/bin/python3", sequences)
        assert event is not None
        self.assertEqual(event["provenance"]["source"], "bpf")
        self.assertEqual(event["operation"], "process.exec")
        self.assertEqual(event["sequence"], 1)
        self.assertIn("start_time_ns", event["subject"])

