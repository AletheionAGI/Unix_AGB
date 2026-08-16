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
        self.assertEqual(event["subject"]["exe"], "/usr/bin/python3")
        self.assertEqual(event["resource"]["path"], "/usr/bin/python3")
        self.assertEqual(event["sequence"], 1)
        self.assertIn("start_time_ns", event["subject"])

    def test_preserves_network_destination_and_socket_metadata(self) -> None:
        sequences: dict[str, int] = {}
        event = normalize(
            f"AGB_BPF|network.connect|pid={os.getpid()}|uid={os.getuid()}|"
            "gid=1000|comm=python|fd=7|family=AF_INET|address=198.51.100.42|"
            "port=443|socket_type=1|protocol=6|addrlen=16",
            sequences,
        )
        assert event is not None
        self.assertEqual(
            event["resource"],
            {
                "type": "network",
                "fd": 7,
                "family": "AF_INET",
                "protocol": "tcp",
                "protocol_number": 6,
                "socket_type": "stream",
                "socket_type_number": 1,
                "address": "198.51.100.42",
                "port": 443,
                "addrlen": 16,
            },
        )
        self.assertIn("network-destination-observed", event["labels"])

    def test_sensitive_path_is_labeled_only_by_explicit_policy(self) -> None:
        line = (
            f"AGB_BPF|file.open|pid={os.getpid()}|uid={os.getuid()}|gid=1000|"
            "comm=lab|path=/tmp/agb-canary"
        )
        event = normalize(line, {}, sensitive_paths={"/tmp/agb-canary"})
        assert event is not None
        self.assertEqual(event["labels"], ["credential"])

    def test_exact_path_policy_can_attach_causal_labels(self) -> None:
        path = "/tmp/agb-controlled-persistence"
        line = (
            f"AGB_BPF|file.open|pid={os.getpid()}|uid={os.getuid()}|gid=1000|"
            f"comm=lab|path={path}|flags={os.O_WRONLY}"
        )
        event = normalize(
            line,
            {},
            path_labels={path: {"persistence-control", "policy-query"}},
        )
        assert event is not None
        self.assertEqual(event["labels"], ["persistence-control", "policy-query"])
        self.assertEqual(event["resource"]["access"], "write")
        self.assertEqual(event["resource"]["open_flags"], os.O_WRONLY)
