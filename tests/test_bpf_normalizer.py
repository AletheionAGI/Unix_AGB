from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from bpf_to_events import CorrelatingNormalizer, normalize


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
        self.assertIn("ppid", event["subject"])
        self.assertIsInstance(event["subject"]["cmdline"], list)

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

    def test_syscall_return_is_classified_without_inferring_success(self) -> None:
        allowed = normalize(
            f"AGB_BPF|file.open|pid={os.getpid()}|path=/tmp/example|flags=0|ret=7|syscall=openat",
            {},
        )
        denied = normalize(
            f"AGB_BPF|file.open|pid={os.getpid()}|path=/root/secret|flags=0|ret=-13|syscall=openat",
            {},
        )
        assert allowed is not None and denied is not None
        self.assertEqual(allowed["result"], "allowed")
        self.assertEqual(allowed["resource"]["return_value"], 7)
        self.assertEqual(denied["result"], "denied")
        self.assertEqual(denied["resource"]["error_name"], "EACCES")

    def test_entry_is_not_evidence_until_matching_exit(self) -> None:
        correlator = CorrelatingNormalizer()
        sequences: dict[str, int] = {}
        entered = correlator.normalize(
            f"AGB_BPF|network.connect.enter|tid=42|pid={os.getpid()}|fd=7|"
            "family=AF_INET|address=127.0.0.1|port=443|socket_type=1|protocol=6|syscall=connect",
            sequences,
        )
        event = correlator.normalize(
            f"AGB_BPF|network.connect.exit|tid=42|pid={os.getpid()}|ret=0",
            sequences,
        )
        self.assertIsNone(entered)
        assert event is not None
        self.assertEqual(event["result"], "allowed")
        self.assertEqual(event["resource"]["address"], "127.0.0.1")

    def test_socket_and_bind_are_not_misreported_as_connect(self) -> None:
        socket_event = normalize(
            f"AGB_BPF|network.socket|pid={os.getpid()}|fd=9|family=2|"
            "socket_type=2|protocol=17|ret=9|syscall=socket",
            {},
        )
        bind_event = normalize(
            f"AGB_BPF|network.bind|pid={os.getpid()}|fd=9|family=AF_INET|"
            "address=0.0.0.0|port=0|socket_type=2|protocol=17|ret=0|syscall=bind",
            {},
        )
        assert socket_event is not None and bind_event is not None
        self.assertEqual(socket_event["operation"], "network.socket")
        self.assertEqual(bind_event["operation"], "network.bind")

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
