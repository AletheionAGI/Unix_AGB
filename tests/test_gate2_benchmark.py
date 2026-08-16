from __future__ import annotations

import json
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "scripts"))

from agb_fake_asm import AsmCmEngine, AsmCmUnavailable, PersistentStatefulProxy, SnapshotError
from agb_fake_asm.server import StateEngineServer
from benchmark_gate2 import adversarial_corpus, corpus, evaluate, persistence_proofs
from benchmark_gate2_multiseed import accuracy
from agb_fake_asm import EventLocalEngine, SequenceRuleEngine, SlidingWindowEngine, StatefulProxyEngine


class AlwaysAbstainEngine:
    name = "test:always-abstain"

    def update(self, event):
        return {"effect": "ABSTAIN", "event_id": event["event_id"]}


class Gate2BenchmarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (ROOT / "fixtures" / "benchmark" / "gate2-v1.json").read_text()
        )
        self.trajectories = corpus(self.manifest)

    def test_frozen_corpus_has_balanced_identical_terminal_actions(self) -> None:
        self.assertEqual(len(self.trajectories), 40)
        self.assertEqual(sum(item["malicious"] for item in self.trajectories), 20)
        terminals = {
            (
                item["events"][-1]["operation"],
                item["events"][-1]["resource"]["path"],
            )
            for item in self.trajectories
        }
        self.assertEqual(terminals, {("file.open", "/run/secrets/api-token")})
        namespaces = {item["events"][0]["namespace_id"] for item in self.trajectories}
        self.assertEqual(len(namespaces), 40)

    def test_modes_are_reproducible_and_proxy_does_not_outclaim_sequence(self) -> None:
        results = {
            engine.name: evaluate(engine, self.trajectories)
            for engine in (EventLocalEngine, SequenceRuleEngine, SlidingWindowEngine, StatefulProxyEngine)
        }
        self.assertEqual(results[SequenceRuleEngine.name]["recall"], 1.0)
        self.assertEqual(results[SequenceRuleEngine.name]["false_positive_rate"], 0.0)
        self.assertEqual(
            results[StatefulProxyEngine.name]["confusion"],
            results[SequenceRuleEngine.name]["confusion"],
        )

    def test_dataset_without_credential_queries_reports_empty_query_latency(self) -> None:
        trajectory = self.trajectories[0]
        without_query_labels = {
            **trajectory,
            "events": [{**event, "labels": []} for event in trajectory["events"]],
        }
        result = evaluate(EventLocalEngine, [without_query_labels])
        self.assertEqual(
            result["query_latency_us"],
            {"sample_count": 0, "p50": None, "p95": None, "p99": None},
        )
        self.assertEqual(result["latency_us"]["sample_count"], len(trajectory["events"]))

    def test_abstention_is_not_counted_as_true_negative(self) -> None:
        result = evaluate(AlwaysAbstainEngine, [self.trajectories[0]])
        self.assertEqual(
            result["confusion"],
            {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "abstain": 1},
        )
        self.assertEqual(result["decision_coverage"]["rate"], 0.0)
        self.assertEqual(accuracy(result), 0.0)
        self.assertEqual(result["families"]["default"]["abstain"], 1)

    def test_source_sequence_preserves_state_across_candidate_windows(self) -> None:
        first = dict(self.trajectories[0]["events"][0])
        first["provenance"] = {**first.get("provenance", {}), "source_sequence": 1}
        second = {**first, "event_id": "event:continuation", "sequence": 1}
        second["provenance"] = {**first["provenance"], "source_sequence": 2}
        base = {"malicious": False, "family": "windowed", "review_confidence": "low"}
        result = evaluate(
            StatefulProxyEngine,
            [{**base, "events": [first]}, {**base, "events": [second]}],
        )
        self.assertEqual(result["confusion"]["abstain"], 0)
        self.assertEqual(result["decision_coverage"]["rate"], 1.0)
        self.assertEqual(result["review_confidence_strata"]["low"]["tn"], 2)

    def test_restart_corruption_gap_and_namespace_proofs(self) -> None:
        self.assertTrue(all(persistence_proofs(self.trajectories).values()))

    def test_initial_sequence_gap_abstains(self) -> None:
        engine = StatefulProxyEngine()
        event = dict(self.trajectories[0]["events"][0])
        event["sequence"] = 2
        self.assertEqual(engine.update(event)["effect"], "ABSTAIN")

    def test_configuration_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            engine = PersistentStatefulProxy(path, "config:v1")
            engine.update(self.trajectories[0]["events"][0])
            with self.assertRaises(SnapshotError):
                PersistentStatefulProxy(path, "config:v2")

    def test_persistent_proxy_runs_behind_unix_socket_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            socket_path = base / "state.sock"
            engine = PersistentStatefulProxy(base / "snapshot.json", "config:test")
            server = StateEngineServer(str(socket_path), engine)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(socket_path))
                    client.sendall(
                        json.dumps(self.trajectories[0]["events"][0]).encode() + b"\n"
                    )
                    response = json.loads(client.makefile("rb").readline())
                self.assertEqual(response["engine"], "D:stateful-proxy")
                self.assertEqual(response["state_revision"], 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_real_adapter_fails_explicitly_without_checkpoint(self) -> None:
        with self.assertRaisesRegex(AsmCmUnavailable, "checkpoint not found"):
            AsmCmEngine(Path("/missing/asm-cm.pt"), ROOT)

    def test_adversarial_v2_keeps_strong_sequence_baseline(self) -> None:
        manifest = json.loads(
            (ROOT / "fixtures" / "benchmark" / "gate2-adversarial-v2.json").read_text()
        )
        trajectories = adversarial_corpus(manifest)
        self.assertEqual(len(trajectories), 60)
        self.assertEqual(sum(item["malicious"] for item in trajectories), 30)
        sequence = evaluate(SequenceRuleEngine, trajectories)
        self.assertEqual(sequence["confusion"], {"tp": 30, "fp": 0, "tn": 30, "fn": 0, "abstain": 0})
        stateful = evaluate(StatefulProxyEngine, trajectories)
        self.assertEqual(stateful["confusion"], sequence["confusion"])


if __name__ == "__main__":
    unittest.main()
