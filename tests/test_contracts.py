from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ContractFixtureTests(unittest.TestCase):
    def test_all_schema_documents_are_valid_json(self) -> None:
        schemas = list((ROOT / "schemas").rglob("*.json"))
        self.assertGreaterEqual(len(schemas), 4)
        schema_ids: set[str] = set()
        for path in schemas:
            document = json.loads(path.read_text())
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(document.get("additionalProperties", True))
            if "$id" in document:
                self.assertNotIn(document["$id"], schema_ids)
                schema_ids.add(document["$id"])

    def test_event_fixtures_respect_gate_zero_invariants(self) -> None:
        for path in (ROOT / "fixtures" / "events").glob("*.jsonl"):
            events = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertTrue(events)
            previous_sequences: dict[str, int] = {}
            for event in events:
                subject = event["subject"]
                expected_namespace = (
                    f"process:{subject['boot_id']}:{subject['pid']}:"
                    f"{subject['start_time_ns']}"
                )
                self.assertEqual(event["schema_version"], "1.0")
                self.assertEqual(event["namespace_id"], expected_namespace)
                self.assertEqual(event["provenance"]["source"], "synthetic")
                previous_sequence = previous_sequences.get(event["namespace_id"], 0)
                self.assertGreater(event["sequence"], previous_sequence)
                previous_sequences[event["namespace_id"]] = event["sequence"]


if __name__ == "__main__":
    unittest.main()
