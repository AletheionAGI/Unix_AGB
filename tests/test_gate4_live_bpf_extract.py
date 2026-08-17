import json
import tempfile
import unittest
from pathlib import Path

from extract_gate4_live_bpf_trajectory import extract


class LiveBpfExtractTests(unittest.TestCase):
    def test_keeps_exact_bpf_events_through_terminal(self):
        namespace = "process:boot:7:9"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            rows = [
                {"namespace_id": namespace, "sequence": 1, "labels": [], "provenance": {"source": "bpf"}},
                {"namespace_id": "process:other:1:1", "sequence": 1, "labels": [], "provenance": {"source": "bpf"}},
                {"namespace_id": namespace, "sequence": 2, "labels": ["credential"], "provenance": {"source": "bpf"}},
                {"namespace_id": namespace, "sequence": 3, "labels": [], "provenance": {"source": "bpf"}},
            ]
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            self.assertEqual(extract(path, namespace), [rows[0], rows[2]])


if __name__ == "__main__":
    unittest.main()
