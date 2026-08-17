from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from serve_review_ui import render, validate_review, write_reviews


class ReviewUiTests(unittest.TestCase):
    def test_review_validation_and_atomic_ordered_write(self) -> None:
        ids = {"candidate:a", "candidate:b"}
        first = validate_review(
            {
                "trajectory_id": "candidate:a",
                "label": "benign",
                "label_source": "human-review:test",
                "family": "developer-tooling",
            },
            ids,
        )
        self.assertEqual(first["review_confidence"], "high")
        low = validate_review(
            {
                "trajectory_id": "candidate:b",
                "label": "benign",
                "label_source": "human-review:test",
                "family": "container-runtime",
                "review_confidence": "low",
            },
            ids,
        )
        self.assertEqual(low["review_confidence"], "low")
        excluded = validate_review(
            {
                "trajectory_id": "candidate:b",
                "label": "inconclusive",
                "label_source": "human-review:test",
                "family": "unknown",
                "review_confidence": "low",
                "review_reason": "requested-only network events",
            },
            ids,
        )
        self.assertEqual(excluded["label"], "inconclusive")
        self.assertEqual(excluded["review_reason"], "requested-only network events")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reviews.jsonl"
            write_reviews(path, ["candidate:b", "candidate:a"], {"candidate:a": first})
            self.assertEqual(json.loads(path.read_text())["trajectory_id"], "candidate:a")
            self.assertFalse(path.with_suffix(".jsonl.tmp").exists())

    def test_render_escapes_script_terminators(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            queue = Path(directory) / "queue.jsonl"
            queue.write_text("{}\n")
            page = render(
                "const DATA=__AGB_REVIEW_DATA__",
                queue,
                [{"trajectory_id": "candidate:</script>"}],
                {},
                "token",
            ).decode()
            self.assertNotIn("</script>", page)
            self.assertIn("\\u003c/script\\u003e", page)


if __name__ == "__main__":
    unittest.main()
