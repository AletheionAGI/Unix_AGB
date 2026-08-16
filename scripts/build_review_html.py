#!/usr/bin/env python3
"""Generate a self-contained, offline HTML reviewer from a compact review queue."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.input.is_file():
        parser.error(f"review queue does not exist: {args.input}")
    items = []
    seen = set()
    for line_number, line in enumerate(args.input.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as error:
            parser.error(f"line {line_number}: invalid JSON: {error}")
        trajectory_id = item.get("trajectory_id")
        if not trajectory_id or trajectory_id in seen:
            parser.error(f"line {line_number}: duplicate or missing trajectory_id")
        seen.add(trajectory_id)
        items.append(item)
    if not items:
        parser.error("review queue is empty")
    template = (Path(__file__).resolve().parents[1] / "tools/review/index.html").read_text()
    dataset_id = hashlib.sha256(args.input.read_bytes()).hexdigest()
    payload = json.dumps({"dataset_id": dataset_id, "items": items}, separators=(",", ":"))
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    rendered = template.replace("__AGB_REVIEW_DATA__", payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered)
    print(json.dumps({"review_items": len(items), "output": str(args.output)}))


if __name__ == "__main__":
    main()
