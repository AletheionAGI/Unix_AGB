#!/usr/bin/env python3
"""Serve the offline review UI and persist validated review decisions."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ALLOWED_LABELS = {"benign", "malicious"}
ALLOWED_CONFIDENCE = {"high", "low"}


def load_jsonl(path: Path, *, required: bool = True) -> list[dict[str, Any]]:
    if not path.is_file():
        if required:
            raise ValueError(f"file does not exist: {path}")
        return []
    items = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}: line {line_number}: invalid JSON: {error}") from error
        if not isinstance(item, dict):
            raise ValueError(f"{path}: line {line_number}: expected an object")
        items.append(item)
    return items


def validate_review(review: dict[str, Any], candidate_ids: set[str]) -> dict[str, str]:
    required = {"trajectory_id", "label", "label_source", "family"}
    allowed = required | {"review_confidence"}
    if not required <= set(review) or not set(review) <= allowed:
        raise ValueError(f"review fields must be {sorted(required)} with optional review_confidence")
    if review["trajectory_id"] not in candidate_ids:
        raise ValueError("unknown trajectory_id")
    if review["label"] not in ALLOWED_LABELS:
        raise ValueError("label must be benign or malicious")
    confidence = review.get("review_confidence", "high")
    if confidence not in ALLOWED_CONFIDENCE:
        raise ValueError("review_confidence must be high or low")
    for field in ("trajectory_id", "label_source", "family"):
        if not isinstance(review[field], str) or not review[field].strip():
            raise ValueError(f"{field} must be a non-empty string")
    validated = {field: review[field].strip() for field in required}
    validated["review_confidence"] = confidence
    return validated


def write_reviews(path: Path, order: list[str], reviews: dict[str, dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        "".join(json.dumps(reviews[item], sort_keys=True) + "\n" for item in order if item in reviews)
    )
    temporary.replace(path)


def render(template: str, queue_path: Path, items: list[dict[str, Any]], reviews: dict[str, Any], token: str) -> bytes:
    payload = json.dumps(
        {
            "dataset_id": hashlib.sha256(queue_path.read_bytes()).hexdigest(),
            "items": items,
            "initial_reviews": reviews,
            "server_mode": True,
            "csrf_token": token,
        },
        separators=(",", ":"),
    )
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return template.replace("__AGB_REVIEW_DATA__", payload).encode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--reviews", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    try:
        items = load_jsonl(args.queue)
        candidate_ids = {item["trajectory_id"] for item in items}
        if len(candidate_ids) != len(items):
            raise ValueError("review queue contains duplicate trajectory IDs")
        existing = load_jsonl(args.reviews, required=False)
        reviews = {
            item["trajectory_id"]: validate_review(item, candidate_ids)
            for item in existing
            if item.get("label") in ALLOWED_LABELS
        }
    except (KeyError, ValueError, OSError) as error:
        parser.error(str(error))
    order = [item["trajectory_id"] for item in items]
    token = secrets.token_urlsafe(24)
    template = (Path(__file__).resolve().parents[1] / "tools/review/index.html").read_text()
    review_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def respond(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path != "/":
                self.respond(404, "text/plain; charset=utf-8", b"not found\n")
                return
            with review_lock:
                page = render(template, args.queue, items, reviews, token)
            self.respond(200, "text/html; charset=utf-8", page)

        def do_POST(self) -> None:
            if self.path != "/api/review":
                self.respond(404, "application/json", b'{"error":"not found"}')
                return
            if self.headers.get("X-AGB-CSRF") != token:
                self.respond(403, "application/json", b'{"error":"invalid CSRF token"}')
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536:
                    raise ValueError("invalid request size")
                review = validate_review(json.loads(self.rfile.read(length)), candidate_ids)
                with review_lock:
                    reviews[review["trajectory_id"]] = review
                    write_reviews(args.reviews, order, reviews)
                    reviewed = len(reviews)
                body = json.dumps({"saved": True, "reviewed": reviewed}).encode()
                self.respond(200, "application/json", body)
            except (json.JSONDecodeError, OSError, ValueError) as error:
                self.respond(400, "application/json", json.dumps({"error": str(error)}).encode())

        def log_message(self, format: str, *values: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Unix-AGB reviewer: http://127.0.0.1:{args.port}")
    print(f"Writing reviews to: {args.reviews}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nReviewer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
