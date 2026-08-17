#!/usr/bin/env python3
"""Run an unattended, hash-chained Gate 4 campaign without network APIs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

TARGET_DOMAINS = {
    "real_application_coverage", "concurrency_endurance",
    "namespace_application_isolation", "production_resource_latency",
    "ubuntu_boot_matrix",
}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(path: Path) -> str:
    block = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            block.update(chunk)
    return block.hexdigest()


def validate_command(command: object, field: str) -> list[str]:
    if not isinstance(command, list) or not command or not all(isinstance(x, str) and x for x in command):
        raise ValueError(f"{field} must be a non-empty argv array")
    return command


def validate_manifest(value: dict[str, Any], mode: str, duration: int) -> None:
    required = {"protocol", "artifact_path", "artifact_sha256", "policy_revision", "domains", "application_classes",
                "setup", "workloads", "probes", "teardown", "artifacts"}
    if set(value) != required:
        raise ValueError("manifest fields do not match the frozen campaign contract")
    if value["protocol"] != "unix-agb-gate4-automated-campaign-v1":
        raise ValueError("manifest protocol mismatch")
    if not isinstance(value["artifact_sha256"], str) or len(value["artifact_sha256"]) != 64:
        raise ValueError("artifact digest must be SHA-256")
    if not isinstance(value["artifact_path"], str) or not value["artifact_path"]:
        raise ValueError("artifact path is required")
    if not isinstance(value["policy_revision"], str) or not value["policy_revision"].startswith("policy:"):
        raise ValueError("policy revision is invalid")
    for field in ("setup", "probes", "teardown"):
        if not isinstance(value[field], list):
            raise ValueError(f"{field} must be a list")
        for index, item in enumerate(value[field]):
            validate_command(item, f"{field}[{index}]")
    if not isinstance(value["workloads"], list):
        raise ValueError("workloads must be a list")
    identifiers = set()
    for index, workload in enumerate(value["workloads"]):
        if set(workload) != {"id", "class", "command", "allow_early_exit"}:
            raise ValueError(f"workloads[{index}] fields invalid")
        if workload["id"] in identifiers:
            raise ValueError("workload IDs must be unique")
        identifiers.add(workload["id"])
        validate_command(workload["command"], f"workloads[{index}].command")
        if not isinstance(workload["allow_early_exit"], bool):
            raise ValueError("allow_early_exit must be boolean")
    if not isinstance(value["artifacts"], list) or not all(isinstance(x, str) and x for x in value["artifacts"]):
        raise ValueError("artifacts must be path strings")
    if mode == "formal":
        if duration < 28_800:
            raise ValueError("formal duration must be at least eight hours")
        if len(value["workloads"]) < 32:
            raise ValueError("formal campaign requires at least 32 workload groups")
        if len(set(value["application_classes"])) < 3:
            raise ValueError("formal campaign requires at least three application classes")
        if set(value["domains"]) != TARGET_DOMAINS:
            raise ValueError("formal campaign must declare the five coordinated domains")


def run_command(command: list[str], timeout: float) -> dict[str, object]:
    started = time.monotonic_ns()
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout)
        return {"argv": command, "returncode": result.returncode,
                "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                "duration_ms": (time.monotonic_ns() - started) / 1_000_000}
    except subprocess.TimeoutExpired as error:
        return {"argv": command, "returncode": None, "timeout": True,
                "stdout_sha256": hashlib.sha256(error.stdout or b"").hexdigest(),
                "stderr_sha256": hashlib.sha256(error.stderr or b"").hexdigest(),
                "duration_ms": (time.monotonic_ns() - started) / 1_000_000}


def process_metrics(pid: int) -> dict[str, int]:
    stat = Path(f"/proc/{pid}/stat").read_text().split()
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    rss = next(int(line.split()[1]) for line in status if line.startswith("VmRSS:"))
    return {"pid": pid, "cpu_ticks": int(stat[13]) + int(stat[14]), "rss_kib": rss,
            "fd_count": len(list(Path(f"/proc/{pid}/fd").iterdir()))}


def append_sync(path: Path, value: object) -> None:
    with path.open("ab", buffering=0) as stream:
        stream.write(canonical(value) + b"\n")
        os.fsync(stream.fileno())


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("wb") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True).encode() + b"\n")
        stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)


def terminate(process: subprocess.Popen[bytes], grace: float = 5.0) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try: process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--mode", choices=("smoke", "formal"), required=True)
    parser.add_argument("--duration-seconds", type=int, required=True)
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.duration_seconds < 1 or args.interval_seconds <= 0:
        parser.error("duration and interval must be positive")
    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    try: validate_manifest(manifest, args.mode, args.duration_seconds)
    except ValueError as error: parser.error(str(error))
    frozen_artifact = Path(manifest["artifact_path"])
    if not frozen_artifact.is_file():
        parser.error("frozen artifact does not exist")
    if digest(frozen_artifact) != manifest["artifact_sha256"]:
        parser.error("frozen artifact SHA-256 mismatch")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    heartbeats = args.output_dir / "heartbeats.jsonl"
    failures_path = args.output_dir / "failures.jsonl"
    summary_path = args.output_dir / "summary.json"
    heartbeats.unlink(missing_ok=True); failures_path.unlink(missing_ok=True)
    failures: list[dict[str, object]] = []; setup_results = []; teardown_results = []
    workloads: list[tuple[dict[str, Any], subprocess.Popen[bytes]]] = []
    interrupted = False; chain = "0" * 64; samples = 0
    maxima = {"rss_kib": 0, "fd_count": 0, "cpu_ticks": 0}

    def stop(_signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True
    signal.signal(signal.SIGINT, stop); signal.signal(signal.SIGTERM, stop)
    started_wall = time.time(); started_mono = time.monotonic()
    try:
        for command in manifest["setup"]:
            result = run_command(command, 300); setup_results.append(result)
            if result["returncode"] != 0:
                failures.append({"type": "setup", "result": result}); raise RuntimeError("setup failed")
        for item in manifest["workloads"]:
            process = subprocess.Popen(item["command"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
            workloads.append((item, process))
        deadline = started_mono + args.duration_seconds
        while time.monotonic() < deadline and not interrupted:
            process_rows = []
            for item, process in workloads:
                code = process.poll()
                if code is not None:
                    row = {"type": "workload_exit", "id": item["id"], "returncode": code}
                    if not item["allow_early_exit"] and not any(f.get("id") == item["id"] for f in failures):
                        failures.append(row); append_sync(failures_path, row)
                    continue
                try: metrics = process_metrics(process.pid)
                except (OSError, StopIteration, ValueError) as error:
                    row = {"type": "metric_read", "id": item["id"], "error": str(error)}
                    failures.append(row); append_sync(failures_path, row); continue
                process_rows.append({"id": item["id"], "class": item["class"], **metrics})
                for field in maxima: maxima[field] = max(maxima[field], metrics[field])
            probes = [run_command(command, min(60.0, args.interval_seconds)) for command in manifest["probes"]]
            for result in probes:
                if result["returncode"] != 0:
                    row = {"type": "probe", "result": result}; failures.append(row); append_sync(failures_path, row)
            load = os.getloadavg()
            body = {"sample": samples + 1, "wall_epoch": time.time(), "monotonic_seconds": time.monotonic(),
                    "loadavg": load, "processes": process_rows, "probes": probes, "previous_sha256": chain}
            chain = hashlib.sha256(canonical(body)).hexdigest()
            append_sync(heartbeats, {**body, "sha256": chain}); samples += 1
            remaining = deadline - time.monotonic()
            if remaining > 0: time.sleep(min(args.interval_seconds, remaining))
    except Exception as error:
        row = {"type": "runner", "error": str(error)}; failures.append(row); append_sync(failures_path, row)
    finally:
        for _item, process in workloads: terminate(process)
        for command in manifest["teardown"]:
            result = run_command(command, 300); teardown_results.append(result)
            if result["returncode"] != 0:
                row = {"type": "teardown", "result": result}; failures.append(row); append_sync(failures_path, row)
    elapsed = time.monotonic() - started_mono
    artifacts = {}
    for name in manifest["artifacts"]:
        path = Path(name)
        if path.is_file(): artifacts[name] = {"sha256": digest(path), "size": path.stat().st_size}
        else:
            failures.append({"type": "artifact_missing", "path": name})
    complete = not interrupted and elapsed >= args.duration_seconds and not failures
    summary = {"protocol": manifest["protocol"], "mode": args.mode,
               "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
               "artifact_sha256": manifest["artifact_sha256"], "policy_revision": manifest["policy_revision"],
               "started_epoch": started_wall, "elapsed_seconds": elapsed, "requested_seconds": args.duration_seconds,
               "heartbeat_samples": samples, "heartbeat_chain_head": chain, "maxima": maxima,
               "setup": setup_results, "teardown": teardown_results, "failures": failures,
               "artifacts": artifacts, "interrupted": interrupted, "complete": complete,
               "promotion_eligible": args.mode == "formal" and complete}
    atomic_json(summary_path, summary)
    print(json.dumps(summary, sort_keys=True))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
