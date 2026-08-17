#!/usr/bin/env python3
"""Fail-closed per-domain evaluation of a completed formal campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

from verify_gate4_automated_campaign import verify


def percentile(values: list[float], fraction: float) -> float | None:
    if not values: return None
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--vm-evidence", type=Path, help="authenticated install/reboot/purge evidence for both VMs")
    parser.add_argument("--namespace-evidence", type=Path, help="authenticated namespace isolation matrix")
    parser.add_argument("--resource-evidence", type=Path, help="authenticated audit-growth and host-budget evidence")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text()); manifest = json.loads(args.manifest.read_text())
    profile_sha256 = hashlib.sha256(args.profile.read_bytes()).hexdigest()
    manifest_sha256 = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    summary = json.loads((args.output_dir / "summary.json").read_text())
    integrity = verify(args.manifest, args.output_dir)
    rows = [json.loads(line) for line in (args.output_dir / "heartbeats.jsonl").read_text().splitlines()]
    latencies = [float(probe["duration_ms"]) for row in rows for probe in row.get("probes", [])
                 if probe.get("returncode") == 0]
    latency = {name: percentile(latencies, value) for name, value in (("p50", .50), ("p95", .95), ("p99", .99))}
    budgets = profile["budgets"]
    resources_ok = all((latency[key] is not None and latency[key] <= budgets["probe_latency_ms"][key])
                       for key in ("p50", "p95", "p99")) and all(
        summary["maxima"][key] <= budgets[name] for key, name in
        (("cpu_ticks", "cpu_ticks_per_process"), ("rss_kib", "rss_kib_per_process"),
         ("fd_count", "fd_count_per_process")))
    binding_ok = bool(summary.get("artifact_sha256") == profile["artifact_sha256"] == manifest["artifact_sha256"]
                      and summary.get("policy_revision") == profile["policy_revision"] == manifest["policy_revision"])
    base = bool(integrity["valid"] and binding_ok and summary.get("complete") and summary.get("mode") == "formal"
                and summary.get("elapsed_seconds", 0) >= profile["duration_seconds"] and not summary.get("failures"))
    vm = json.loads(args.vm_evidence.read_text()) if args.vm_evidence and args.vm_evidence.is_file() else {}
    namespace = json.loads(args.namespace_evidence.read_text()) if args.namespace_evidence and args.namespace_evidence.is_file() else {}
    resource = json.loads(args.resource_evidence.read_text()) if args.resource_evidence and args.resource_evidence.is_file() else {}
    def bound(record: dict[str, object]) -> bool:
        return bool(record.get("profile_sha256") == profile_sha256
                    and record.get("manifest_sha256") == manifest_sha256
                    and record.get("artifact_sha256") == profile["artifact_sha256"]
                    and record.get("policy_revision") == profile["policy_revision"]
                    and record.get("protected_fail_open") == 0
                    and record.get("cross_scope_effects") == 0)
    domains = {
        "real_application_coverage": {"supported": base and len(set(manifest["application_classes"])) >= 3
                                      and bound(vm) and vm.get("real_controls_passed") is True,
                                      "requires": ["complete formal run", "three classes", "protected/unprotected controls"]},
        "concurrency_endurance": {"supported": base and len(manifest["workloads"]) >= 32,
                                  "requires": ["32 groups", "eight hours", "zero campaign failures"]},
        "namespace_application_isolation": {"supported": base and bound(namespace) and namespace.get("supported") is True,
                                            "requires": ["authenticated PID/mount/user/network/cgroup matrix"]},
        "production_resource_latency": {"supported": base and resources_ok and bound(resource) and resource.get("supported") is True
                                        and resource.get("audit_bytes", budgets["audit_bytes"] + 1) <= budgets["audit_bytes"],
                                        "requires": ["complete samples", "preregistered CPU/RSS/FD/latency budgets",
                                                     "authenticated audit-growth measurement"]},
        "ubuntu_boot_matrix": {"supported": base and bound(vm) and vm.get("supported") is True
                               and sorted(vm.get("ubuntu_releases", [])) == sorted(profile["ubuntu_releases"]),
                               "requires": ["authenticated 24.04 and 26.04 install/reboot/upgrade/rollback/purge"]},
    }
    result = {"protocol": "unix-agb-gate4-formal-evaluation-v1",
              "profile_sha256": profile_sha256, "manifest_sha256": manifest_sha256,
              "artifact_sha256": summary.get("artifact_sha256"), "policy_revision": summary.get("policy_revision"),
              "integrity": integrity, "binding_valid": binding_ok, "latency_ms": latency, "domains": domains,
              "supported": all(item["supported"] for item in domains.values())}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["supported"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
