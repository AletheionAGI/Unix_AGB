#!/usr/bin/env python3
"""Plot Gate 4 concurrent broker latency and failure-path counts."""

import argparse
import json
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.environ.setdefault("MPLCONFIGDIR", str((args.output.parent / ".matplotlib").resolve()))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    report = json.loads(args.report.read_text())
    scenarios = report["scenarios"]
    names = [item["name"].replace("-", "\n") for item in scenarios]
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8))
    positions = list(range(len(names)))
    width = 0.24
    for offset, (key, color) in enumerate((("p50", "#60a5fa"), ("p95", "#2563eb"), ("p99", "#172554"))):
        axes[0].bar([x + (offset - 1) * width for x in positions], [item["latency_us"][key] / 1000 for item in scenarios], width, label=key.upper(), color=color)
    axes[0].set_xticks(positions, names)
    axes[0].set_ylabel("Broker response latency (ms)")
    axes[0].set_title("Kernel notification → userspace response")
    axes[0].legend()
    listener_index = next(index for index, item in enumerate(scenarios) if item["name"] == "listener-loss")
    axes[0].annotate(
        "WATCHDOG\n(no response)",
        (listener_index, 0),
        xytext=(listener_index, max(item["latency_us"]["p99"] for item in scenarios) / 2000),
        ha="center",
        color="#b91c1c",
        fontweight="bold",
        arrowprops={"arrowstyle": "->", "color": "#b91c1c"},
    )
    overload = [item["responses"]["overload_fail_closed"] for item in scenarios]
    timeouts = [item["responses"]["timeout_fail_closed"] for item in scenarios]
    axes[1].bar(positions, overload, label="Overload fail-closed", color="#f97316")
    axes[1].bar(positions, timeouts, bottom=overload, label="Timeout fail-closed", color="#dc2626")
    axes[1].set_xticks(positions, names)
    axes[1].set_ylabel("Responses")
    axes[1].set_title("Injected degraded paths")
    axes[1].legend()
    recovery_index = next(index for index, item in enumerate(scenarios) if item["name"] == "worker-crash-recovery")
    axes[1].annotate(
        "worker restarted",
        (recovery_index, 0),
        xytext=(recovery_index, max(max(overload), max(timeouts)) * 0.15),
        ha="center",
        color="#15803d",
        fontweight="bold",
        arrowprops={"arrowstyle": "->", "color": "#15803d"},
    )
    fig.suptitle("Unix-AGB Gate 4 — supervised concurrent seccomp broker")
    fig.tight_layout()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, dpi=180)


if __name__ == "__main__":
    main()
