#!/usr/bin/env python3
"""Render Gate 3 ensemble correctness, telemetry, and latency."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


def safe_ratio(numerator: int, denominator: int) -> float:
    return 100.0 * numerator / denominator if denominator else 0.0


def plot_report(report: dict[str, Any], output_prefix: Path) -> list[str]:
    config_directory = output_prefix.parent / ".matplotlib"
    config_directory.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(config_directory.resolve()))
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    confusion = report["terminal_confusion"]
    proofs = report["persistence_proofs"]
    telemetry = report["asm_cm"]["ensemble_telemetry"]
    terminal_total = sum(confusion[key] for key in ("tp", "fp", "tn", "fn", "abstain"))
    metrics = {
        "Accuracy\nterminal": safe_ratio(
            confusion["tp"] + confusion["tn"], terminal_total
        ),
        "Precisão\nDENY": safe_ratio(
            confusion["tp"], confusion["tp"] + confusion["fp"]
        ),
        "Recall\nmalicioso": safe_ratio(
            confusion["tp"], confusion["tp"] + confusion["fn"]
        ),
        "Concordância\n3 seeds": 100.0 * (1.0 - telemetry["disagreement_rate"]),
        "Cobertura\nde auditoria": safe_ratio(
            proofs["audit_record_count"], report["event_count"]
        ),
    }

    figure, axes = plt.subplots(1, 2, figsize=(14, 6.6))
    left, right = axes
    colors = ["#2563eb", "#0f766e", "#16a34a", "#7c3aed", "#b45309"]
    bars = left.bar(metrics.keys(), metrics.values(), color=colors, width=0.68)
    left.set_ylim(0, 108)
    left.set_ylabel("Percentual (%)")
    left.set_title("Resultado e telemetria")
    left.grid(axis="y", alpha=0.22)
    left.bar_label(bars, labels=[f"{value:.1f}%" for value in metrics.values()], padding=4)
    left.text(
        0.5,
        0.035,
        (
            f"TN={confusion['tn']}  TP={confusion['tp']}  FP={confusion['fp']}  "
            f"FN={confusion['fn']}  ABSTAIN={confusion['abstain']}\n"
            f"Discordâncias={telemetry['disagreements']}/{telemetry['events']} · "
            f"DENY no cache={proofs['cache_entry_count']}"
        ),
        transform=left.transAxes,
        ha="center",
        va="bottom",
        fontsize=9,
        bbox={"boxstyle": "round,pad=0.45", "facecolor": "#f8fafc", "edgecolor": "#cbd5e1"},
    )

    stages = ["ASM-CM\n3 seeds", "Audit + cache\nGate 3", "Ponta a ponta"]
    stage_keys = ["asm_cm", "gate3_audit_cache", "end_to_end"]
    percentiles = [("p50", "#60a5fa"), ("p95", "#2563eb"), ("p99", "#1e3a8a")]
    positions = list(range(len(stages)))
    width = 0.23
    for offset, (percentile, color) in enumerate(percentiles):
        values_ms = [report["latency_us"][key][percentile] / 1000 for key in stage_keys]
        shifted = [position + (offset - 1) * width for position in positions]
        latency_bars = right.bar(
            shifted, values_ms, width=width, color=color, label=percentile.upper()
        )
        right.bar_label(
            latency_bars,
            labels=[f"{value:.3g} ms" for value in values_ms],
            padding=3,
            fontsize=8,
            rotation=90,
        )
    right.set_yscale("log")
    right.set_ylim(0.02, 160)
    right.set_xticks(positions, stages)
    right.set_ylabel("Latência por evento (ms, escala log)")
    right.set_title("Latência sequencial na RTX 4090")
    right.grid(axis="y", which="both", alpha=0.22)
    right.legend(frameon=False, ncol=3, loc="upper left")

    figure.suptitle(
        "Unix-AGB Gate 3 — ensemble ASM-CM 2-de-3 em dry-run",
        fontsize=15,
        fontweight="bold",
    )
    figure.text(
        0.5,
        0.015,
        "Corpus BPF controlado · 987 eventos · 423 inferências · enforcement_applied: false",
        ha="center",
        fontsize=9,
    )
    figure.tight_layout(rect=(0, 0.06, 1, 0.93))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    outputs = [output_prefix.with_suffix(".png"), output_prefix.with_suffix(".svg")]
    figure.savefig(outputs[0], dpi=180, bbox_inches="tight")
    figure.savefig(outputs[1], bbox_inches="tight")
    plt.close(figure)
    return [str(path.resolve()) for path in outputs]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output-prefix", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    if report.get("benchmark") != "unix-agb-gate3-asm-cm-ensemble-pipeline-v1":
        parser.error("report is not the Gate 3 ASM-CM ensemble benchmark")
    print(json.dumps({"charts": plot_report(report, args.output_prefix)}, indent=2))


if __name__ == "__main__":
    main()
