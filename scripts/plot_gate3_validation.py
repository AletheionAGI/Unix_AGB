#!/usr/bin/env python3
"""Plot the frozen Gate 3 natural/controlled validation without overclaiming."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


def plot_report(report: dict[str, Any], output_prefix: Path) -> list[str]:
    config_directory = output_prefix.parent / ".matplotlib"
    config_directory.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(config_directory.resolve()))
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    natural = report["natural_false_positive_monitoring"]
    controlled = report["controlled_security_efficacy"]
    figure, axes = plt.subplots(1, 3, figsize=(17, 6.5))

    # Natural telemetry: retain review confidence and make zero neural work
    # impossible to miss. This is pipeline-selectivity evidence, not neural FPR.
    natural_axis = axes[0]
    strata = natural["review_confidence_strata"]
    natural_labels = ["Alta\nconfiança", "Baixa\nconfiança"]
    natural_values = [strata["high"]["tn"], strata["low"]["tn"]]
    bars = natural_axis.bar(
        natural_labels, natural_values, color=["#0f766e", "#94a3b8"], width=0.62
    )
    natural_axis.bar_label(bars, labels=[str(value) for value in natural_values], padding=4)
    natural_axis.set_ylim(0, max(natural_values) * 1.2)
    natural_axis.set_ylabel("Trajetórias benignas no teste")
    natural_axis.set_title("Telemetria natural revisada")
    natural_axis.grid(axis="y", alpha=0.22)
    natural_axis.text(
        0.5,
        0.78,
        "TN=697 · FP=0 · ABSTAIN=0\n0 inferências neurais",
        transform=natural_axis.transAxes,
        ha="center",
        va="center",
        fontsize=11,
        fontweight="bold",
        bbox={
            "boxstyle": "round,pad=0.55",
            "facecolor": "#fef3c7",
            "edgecolor": "#d97706",
        },
    )
    natural_axis.text(
        0.5,
        0.68,
        "Evidência de seletividade do pipeline;\nnão mede FPR neural.",
        transform=natural_axis.transAxes,
        ha="center",
        va="top",
        fontsize=9,
    )

    controlled_axis = axes[1]
    family_names = {
        "protected-admin-origin-delayed": "Admin\ndelayed",
        "protected-credential-egress-delayed": "Credential\ndelayed",
        "protected-persistence-origin-delayed": "Persistence\ndelayed",
    }
    families = controlled["families"]
    keys = list(family_names)
    x = list(range(len(keys)))
    tn = [families[key]["tn"] for key in keys]
    tp = [families[key]["tp"] for key in keys]
    controlled_axis.bar(x, tn, color="#2563eb", label="TN benigno")
    controlled_axis.bar(x, tp, bottom=tn, color="#16a34a", label="TP malicioso")
    for position, benign, malicious in zip(x, tn, tp):
        controlled_axis.text(position, benign / 2, f"TN {benign}", ha="center", va="center", color="white", fontsize=9)
        controlled_axis.text(position, benign + malicious / 2, f"TP {malicious}", ha="center", va="center", color="white", fontsize=9)
    controlled_axis.set_xticks(x, [family_names[key] for key in keys])
    controlled_axis.set_ylim(0, max(a + b for a, b in zip(tn, tp)) * 1.38)
    controlled_axis.set_ylabel("Trajetórias controladas no teste")
    controlled_axis.set_title("Composições controladas inéditas")
    controlled_axis.grid(axis="y", alpha=0.22)
    controlled_axis.legend(frameon=False, loc="upper center", ncol=2)
    controlled_axis.text(
        0.5,
        0.86,
        "FP=0 · FN=0 · ABSTAIN=0 · discordância=0",
        transform=controlled_axis.transAxes,
        ha="center",
        va="top",
        fontsize=9,
    )

    latency_axis = axes[2]
    percentiles = ["p50", "p95", "p99"]
    query_ms = [controlled["query_latency_us"][key] / 1000 for key in percentiles]
    latency_bars = latency_axis.bar(
        [label.upper() for label in percentiles],
        query_ms,
        color=["#60a5fa", "#2563eb", "#1e3a8a"],
        width=0.62,
    )
    latency_axis.bar_label(
        latency_bars, labels=[f"{value:.2f} ms" for value in query_ms], padding=4
    )
    latency_axis.set_ylim(0, max(query_ms) * 1.2)
    latency_axis.set_ylabel("Latência por consulta")
    latency_axis.set_title("Ensemble sequencial · RTX 4090")
    latency_axis.grid(axis="y", alpha=0.22)
    latency_axis.text(
        0.5,
        0.84,
        "420 inferências · 3 seeds\n140 consultas protegidas",
        transform=latency_axis.transAxes,
        ha="center",
        va="center",
        fontsize=10,
        bbox={
            "boxstyle": "round,pad=0.5",
            "facecolor": "#eff6ff",
            "edgecolor": "#60a5fa",
        },
    )

    figure.suptitle(
        "Unix-AGB Gate 3 — validação natural e controlada do ensemble",
        fontsize=15,
        fontweight="bold",
    )
    figure.text(
        0.5,
        0.018,
        "Critérios congelados: supported=true · dry-run · enforcement_applied=false · sem ataques naturais maliciosos",
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
    if report.get("benchmark") != "unix-agb-gate3-natural-controlled-ensemble-validation-v1":
        parser.error("report is not the Gate 3 natural/controlled validation")
    print(json.dumps({"charts": plot_report(report, args.output_prefix)}, indent=2))


if __name__ == "__main__":
    main()
