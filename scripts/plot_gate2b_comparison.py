#!/usr/bin/env python3
"""Render the preregistered Gate 2B baseline versus ASM-CM comparison."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def plot_report(report: dict, output_prefix: Path) -> list[str]:
    config_directory = output_prefix.parent / ".matplotlib"
    config_directory.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(config_directory.resolve()))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    splits = ("test-composition", "test-hidden-family")
    titles = ("Composição inédita", "Família completamente oculta")
    distances = [4, 16, 64, 256, 1024]
    # Reserve a dedicated footer for the explanatory note and the two-row
    # legend. Keeping both outside the axes prevents them from obscuring each
    # other or the distance curves in headless PNG/SVG rendering.
    figure, axes = plt.subplots(1, 2, figsize=(13, 6.4), sharey=True)
    colors = ["#64748b", "#0f766e", "#b45309", "#7c3aed", "#be123c"]

    for axis, split, title in zip(axes, splits, titles):
        baselines = report["baselines"][split]
        for color, result in zip(colors, baselines):
            values = [100 * result["accuracy_by_distance"][str(distance)] for distance in distances]
            axis.plot(distances, values, marker="o", linewidth=1.8, color=color, label=result["engine"])

        seed_values = []
        for seed in report["asm_cm_seeds"]:
            curve = seed["splits"][split]["accuracy_by_distance"]
            seed_values.append([100 * curve[str(distance)] for distance in distances])
        means = [sum(row[index] for row in seed_values) / len(seed_values) for index in range(len(distances))]
        lows = [min(row[index] for row in seed_values) for index in range(len(distances))]
        highs = [max(row[index] for row in seed_values) for index in range(len(distances))]
        axis.fill_between(distances, lows, highs, color="#2563eb", alpha=0.16, label="ASM-CM faixa 3 seeds")
        axis.plot(distances, means, marker="D", linewidth=2.8, color="#2563eb", label="ASM-CM média")
        axis.set_xscale("log", base=2)
        axis.set_xticks(distances, [str(value) for value in distances])
        axis.set_ylim(0, 102)
        axis.grid(True, alpha=0.25)
        axis.set_title(title)
        axis.set_xlabel("Distância causal (eventos)")
    axes[0].set_ylabel("Accuracy (%)")
    handles, labels = axes[1].get_legend_handles_labels()
    figure.legend(
        handles,
        labels,
        loc="lower center",
        bbox_to_anchor=(0.5, 0.025),
        ncol=4,
        frameon=False,
    )
    figure.suptitle("Unix-AGB Gate 2B — generalização causal neutra", fontsize=14, fontweight="bold")
    figure.text(
        0.5,
        0.175,
        "Área azul: mínimo–máximo entre três seeds ASM-CM. Maior é melhor.",
        ha="center",
        fontsize=9,
    )
    figure.tight_layout(rect=(0, 0.23, 1, 0.93))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    png = output_prefix.with_suffix(".png")
    svg = output_prefix.with_suffix(".svg")
    figure.savefig(png, dpi=180, bbox_inches="tight")
    figure.savefig(svg, bbox_inches="tight")
    plt.close(figure)
    return [str(png.resolve()), str(svg.resolve())]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output-prefix", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps({"charts": plot_report(json.loads(args.report.read_text()), args.output_prefix)}, indent=2))


if __name__ == "__main__":
    main()
