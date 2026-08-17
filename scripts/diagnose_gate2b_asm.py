#!/usr/bin/env python3
"""Gate 2B v2 capacity, observability and causal-distance diagnostics."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import random
import sys
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from agb_gate2b import load_corpus
from agb_gate2b.diagnostics import add_explicit_equality, balanced_items, confusion, distribution, permute_entity_ids, strip_distractors
from generate_gate2b_neutral import trajectory


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def precision(torch, device):
    return torch.autocast("cuda", dtype=torch.bfloat16) if device.type == "cuda" else nullcontext()


def classify(torch, model, items, device) -> dict[str, Any]:
    predictions: list[bool] = []
    labels = [item["label"] == "malicious" for item in items]
    confidences: list[float] = []
    model.eval()
    with torch.inference_mode():
        for item in items:
            x = torch.tensor([item["tokens"]], dtype=torch.long, device=device)
            with precision(torch, device):
                pair = model(x, collect_diagnostics=False)["logits"][:, -1, [2, 3]].float()
            probability = pair.softmax(-1)[0]
            predicted = bool(pair.argmax(-1).item())
            predictions.append(predicted)
            confidences.append(float(probability[int(predicted)].item()))
    matrix = confusion(predictions, labels)
    return {
        "accuracy": (matrix["tn"] + matrix["tp"]) / len(items),
        "count": len(items),
        "confusion": matrix,
        "confidence": distribution(confidences),
    }


def parameter_norm(torch, model, *, trainable_only: bool = False) -> float:
    total = torch.zeros((), device=next(model.parameters()).device)
    with torch.no_grad():
        for parameter in model.parameters():
            if trainable_only and not parameter.requires_grad:
                continue
            total += parameter.float().square().sum()
    return float(total.sqrt().item())


def train_until(torch, model, items, device, *, seed, lr, batch_pairs, max_steps, report_every, threshold):
    rng = random.Random(seed)
    trainable = [parameter for parameter in model.parameters() if parameter.requires_grad]
    if not trainable:
        raise ValueError("training stage has no trainable parameters")
    optimizer = torch.optim.AdamW(trainable, lr=lr, weight_decay=0.01)
    losses: list[float] = []
    gradient_norms: list[float] = []
    records: list[dict[str, Any]] = []
    initial_norm = parameter_norm(torch, model, trainable_only=True)
    started = time.perf_counter()
    classes = {
        False: [x for x in items if x["label"] == "benign"],
        True: [x for x in items if x["label"] == "malicious"],
    }
    if not all(classes.values()):
        raise ValueError("training stage must contain both classes")
    for step in range(1, max_steps + 1):
        # Every batch has one length/distance and exactly the same class count.
        batch = [rng.choice(classes[label]) for label in (False, True) for _ in range(batch_pairs)]
        rng.shuffle(batch)
        x = torch.tensor([item["tokens"] for item in batch], dtype=torch.long, device=device)
        target = torch.tensor([item["label"] == "malicious" for item in batch], dtype=torch.long, device=device)
        model.train()
        if getattr(model, "_gate2b_head_only", False):
            model.eval()
            model._gate2b_trainable_head.train()
        with precision(torch, device):
            logits = model(x, collect_diagnostics=False)["logits"][:, -1, [2, 3]]
            loss = torch.nn.functional.cross_entropy(logits.float(), target)
        optimizer.zero_grad(set_to_none=True)
        loss.backward()
        grad_norm = torch.nn.utils.clip_grad_norm_(trainable, 1.0, error_if_nonfinite=True)
        optimizer.step()
        losses.append(float(loss.detach().item()))
        gradient_norms.append(float(grad_norm.detach().item()))
        if step == 1 or step % report_every == 0 or step == max_steps:
            metrics = classify(torch, model, items, device)
            current_norm = parameter_norm(torch, model, trainable_only=True)
            record = {
                "step": step,
                "loss": distribution(losses),
                "gradient_norm_before_clip": distribution(gradient_norms),
                "train": metrics,
                "parameter_norm": current_norm,
                "relative_parameter_norm_change": abs(current_norm - initial_norm) / max(initial_norm, 1e-12),
                "trainable_parameters": sum(parameter.numel() for parameter in trainable),
                "elapsed_sec": time.perf_counter() - started,
            }
            records.append(record)
            print(json.dumps(record), flush=True)
            losses.clear(); gradient_norms.clear()
            if metrics["accuracy"] >= threshold:
                return {"passed": True, "steps": step, "history": records, "final": metrics}
    return {"passed": False, "steps": max_steps, "history": records, "final": classify(torch, model, items, device)}


def load_fresh(load_model, checkpoint, device):
    return load_model(checkpoint).to(device)


def configure_new_head(torch, model, seed: int):
    """Freeze the encoder and replace the vocabulary projection."""
    torch.manual_seed(seed)
    for parameter in model.parameters():
        parameter.requires_grad_(False)
    if model.emitter.legacy:
        old = model.emitter.net[-1]
        head = torch.nn.Linear(old.in_features, old.out_features, bias=old.bias is not None).to(old.weight.device)
        model.emitter.net[-1] = head
    else:
        old = model.emitter.lm_head
        head = torch.nn.Linear(old.in_features, old.out_features, bias=old.bias is not None).to(old.weight.device)
        model.emitter.lm_head = head
    model._gate2b_head_only = True
    model._gate2b_trainable_head = head
    return model


def relational_items(split: str, seed: int) -> list[dict[str, Any]]:
    """Counterfactual pairs with fixed composition and new sessions/destinations."""
    offset = 10000 if split == "probe-train" else 20000
    items: list[dict[str, Any]] = []
    for repetition in range(16):
        index = offset + repetition
        destination_base = 56 if split == "probe-train" else 72
        setup_destination = destination_base + repetition % 8
        for malicious in (False, True):
            item = trajectory(index, "calibration", 4, malicious, "A0", "T0", "F0", random.Random(seed + repetition))
            item["split"] = split
            item["trajectory_id"] = f"{split}:{repetition}:{int(malicious)}"
            terminal_destination = setup_destination if malicious else destination_base + (repetition + 1) % 8
            item["events"][4]["object"] = f"{split}:D{setup_destination}"
            item["events"][-1]["object"] = f"{split}:D{terminal_destination}"
            item["tokens"][19] = setup_destination
            item["tokens"][-2] = terminal_destination
            items.append(item)
    return items


def run_relational_probe(torch, load_model, checkpoint, device, train_items, validation_items, args, *, mode, explicit=False):
    model = load_fresh(load_model, checkpoint, device)
    if mode == "head-only":
        configure_new_head(torch, model, args.seed + 900)
    fit_items = add_explicit_equality(train_items) if explicit else train_items
    evaluation_items = add_explicit_equality(validation_items) if explicit else validation_items
    training = train_until(torch, model, fit_items, device, seed=args.seed + 700, lr=args.lr, batch_pairs=args.batch_pairs, max_steps=args.max_steps, report_every=args.report_every, threshold=args.pass_threshold)
    result = {
        "mode": mode,
        "representation": "derived-explicit-equality" if explicit else "raw-entity-ids",
        "training": training,
        "same_composition_new_sessions_destinations": classify(torch, model, evaluation_items, device),
        "permuted_entity_ids": classify(torch, model, permute_entity_ids(evaluation_items, args.seed + 808), device),
        "counterfactual_pairs": classify(torch, model, evaluation_items, device),
    }
    del model
    if device.type == "cuda": torch.cuda.empty_cache()
    return result


def render(torch, report: dict[str, Any], output: Path) -> None:
    import os
    os.environ.setdefault("MPLCONFIGDIR", str((output.parent / ".matplotlib").resolve()))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    figure, axes = plt.subplots(1, 3, figsize=(17, 5.2))
    for run in report["capacity_checks"]:
        history = run["training"]["history"]
        axes[0].plot([x["step"] for x in history], [x["loss"]["mean"] for x in history], marker="o", label=f'{run["examples"]} exemplos')
        axes[1].plot([x["step"] for x in history], [100 * x["train"]["accuracy"] for x in history], marker="o", label=f'{run["examples"]} exemplos')
    axes[0].set(title="Loss média por janela", xlabel="Passo", ylabel="Cross-entropy [logits 2, 3]")
    axes[1].set(title="Memorização do conjunto mínimo", xlabel="Passo", ylabel="Accuracy (%)", ylim=(0, 102))
    ladder = report["causal_ladder"]
    distances = [stage["distance"] for stage in ladder]
    axes[2].plot(distances, [100 * stage["training"]["final"]["accuracy"] for stage in ladder], marker="o", label="treino")
    axes[2].plot(distances, [100 * stage["validation"]["accuracy"] for stage in ladder], marker="o", label="validação")
    zero_shot = [(stage["next_distance_zero_shot"]["distance"], 100 * stage["next_distance_zero_shot"]["metrics"]["accuracy"]) for stage in ladder if "next_distance_zero_shot" in stage]
    if zero_shot:
        axes[2].plot([x for x, _ in zero_shot], [y for _, y in zero_shot], marker="D", linestyle="--", label="zero-shot")
    axes[2].set_xscale("log", base=2); axes[2].set_xticks([4,16,64,256,1024],["4","16","64","256","1024"])
    axes[2].set(title="Escada causal", xlabel="Distância", ylabel="Accuracy (%)", ylim=(0, 102))
    for axis in axes: axis.grid(True, alpha=.25); axis.legend(frameon=False)
    figure.suptitle("Unix-AGB Gate 2B v2 — diagnóstico de capacidade", fontweight="bold")
    figure.tight_layout(rect=(0, 0, 1, .94)); figure.savefig(output, dpi=180); plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--checkpoint-sha256", required=True)
    parser.add_argument("--asm-source-root", type=Path, required=True)
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--lr", type=float, default=1e-4)
    parser.add_argument("--batch-pairs", type=int, default=1)
    parser.add_argument("--max-steps", type=int, default=600)
    parser.add_argument("--report-every", type=int, default=50)
    parser.add_argument("--pass-threshold", type=float, default=.99)
    parser.add_argument("--prior-report", type=Path)
    parser.add_argument("--output", type=Path, default=Path("var/benchmark/gate2b-v2-diagnostic.json"))
    args = parser.parse_args()
    if sha256(args.checkpoint) != args.checkpoint_sha256:
        raise RuntimeError("initial checkpoint fingerprint mismatch")
    sys.path.insert(0, str(args.asm_source_root.resolve()))
    torch = importlib.import_module("torch")
    load_model = importlib.import_module("drm_language_emitter.checkpoint").load_model
    device = torch.device(args.device)
    if device.type == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA requested but unavailable")
    torch.manual_seed(args.seed)
    items = load_corpus(args.corpus)
    calibration = [x for x in items if x["split"] == "calibration"]
    validation = [x for x in items if x["split"] == "validation"]
    if args.prior_report:
        prior = json.loads(args.prior_report.read_text())
        if prior.get("dataset_sha256") != sha256(args.corpus) or prior.get("initial_checkpoint_sha256") != args.checkpoint_sha256 or prior.get("test_evaluated") is not False:
            raise RuntimeError("prior diagnostic fingerprints do not match")
        capacity = prior["capacity_checks"]
        ladder = prior["causal_ladder"]
        ladder_skipped = prior["causal_ladder_skipped"]
    else:
        simple = [strip_distractors(x) for x in calibration if x["distance"] == 4]
        capacity = []
        for size in (2, 8, 32):
            subset = balanced_items(simple, size)
            model = load_fresh(load_model, args.checkpoint, device)
            training = train_until(torch, model, subset, device, seed=args.seed + size, lr=args.lr, batch_pairs=min(args.batch_pairs, size // 2), max_steps=args.max_steps, report_every=args.report_every, threshold=args.pass_threshold)
            capacity.append({"examples": size, "distractors": 0, "training": training})
            del model
            if device.type == "cuda": torch.cuda.empty_cache()
        ladder = []
        ladder_skipped = not all(run["training"]["passed"] for run in capacity)
        if not ladder_skipped:
            model = load_fresh(load_model, args.checkpoint, device)
            for index, distance in enumerate((4, 16, 64, 256, 1024)):
                train_items = [x for x in calibration if x["distance"] == distance]
                training = train_until(torch, model, train_items, device, seed=args.seed + 100 + distance, lr=args.lr, batch_pairs=args.batch_pairs, max_steps=args.max_steps, report_every=args.report_every, threshold=args.pass_threshold)
                stage = {"distance": distance, "training": training, "validation": classify(torch, model, [x for x in validation if x["distance"] == distance], device)}
                if index < 4:
                    next_distance = (4, 16, 64, 256, 1024)[index + 1]
                    stage["next_distance_zero_shot"] = {"distance": next_distance, "metrics": classify(torch, model, [x for x in validation if x["distance"] == next_distance], device)}
                ladder.append(stage)
                if not training["passed"]: break
    probe_train = relational_items("probe-train", args.seed)
    probe_validation = relational_items("probe-validation", args.seed + 1000)
    relational_probes = [
        run_relational_probe(torch, load_model, args.checkpoint, device, probe_train, probe_validation, args, mode="full-finetune"),
        run_relational_probe(torch, load_model, args.checkpoint, device, probe_train, probe_validation, args, mode="head-only"),
        run_relational_probe(torch, load_model, args.checkpoint, device, probe_train, probe_validation, args, mode="full-finetune", explicit=True),
    ]
    result = {
        "protocol": "gate2b-v2-diagnostic-v2",
        "claim_scope": "diagnostic only; does not replace or reinterpret Gate 2B v1",
        "dataset_sha256": sha256(args.corpus),
        "initial_checkpoint_sha256": args.checkpoint_sha256,
        "seed": args.seed,
        "configuration": {"lr": args.lr, "batch_pairs": args.batch_pairs, "max_steps": args.max_steps, "report_every": args.report_every, "pass_threshold": args.pass_threshold},
        "capacity_checks": capacity,
        "causal_ladder_skipped": ladder_skipped,
        "causal_ladder": ladder,
        "relational_probes": relational_probes,
        "relational_probe_sha256": hashlib.sha256(json.dumps({"train": probe_train, "validation": probe_validation}, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "explicit_equality_warning": "Derived equality is an engineered upper bound and is not causal-discovery evidence.",
        "test_evaluated": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    chart = args.output.with_suffix(".png")
    result["chart"] = str(chart.resolve())
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    render(torch, result, chart)
    print(json.dumps({"output": str(args.output.resolve()), "chart": str(chart.resolve()), "capacity_passed": not ladder_skipped, "ladder_stages": len(ladder)}, indent=2))


if __name__ == "__main__":
    main()
