#!/usr/bin/env python3
"""Gate 2B v3 identity-binding representation comparison."""
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
from typing import Any, Callable

from agb_gate2b.diagnostics import (
    add_explicit_equality,
    canonicalize_entity_ids,
    confusion,
    counterfactual_pairs,
    distribution,
    permute_entity_ids,
)
from diagnose_gate2b_asm import relational_items


Transform = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]


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
                logits = model(x, collect_diagnostics=False)["logits"][:, -1, [2, 3]].float()
            probability = logits.softmax(-1)[0]
            prediction = bool(logits.argmax(-1).item())
            predictions.append(prediction)
            confidences.append(float(probability[int(prediction)].item()))
    matrix = confusion(predictions, labels)
    return {
        "accuracy": (matrix["tn"] + matrix["tp"]) / len(items),
        "count": len(items),
        "confusion": matrix,
        "confidence": distribution(confidences),
    }


def groups(items: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    grouped: dict[str, dict[str, dict[str, Any]]] = {}
    for item in items:
        key = item["trajectory_id"].rsplit(":", 1)[0]
        grouped.setdefault(key, {})[item["label"]] = item
    return [(grouped[key]["benign"], grouped[key]["malicious"]) for key in sorted(grouped)]


def train_arm(torch, load_model, checkpoint, device, raw_train, raw_validation, args, arm):
    torch.manual_seed(args.seed + arm["seed_offset"])
    model = load_model(checkpoint).to(device)
    transform: Transform = arm["transform"]
    train_items = transform(raw_train)
    validation_items = transform(raw_validation)
    paired = groups(train_items)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    rng = random.Random(args.seed + arm["seed_offset"])
    history = []
    losses: list[float] = []
    classification_losses: list[float] = []
    auxiliary_losses: list[float] = []
    started = time.perf_counter()
    for step in range(1, args.steps + 1):
        pair = list(rng.choice(paired))
        if arm["permutation_augmentation"]:
            pair = permute_entity_ids(pair, rng.randrange(2**31))
        x = torch.tensor([item["tokens"] for item in pair], dtype=torch.long, device=device)
        target = torch.tensor([0, 1], dtype=torch.long, device=device)
        model.train()
        with precision(torch, device):
            output = model(x, return_states=arm["auxiliary_matching"], collect_diagnostics=False)
            classification_loss = torch.nn.functional.cross_entropy(output["logits"][:, -1, [2, 3]].float(), target)
            auxiliary_loss = torch.zeros((), device=device)
            if arm["auxiliary_matching"]:
                states = output["states"].float()
                similarity = torch.nn.functional.cosine_similarity(states[:, 19], states[:, -2], dim=-1)
                expected = torch.tensor([-1.0, 1.0], device=device)
                auxiliary_loss = torch.nn.functional.cosine_embedding_loss(states[:, 19], states[:, -2], expected, margin=0.2)
            loss = classification_loss + args.auxiliary_weight * auxiliary_loss
        optimizer.zero_grad(set_to_none=True)
        loss.backward()
        gradient_norm = torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0, error_if_nonfinite=True)
        optimizer.step()
        losses.append(float(loss.detach().item()))
        classification_losses.append(float(classification_loss.detach().item()))
        auxiliary_losses.append(float(auxiliary_loss.detach().item()))
        if step == 1 or step % args.report_every == 0 or step == args.steps:
            record = {
                "step": step,
                "loss": distribution(losses),
                "classification_loss": distribution(classification_losses),
                "auxiliary_matching_loss": distribution(auxiliary_losses),
                "gradient_norm_before_clip": float(gradient_norm.detach().item()),
                "train_accuracy": classify(torch, model, train_items, device)["accuracy"],
                "elapsed_sec": time.perf_counter() - started,
            }
            history.append(record); print(json.dumps({"arm": arm["name"], **record}), flush=True)
            losses.clear(); classification_losses.clear(); auxiliary_losses.clear()
    permuted_validation = transform(permute_entity_ids(raw_validation, args.seed + 5000))
    result = {
        "arm": arm["name"],
        "representation": arm["representation"],
        "permutation_augmentation": arm["permutation_augmentation"],
        "auxiliary_matching": arm["auxiliary_matching"],
        "history": history,
        "train": classify(torch, model, train_items, device),
        "new_sessions_disjoint_destinations": classify(torch, model, validation_items, device),
        "permuted_entity_ids": classify(torch, model, permuted_validation, device),
    }
    del model
    if device.type == "cuda": torch.cuda.empty_cache()
    return result


def render(report: dict[str, Any], output: Path) -> None:
    import os
    os.environ.setdefault("MPLCONFIGDIR", str((output.parent / ".matplotlib").resolve()))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    arms = report["arms"]
    names = [arm["arm"] for arm in arms]
    train = [100 * arm["train"]["accuracy"] for arm in arms]
    validation = [100 * arm["new_sessions_disjoint_destinations"]["accuracy"] for arm in arms]
    permuted = [100 * arm["permuted_entity_ids"]["accuracy"] for arm in arms]
    figure, axes = plt.subplots(1, 2, figsize=(15, 5.5))
    x = list(range(len(arms))); width = .25
    axes[0].bar([v-width for v in x], train, width, label="treino")
    axes[0].bar(x, validation, width, label="novas entidades")
    axes[0].bar([v+width for v in x], permuted, width, label="IDs permutados")
    axes[0].set_xticks(x, names, rotation=18, ha="right"); axes[0].set_ylim(0,105)
    axes[0].set(title="Generalização por representação", ylabel="Accuracy (%)")
    for arm in arms:
        axes[1].plot([r["step"] for r in arm["history"]], [100*r["train_accuracy"] for r in arm["history"]], marker="o", label=arm["arm"])
    axes[1].set(title="Ajuste durante treinamento", xlabel="Passo", ylabel="Accuracy de treino (%)", ylim=(0,105))
    for axis in axes: axis.grid(True, axis="y", alpha=.25); axis.legend(frameon=False)
    figure.suptitle("Unix-AGB Gate 2B v3 — binding de identidade", fontweight="bold")
    figure.tight_layout(rect=(0,0,1,.94)); figure.savefig(output, dpi=180); plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--checkpoint-sha256", required=True)
    parser.add_argument("--asm-source-root", type=Path, required=True)
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--steps", type=int, default=400)
    parser.add_argument("--report-every", type=int, default=50)
    parser.add_argument("--lr", type=float, default=1e-4)
    parser.add_argument("--auxiliary-weight", type=float, default=.2)
    parser.add_argument("--output", type=Path, default=Path("var/benchmark/gate2b-v3-binding.json"))
    args = parser.parse_args()
    if sha256(args.checkpoint) != args.checkpoint_sha256:
        raise RuntimeError("initial checkpoint fingerprint mismatch")
    sys.path.insert(0, str(args.asm_source_root.resolve()))
    torch = importlib.import_module("torch")
    load_model = importlib.import_module("drm_language_emitter.checkpoint").load_model
    device = torch.device(args.device)
    if device.type == "cuda" and not torch.cuda.is_available(): raise RuntimeError("CUDA requested but unavailable")
    raw_train = relational_items("probe-train", args.seed)
    raw_validation = relational_items("probe-validation", args.seed + 1000)
    counterfactual_pairs(raw_train); counterfactual_pairs(raw_validation)
    identity = lambda items: items
    arms = [
        {"name":"IDs crus","representation":"raw-entity-ids","transform":identity,"permutation_augmentation":False,"auxiliary_matching":False,"seed_offset":10},
        {"name":"IDs canônicos","representation":"trajectory-local-first-occurrence","transform":canonicalize_entity_ids,"permutation_augmentation":False,"auxiliary_matching":False,"seed_offset":20},
        {"name":"Aug. permutação","representation":"raw-entity-ids","transform":identity,"permutation_augmentation":True,"auxiliary_matching":False,"seed_offset":30},
        {"name":"Canônico + auxiliar","representation":"trajectory-local-first-occurrence","transform":canonicalize_entity_ids,"permutation_augmentation":False,"auxiliary_matching":True,"seed_offset":40},
        {"name":"Igualdade explícita","representation":"derived-explicit-equality-upper-bound","transform":add_explicit_equality,"permutation_augmentation":False,"auxiliary_matching":False,"seed_offset":50},
    ]
    results = [train_arm(torch, load_model, args.checkpoint, device, raw_train, raw_validation, args, arm) for arm in arms]
    serializable_arms = [{key:value for key,value in arm.items() if key != "transform"} for arm in arms]
    probe_hash = hashlib.sha256(json.dumps({"train":raw_train,"validation":raw_validation},sort_keys=True,separators=(",",":")).encode()).hexdigest()
    report = {
        "protocol":"gate2b-v3-identity-binding-v1",
        "claim_scope":"diagnostic only; does not replace Gate 2B v1 or v2",
        "checkpoint_sha256":args.checkpoint_sha256,
        "probe_sha256":probe_hash,
        "configuration":{"seed":args.seed,"steps":args.steps,"lr":args.lr,"auxiliary_weight":args.auxiliary_weight,"arms":serializable_arms},
        "counterfactual_batching":True,
        "arms":results,
        "explicit_equality_warning":"Engineered upper bound; not causal-discovery evidence.",
        "test_evaluated":False,
    }
    args.output.parent.mkdir(parents=True,exist_ok=True); chart=args.output.with_suffix(".png"); report["chart"]=str(chart.resolve())
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n"); render(report,chart)
    print(json.dumps({"output":str(args.output.resolve()),"chart":str(chart.resolve()),"arms":len(results)},indent=2))


if __name__ == "__main__": main()
