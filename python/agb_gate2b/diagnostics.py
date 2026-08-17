from __future__ import annotations

import math
import random
import statistics
import copy
from typing import Any


def balanced_items(items: list[dict[str, Any]], size: int) -> list[dict[str, Any]]:
    """Return a deterministic, class-balanced diagnostic subset."""
    if size <= 0 or size % 2:
        raise ValueError("diagnostic size must be a positive even number")
    benign = sorted((x for x in items if x["label"] == "benign"), key=lambda x: x["trajectory_id"])
    malicious = sorted((x for x in items if x["label"] == "malicious"), key=lambda x: x["trajectory_id"])
    half = size // 2
    if len(benign) < half or len(malicious) < half:
        raise ValueError("not enough examples for a balanced diagnostic subset")
    result: list[dict[str, Any]] = []
    for left, right in zip(benign[:half], malicious[:half]):
        result.extend((left, right))
    return result


def strip_distractors(item: dict[str, Any]) -> dict[str, Any]:
    """Keep the five setup relations, terminal relation and neutral query."""
    result = dict(item)
    result["events"] = item["events"][:5] + item["events"][-1:]
    result["tokens"] = item["tokens"][:20] + item["tokens"][-5:]
    result["distance"] = 0
    return result


def permute_entity_ids(items: list[dict[str, Any]], seed: int) -> list[dict[str, Any]]:
    """Apply one global bijection to entity tokens, preserving relation tokens."""
    source = list(range(32, 256))
    target = source.copy()
    random.Random(seed).shuffle(target)
    mapping = dict(zip(source, target))
    result = copy.deepcopy(items)
    for item in result:
        item["tokens"] = [mapping.get(token, token) for token in item["tokens"]]
    return result


def add_explicit_equality(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add a derived match/mismatch token before the neutral query.

    This is an intentionally engineered upper bound, not evidence that a model
    discovered the equality relation from raw identifiers.
    """
    result = copy.deepcopy(items)
    for item in result:
        setup = next(event["object"] for event in item["events"] if event["relation"] == "R4")
        terminal = next(event["object"] for event in reversed(item["events"]) if event["relation"] == "R5")
        item["tokens"] = item["tokens"][:-1] + [15 if setup == terminal else 16, item["tokens"][-1]]
    return result


def canonicalize_entity_ids(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rename entity tokens by first occurrence inside each trajectory."""
    result = copy.deepcopy(items)
    for item in result:
        mapping: dict[int, int] = {}
        next_token = 32
        encoded: list[int] = []
        for token in item["tokens"]:
            if token < 32:
                encoded.append(token)
                continue
            if token not in mapping:
                if next_token >= 256:
                    raise ValueError("trajectory exceeds canonical entity-token budget")
                mapping[token] = next_token
                next_token += 1
            encoded.append(mapping[token])
        item["tokens"] = encoded
    return result


def counterfactual_pairs(items: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Pair benign/malicious records sharing the same counterfactual prefix."""
    groups: dict[str, dict[str, dict[str, Any]]] = {}
    for item in items:
        prefix = item["trajectory_id"].rsplit(":", 1)[0]
        groups.setdefault(prefix, {})[item["label"]] = item
    pairs = []
    for prefix in sorted(groups):
        group = groups[prefix]
        if set(group) != {"benign", "malicious"}:
            raise ValueError("counterfactual group must contain both labels")
        left, right = group["benign"], group["malicious"]
        if left["tokens"][:-2] != right["tokens"][:-2]:
            raise ValueError("counterfactual pair differs before terminal destination")
        pairs.append((left, right))
    return pairs


def distribution(values: list[float]) -> dict[str, float]:
    if not values:
        raise ValueError("cannot summarize an empty metric window")
    ordered = sorted(values)
    rank = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return {
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "p95": ordered[rank],
        "maximum": ordered[-1],
    }


def confusion(predictions: list[bool], labels: list[bool]) -> dict[str, int]:
    if len(predictions) != len(labels) or not labels:
        raise ValueError("predictions and labels must be non-empty and aligned")
    return {
        "tn": sum(not p and not y for p, y in zip(predictions, labels)),
        "fp": sum(p and not y for p, y in zip(predictions, labels)),
        "fn": sum(not p and y for p, y in zip(predictions, labels)),
        "tp": sum(p and y for p, y in zip(predictions, labels)),
    }
