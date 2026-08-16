from __future__ import annotations

from collections import OrderedDict, deque
from typing import Any


def malicious_from_links(events: list[dict[str, str]], retained: int | None = None) -> bool:
    tool_family: OrderedDict[str, str] = OrderedDict()
    family_destination: OrderedDict[str, str] = OrderedDict()

    def put(mapping: OrderedDict[str, str], key: str, value: str) -> None:
        mapping[key] = value
        mapping.move_to_end(key)
        if retained is not None:
            while len(tool_family) + len(family_destination) > retained:
                target = tool_family if tool_family and (not family_destination or next(iter(tool_family)) <= next(iter(family_destination))) else family_destination
                target.popitem(last=False)

    terminal_tool = terminal_destination = None
    for event in events:
        relation = event["relation"]
        if relation == "R3":
            put(tool_family, event["subject"], event["object"])
        elif relation == "R4":
            put(family_destination, event["subject"], event["object"])
        elif relation == "R5":
            terminal_tool, terminal_destination = event["subject"], event["object"]
    family = tool_family.get(terminal_tool or "")
    return bool(family and family_destination.get(family) == terminal_destination)


class FSMBaseline:
    name = "fsm-bounded"

    def __init__(self, budget: int = 64):
        self.budget = budget

    def predict(self, item: dict[str, Any]) -> bool:
        meaningful = deque(maxlen=self.budget)
        for event in item["events"]:
            if event["relation"] != "RN":
                meaningful.append(event)
        return malicious_from_links(list(meaningful))


class CEPGraphBaseline:
    name = "cep-graph-bounded"

    def __init__(self, budget: int = 64):
        self.budget = budget

    def predict(self, item: dict[str, Any]) -> bool:
        return malicious_from_links(item["events"], retained=self.budget)


class SlidingWindowBaseline:
    name = "sliding-window"

    def __init__(self, window: int = 64):
        self.window = window

    def predict(self, item: dict[str, Any]) -> bool:
        return malicious_from_links(item["events"][-self.window :])


class RiskScoreBaseline:
    name = "conventional-risk-score"

    def __init__(self):
        self.threshold = 0.0

    @staticmethod
    def score(item: dict[str, Any]) -> float:
        counts = {key: 0 for key in ("R0", "R1", "R2", "R3", "R4", "R5")}
        for event in item["events"]:
            if event["relation"] in counts:
                counts[event["relation"]] += 1
        return counts["R5"] - 0.05 * abs(counts["R3"] - counts["R4"])

    def fit(self, items: list[dict[str, Any]]) -> None:
        candidates = sorted({self.score(item) for item in items})
        best = (-1.0, 0.0)
        for threshold in candidates:
            accuracy = sum((self.score(item) >= threshold) == (item["label"] == "malicious") for item in items) / len(items)
            best = max(best, (accuracy, threshold))
        self.threshold = best[1]

    def predict(self, item: dict[str, Any]) -> bool:
        return self.score(item) >= self.threshold


class GRUBaseline:
    name = "gru"

    def __init__(self, *, hidden_size: int = 64, seed: int = 1, device: str = "cpu"):
        import torch
        self.torch = torch
        torch.manual_seed(seed)
        self.device = torch.device(device)
        self.model = torch.nn.Sequential()  # registered holder is replaced below
        class Model(torch.nn.Module):
            def __init__(inner):
                super().__init__()
                inner.embedding = torch.nn.Embedding(256, 32)
                inner.gru = torch.nn.GRU(32, hidden_size, batch_first=True)
                inner.head = torch.nn.Linear(hidden_size, 2)
            def forward(inner, x):
                output, _ = inner.gru(inner.embedding(x))
                return inner.head(output[:, -1])
        self.model = Model().to(self.device)

    def fit(self, items: list[dict[str, Any]], epochs: int = 3) -> None:
        torch = self.torch
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=2e-3)
        ordered = sorted(items, key=lambda item: (item["distance"], item["trajectory_id"]))
        self.model.train()
        for _ in range(epochs):
            for item in ordered:
                x = torch.tensor([item["tokens"]], device=self.device)
                y = torch.tensor([item["label"] == "malicious"], dtype=torch.long, device=self.device)
                loss = torch.nn.functional.cross_entropy(self.model(x), y)
                optimizer.zero_grad(set_to_none=True); loss.backward(); optimizer.step()

    def predict(self, item: dict[str, Any]) -> bool:
        torch = self.torch
        self.model.eval()
        with torch.inference_mode():
            x = torch.tensor([item["tokens"]], device=self.device)
            return bool(self.model(x).argmax(-1).item())
