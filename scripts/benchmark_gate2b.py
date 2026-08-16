#!/usr/bin/env python3
from __future__ import annotations

import argparse, hashlib, json, time, tracemalloc
from collections import defaultdict
from pathlib import Path

from agb_gate2b import load_corpus
from agb_gate2b.baselines import CEPGraphBaseline, FSMBaseline, GRUBaseline, RiskScoreBaseline, SlidingWindowBaseline

ROOT = Path(__file__).resolve().parents[1]


def evaluate(engine, items):
    counts = defaultdict(int); by_distance = {}
    latency = []; tracemalloc.start()
    for item in items:
        started = time.perf_counter_ns(); predicted = engine.predict(item); latency.append((time.perf_counter_ns()-started)/1000)
        actual = item["label"] == "malicious"
        counts["tp" if actual and predicted else "fn" if actual else "fp" if predicted else "tn"] += 1
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    for distance in sorted({item["distance"] for item in items}):
        subset = [item for item in items if item["distance"] == distance]
        by_distance[str(distance)] = sum(engine.predict(item) == (item["label"] == "malicious") for item in subset) / len(subset)
    total = len(items)
    return {"engine": engine.name, "confusion": {key: counts[key] for key in ("tp","fp","tn","fn")}, "accuracy": (counts["tp"]+counts["tn"])/total, "accuracy_by_distance": by_distance, "latency_us_mean": sum(latency)/len(latency), "python_peak_bytes": peak}


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--corpus",type=Path,required=True); parser.add_argument("--manifest",type=Path,required=True); parser.add_argument("--budget",type=int,default=64); parser.add_argument("--gru-device",default="cpu"); parser.add_argument("--gru-epochs",type=int,default=3); parser.add_argument("--skip-gru",action="store_true"); parser.add_argument("--gru-checkpoint",type=Path,default=ROOT/"var/benchmark/gate2b-gru.pt"); parser.add_argument("--output",type=Path,default=ROOT/"var/benchmark/gate2b-baselines.json"); args=parser.parse_args()
    manifest=json.loads(args.manifest.read_text()); public_digest=hashlib.sha256(args.corpus.read_bytes()).hexdigest()
    if manifest["public_corpus_sha256"] != public_digest: raise RuntimeError("public corpus manifest mismatch")
    items=load_corpus(args.corpus); calibration=[x for x in items if x["split"]=="calibration"]; validation=[x for x in items if x["split"]=="validation"]
    if len(calibration)+len(validation) != len(items): raise RuntimeError("baseline process received a test split")
    engines=[FSMBaseline(args.budget),CEPGraphBaseline(args.budget),SlidingWindowBaseline(args.budget),RiskScoreBaseline()]
    engines[-1].fit(calibration)
    if not args.skip_gru:
        gru=GRUBaseline(hidden_size=args.budget,device=args.gru_device); gru.fit(calibration,args.gru_epochs); engines.append(gru); args.gru_checkpoint.parent.mkdir(parents=True,exist_ok=True); gru.torch.save({"model":gru.model.state_dict(),"hidden_size":args.budget,"protocol":"gate2b-neutral-v1"},args.gru_checkpoint)
    gru_digest=hashlib.sha256(args.gru_checkpoint.read_bytes()).hexdigest() if args.gru_checkpoint.exists() and not args.skip_gru else None
    report={"benchmark":"unix-agb-gate2b-baselines-v1","dataset_sha256":hashlib.sha256(args.corpus.read_bytes()).hexdigest(),"state_budget":args.budget,"engine_configuration":{"fsm_budget":args.budget,"cep_budget":args.budget,"window":args.budget,"risk_threshold":engines[3].threshold,"gru_hidden_size":args.budget,"gru_epochs":args.gru_epochs},"fit_splits":["calibration"],"selection_split":"validation","sealed_test_splits":["test-composition","test-hidden-family"],"test_evaluated":False,"validation":[evaluate(e,validation) for e in engines],"gru_checkpoint_sha256":gru_digest,"asm_cm_included":False,"claim":"Baselines are frozen before ASM-CM training; test labels were not evaluated."}
    report["sealed_test_sha256"]=manifest["sealed_test_sha256"]; report["manifest_sha256"]=hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n"); print(json.dumps(report,indent=2,sort_keys=True))
if __name__=="__main__": main()
