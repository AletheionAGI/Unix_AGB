#!/usr/bin/env python3
"""Evaluate frozen raw/canonical v4 candidates on the fresh sealed test."""
from __future__ import annotations
import argparse,hashlib,importlib,json,sys,time,subprocess
from contextlib import nullcontext
from pathlib import Path
from agb_gate2b import load_corpus
from agb_gate2b.baselines import CEPGraphBaseline,FSMBaseline,GRUBaseline,RiskScoreBaseline,SlidingWindowBaseline
from agb_gate2b.diagnostics import canonicalize_entity_ids,distribution
from agb_gate2b.neutral import validate_corpus
from benchmark_gate2b import evaluate
from plot_gate2b_v4 import plot_report

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def spec(raw):
    representation,seed,path,sha=raw.split(":",3); return representation,int(seed),Path(path),sha
class ASM:
    name="asm-cm-neutral"
    def __init__(self,model,torch,device): self.model=model; self.torch=torch; self.device=device
    def predict(self,item):
        with self.torch.inference_mode(),(self.torch.autocast("cuda",dtype=self.torch.bfloat16) if self.device.type=="cuda" else nullcontext()):
            x=self.torch.tensor([item["tokens"]],device=self.device); logits=self.model(x,collect_diagnostics=False)["logits"][:,-1,[2,3]]
        return bool(logits.argmax(-1).item())
def fpr(result):
    c=result["confusion"]; return c["fp"]/(c["fp"]+c["tn"])
def main():
    p=argparse.ArgumentParser(); p.add_argument("--corpus",type=Path,required=True); p.add_argument("--test-corpus",type=Path,required=True); p.add_argument("--manifest",type=Path,required=True); p.add_argument("--baseline-report",type=Path,required=True); p.add_argument("--gru-checkpoint",type=Path,required=True); p.add_argument("--asm-source-root",type=Path,required=True); p.add_argument("--asm-source-revision",required=True); p.add_argument("--checkpoint",action="append",type=spec,required=True); p.add_argument("--device",default="cuda"); p.add_argument("--output",type=Path,required=True); p.add_argument("--chart-prefix",type=Path,required=True); a=p.parse_args()
    expected={(representation,seed) for representation in ("raw","canonical") for seed in (1,2,3)}
    if {(r,s) for r,s,_,_ in a.checkpoint}!=expected or len(a.checkpoint)!=6: p.error("six distinct raw/canonical seed checkpoints are required")
    frozen=json.loads(a.baseline_report.read_text()); manifest=json.loads(a.manifest.read_text()); public_sha=digest(a.corpus); sealed_sha=digest(a.test_corpus)
    if frozen["dataset_sha256"]!=public_sha or frozen["sealed_test_sha256"]!=sealed_sha or manifest["sealed_test_sha256"]!=sealed_sha or frozen["test_evaluated"] is not False or frozen["gru_checkpoint_sha256"]!=digest(a.gru_checkpoint): raise RuntimeError("v4 freeze or sealed test mismatch")
    public=load_corpus(a.corpus,required_splits={"calibration","validation"}); raw_tests=load_corpus(a.test_corpus,required_splits={"test-composition","test-hidden-family"}); validate_corpus(public+raw_tests,required_splits={"calibration","validation","test-composition","test-hidden-family"})
    actual_revision=subprocess.check_output(["git","-C",str(a.asm_source_root),"rev-parse","HEAD"],text=True).strip()
    if actual_revision!=a.asm_source_revision: raise RuntimeError("ASM source revision mismatch")
    canonical_tests=[]; canonical_latencies=[]
    for item in raw_tests:
        started=time.perf_counter_ns(); canonical_tests.extend(canonicalize_entity_ids([item])); canonical_latencies.append((time.perf_counter_ns()-started)/1000)
    config=frozen["engine_configuration"]; engines=[FSMBaseline(config["fsm_budget"]),CEPGraphBaseline(config["cep_budget"]),SlidingWindowBaseline(config["window"]),RiskScoreBaseline()]; engines[-1].threshold=config["risk_threshold"]
    gru=GRUBaseline(hidden_size=config["gru_hidden_size"],device=a.device); torch=gru.torch; payload=torch.load(a.gru_checkpoint,map_location=a.device,weights_only=True); gru.model.load_state_dict(payload["model"]); engines.append(gru)
    splits=frozen["sealed_test_splits"]; baselines={split:[evaluate(engine,[x for x in raw_tests if x["split"]==split]) for engine in engines] for split in splits}
    sys.path.insert(0,str(a.asm_source_root.resolve())); load_model=importlib.import_module("drm_language_emitter.checkpoint").load_model; device=torch.device(a.device); results={"raw":[],"canonical":[]}; baseline_sha=digest(a.baseline_report); canonicalizer_sha=digest(Path(__file__).resolve().parents[1]/"python/agb_gate2b/diagnostics.py")
    for representation,seed,path,sha in sorted(a.checkpoint):
        if digest(path)!=sha: raise RuntimeError(f"checkpoint fingerprint mismatch: {representation}/{seed}")
        metadata=torch.load(path,map_location="cpu",weights_only=True).get("gate2b_v4",{})
        if metadata.get("dataset_sha256")!=public_sha or metadata.get("baseline_report_sha256")!=baseline_sha or metadata.get("asm_source_revision")!=actual_revision or metadata.get("representation")!=representation or metadata.get("test_seen") is not False: raise RuntimeError("candidate is not bound to v4")
        if representation=="canonical" and metadata.get("canonicalizer_sha256")!=canonicalizer_sha: raise RuntimeError("canonicalizer fingerprint mismatch")
        test_items=canonical_tests if representation=="canonical" else raw_tests; engine=ASM(load_model(path).to(device).eval(),torch,device); results[representation].append({"seed":seed,"checkpoint_sha256":sha,"splits":{split:evaluate(engine,[x for x in test_items if x["split"]==split]) for split in splits}})
    criteria=[]
    for candidate in results["canonical"]:
        checks=[]
        for split in splits:
            best_by_distance={str(distance):max(result["accuracy_by_distance"][str(distance)] for result in baselines[split]) for distance in (256,1024)}
            checks.extend(candidate["splits"][split]["accuracy_by_distance"][str(distance)]>=best_by_distance[str(distance)]+.05 for distance in (256,1024))
        hidden_best=max(result["accuracy"] for result in baselines["test-hidden-family"]); checks.append(candidate["splits"]["test-hidden-family"]["accuracy"]>=hidden_best+.05)
        for split in splits:
            best_accuracy=max(result["accuracy"] for result in baselines[split]); best_fpr=min(fpr(result) for result in baselines[split] if result["accuracy"]==best_accuracy); checks.append(fpr(candidate["splits"][split])<=best_fpr+.01)
        criteria.append({"seed":candidate["seed"],"passed":all(checks),"checks":checks})
    report={"benchmark":"unix-agb-gate2b-v4-canonical-confirmation-v1","public_dataset_sha256":public_sha,"sealed_test_sha256":sealed_sha,"baseline_report_sha256":baseline_sha,"asm_source_revision":actual_revision,"baselines":baselines,"raw_asm_seeds":results["raw"],"canonical_asm_seeds":results["canonical"],"canonicalization":{"implementation_sha256":canonicalizer_sha,"trajectories":len(raw_tests),"latency_us":distribution(canonical_latencies),"total_us":sum(canonical_latencies)},"criteria":{"reference":"docs/gate2b-v4-canonical-confirmation.md","per_seed":criteria,"supported":all(x["passed"] for x in criteria)},"test_evaluated":True,"limitations":"Fresh confirmatory split from the same synthetic generator family; not natural security telemetry."}
    report["charts"]=plot_report(report,a.chart_prefix); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n"); print(json.dumps(report,indent=2,sort_keys=True))
if __name__=="__main__": main()
