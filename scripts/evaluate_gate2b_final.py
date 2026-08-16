#!/usr/bin/env python3
"""Open Gate 2B test labels only after baseline and ASM checkpoints are frozen."""
from __future__ import annotations
import argparse, hashlib, importlib, json, sys
from contextlib import nullcontext
from pathlib import Path
from agb_gate2b import load_corpus
from agb_gate2b.baselines import CEPGraphBaseline,FSMBaseline,GRUBaseline,RiskScoreBaseline,SlidingWindowBaseline
from benchmark_gate2b import evaluate
from plot_gate2b_comparison import plot_report

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def spec(raw):
    seed,path,sha=raw.split(":",2); return int(seed),Path(path),sha
class ASM:
    name="asm-cm-neutral"
    def __init__(self,model,torch,device): self.model=model; self.torch=torch; self.device=device
    def predict(self,item):
        with self.torch.inference_mode(), (self.torch.autocast("cuda",dtype=self.torch.bfloat16) if self.device.type=="cuda" else nullcontext()):
            x=self.torch.tensor([item["tokens"]],device=self.device); logits=self.model(x,collect_diagnostics=False)["logits"][:,-1]
        return bool(logits[:,[2,3]].argmax(-1).item())
def main():
    p=argparse.ArgumentParser(); p.add_argument("--corpus",type=Path,required=True); p.add_argument("--test-corpus",type=Path,required=True); p.add_argument("--manifest",type=Path,required=True); p.add_argument("--baseline-report",type=Path,required=True); p.add_argument("--gru-checkpoint",type=Path,required=True); p.add_argument("--asm-source-root",type=Path,required=True); p.add_argument("--checkpoint",action="append",type=spec,required=True); p.add_argument("--device",default="cuda"); p.add_argument("--output",type=Path,required=True); p.add_argument("--chart-prefix",type=Path); a=p.parse_args()
    if len(a.checkpoint)!=3 or len({x[0] for x in a.checkpoint})!=3: p.error("exactly three distinct ASM seeds are required")
    frozen=json.loads(a.baseline_report.read_text()); manifest=json.loads(a.manifest.read_text()); dataset_sha=digest(a.corpus)
    if frozen["dataset_sha256"]!=dataset_sha or frozen["sealed_test_sha256"]!=digest(a.test_corpus) or manifest["sealed_test_sha256"]!=digest(a.test_corpus) or frozen["test_evaluated"] is not False or frozen["gru_checkpoint_sha256"]!=digest(a.gru_checkpoint): raise RuntimeError("baseline freeze or sealed test mismatch")
    public=load_corpus(a.corpus,required_splits={"calibration","validation"}); tests=load_corpus(a.test_corpus,required_splits={"test-composition","test-hidden-family"}); from agb_gate2b.neutral import validate_corpus; validate_corpus(public+tests,required_splits={"calibration","validation","test-composition","test-hidden-family"}); config=frozen["engine_configuration"]
    engines=[FSMBaseline(config["fsm_budget"]),CEPGraphBaseline(config["cep_budget"]),SlidingWindowBaseline(config["window"]),RiskScoreBaseline()]; engines[-1].threshold=config["risk_threshold"]
    gru=GRUBaseline(hidden_size=config["gru_hidden_size"],device=a.device); torch=gru.torch; payload=torch.load(a.gru_checkpoint,map_location=a.device,weights_only=True); gru.model.load_state_dict(payload["model"]); engines.append(gru)
    baseline_results={split:[evaluate(e,[x for x in tests if x["split"]==split]) for e in engines] for split in frozen["sealed_test_splits"]}
    sys.path.insert(0,str(a.asm_source_root.resolve())); load_model=importlib.import_module("drm_language_emitter.checkpoint").load_model; device=torch.device(a.device); seeds=[]
    for seed,path,sha in sorted(a.checkpoint):
        if digest(path)!=sha: raise RuntimeError(f"checkpoint fingerprint mismatch for seed {seed}")
        raw=torch.load(path,map_location="cpu",weights_only=True); metadata=raw.get("gate2b",{})
        if metadata.get("dataset_sha256")!=dataset_sha or metadata.get("baseline_report_sha256")!=digest(a.baseline_report) or metadata.get("test_seen") is not False: raise RuntimeError(f"checkpoint {seed} is not bound to frozen protocol")
        engine=ASM(load_model(path).to(device).eval(),torch,device); seeds.append({"seed":seed,"checkpoint_sha256":sha,"splits":{split:evaluate(engine,[x for x in tests if x["split"]==split]) for split in frozen["sealed_test_splits"]}})
    report={"benchmark":"unix-agb-gate2b-final-v1","dataset_sha256":dataset_sha,"baseline_report_sha256":digest(a.baseline_report),"baselines":baseline_results,"asm_cm_seeds":seeds,"preregistered_criteria_reference":"docs/gate2b-causal-generalization.md","interpretation":"Criteria must be computed without changing corpus, baselines, checkpoints, or thresholds."}
    chart_prefix=a.chart_prefix or a.output.with_name(a.output.stem+"-comparison"); report["charts"]=plot_report(report,chart_prefix)
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n"); print(json.dumps(report,indent=2,sort_keys=True))
if __name__=="__main__": main()
