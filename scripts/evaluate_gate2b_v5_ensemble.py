#!/usr/bin/env python3
"""Evaluate the pre-frozen canonical ensemble on a fresh physical test."""
from __future__ import annotations
import argparse,hashlib,importlib,json,sys,time,subprocess
from contextlib import nullcontext
from pathlib import Path
from agb_gate2b import load_corpus
from agb_gate2b.baselines import CEPGraphBaseline,FSMBaseline,GRUBaseline,RiskScoreBaseline,SlidingWindowBaseline
from agb_gate2b.diagnostics import canonicalize_entity_ids,distribution
from benchmark_gate2b import evaluate
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def metrics(items,predictions,name):
    def one(subset):
        selected=[(item,predictions[item["trajectory_id"]]) for item in subset]; tp=sum(p and i["label"]=="malicious" for i,p in selected); tn=sum(not p and i["label"]=="benign" for i,p in selected); fp=sum(p and i["label"]=="benign" for i,p in selected); fn=sum(not p and i["label"]=="malicious" for i,p in selected); return {"accuracy":(tp+tn)/len(selected),"false_positive_rate":fp/(fp+tn),"recall":tp/(tp+fn),"precision":tp/(tp+fp) if tp+fp else 0.0,"confusion":{"tp":tp,"tn":tn,"fp":fp,"fn":fn}}
    overall=one(items); overall["engine"]=name; overall["accuracy_by_distance"]={str(d):one([x for x in items if x["distance"]==d])["accuracy"] for d in (4,16,64,256,1024)}; return overall
def fpr(result):
    c=result["confusion"]; return c["fp"]/(c["fp"]+c["tn"])
def render(report,output):
    import os; os.environ.setdefault("MPLCONFIGDIR",str((output.parent/".matplotlib").resolve())); import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    distances=(4,16,64,256,1024); splits=("test-composition","test-hidden-family"); titles=("Composição inédita","Família completamente oculta"); fig,axes=plt.subplots(1,2,figsize=(14,6.5),sharey=True)
    for axis,split,title in zip(axes,splits,titles):
        for baseline in report["baselines"][split]: axis.plot(distances,[100*baseline["accuracy_by_distance"][str(d)] for d in distances],linewidth=1.2,alpha=.5,label=baseline["engine"])
        rows=[[100*seed[split]["accuracy_by_distance"][str(d)] for d in distances] for seed in report["individual_seeds"].values()]; mean=[sum(row[i] for row in rows)/len(rows) for i in range(len(distances))]; low=[min(row[i] for row in rows) for i in range(len(distances))]; high=[max(row[i] for row in rows) for i in range(len(distances))]
        axis.fill_between(distances,low,high,color="#f59e0b",alpha=.18,label="Faixa 3 seeds"); axis.plot(distances,mean,color="#f59e0b",marker="o",linewidth=2.5,label="Média seeds canônicos")
        axis.plot(distances,[100*report["ensemble"][split]["accuracy_by_distance"][str(d)] for d in distances],color="#16a34a",marker="D",linewidth=3,label="Ensemble 2-de-3")
        axis.set_xscale("log",base=2); axis.set_xticks(distances,[str(d) for d in distances]); axis.set_ylim(0,102); axis.grid(True,alpha=.25); axis.set_title(title); axis.set_xlabel("Distância causal")
    axes[0].set_ylabel("Accuracy (%)"); handles,labels=axes[1].get_legend_handles_labels(); fig.legend(handles,labels,loc="lower center",bbox_to_anchor=(.5,.02),ncol=4,frameon=False); fig.suptitle("Unix-AGB Gate 2B v5 — ensemble canônico versus baselines",fontweight="bold"); fig.tight_layout(rect=(0,.19,1,.94)); fig.savefig(output,dpi=180,bbox_inches="tight"); plt.close(fig)
def main():
    p=argparse.ArgumentParser(); p.add_argument("--freeze",type=Path,required=True); p.add_argument("--v4-corpus",type=Path,required=True); p.add_argument("--v4-baseline-report",type=Path,required=True); p.add_argument("--v4-gru-checkpoint",type=Path,required=True); p.add_argument("--fresh-test",type=Path,required=True); p.add_argument("--fresh-manifest",type=Path,required=True); p.add_argument("--asm-source-root",type=Path,required=True); p.add_argument("--device",default="cuda"); p.add_argument("--output",type=Path,required=True); a=p.parse_args()
    freeze=json.loads(a.freeze.read_text()); baseline=json.loads(a.v4_baseline_report.read_text()); manifest=json.loads(a.fresh_manifest.read_text())
    if freeze["test_evaluated"] is not False or freeze["v4_public_dataset_sha256"]!=digest(a.v4_corpus) or freeze["v4_baseline_report_sha256"]!=digest(a.v4_baseline_report) or manifest["sealed_test_sha256"]!=digest(a.fresh_test) or baseline["gru_checkpoint_sha256"]!=digest(a.v4_gru_checkpoint): raise RuntimeError("v5 freeze or dataset mismatch")
    if subprocess.check_output(["git","-C",str(a.asm_source_root),"rev-parse","HEAD"],text=True).strip()!=freeze["asm_source_revision"]: raise RuntimeError("ASM source revision mismatch")
    raw=load_corpus(a.fresh_test,required_splits={"test-composition","test-hidden-family"}); canonical=canonicalize_entity_ids(raw); config=baseline["engine_configuration"]
    engines=[FSMBaseline(config["fsm_budget"]),CEPGraphBaseline(config["cep_budget"]),SlidingWindowBaseline(config["window"]),RiskScoreBaseline()]; engines[-1].threshold=config["risk_threshold"]; gru=GRUBaseline(hidden_size=config["gru_hidden_size"],device=a.device); torch=gru.torch; payload=torch.load(a.v4_gru_checkpoint,map_location=a.device,weights_only=True); gru.model.load_state_dict(payload["model"]); engines.append(gru)
    splits=("test-composition","test-hidden-family"); baselines={split:[evaluate(e,[x for x in raw if x["split"]==split]) for e in engines] for split in splits}
    sys.path.insert(0,str(a.asm_source_root.resolve())); load_model=importlib.import_module("drm_language_emitter.checkpoint").load_model; device=torch.device(a.device); members={}; latency={}
    for entry in freeze["checkpoints"]:
        if entry["representation"]!="canonical": continue
        path=Path(entry["path"])
        if digest(path)!=entry["sha256"]: raise RuntimeError("frozen checkpoint changed")
        model=load_model(path).to(device).eval(); predictions={}; durations=[]
        with torch.inference_mode():
            for item in canonical:
                x=torch.tensor([item["tokens"]],device=device); started=time.perf_counter_ns()
                with (torch.autocast("cuda",dtype=torch.bfloat16) if device.type=="cuda" else nullcontext()): pair=model(x,collect_diagnostics=False)["logits"][:,-1,[2,3]]
                durations.append((time.perf_counter_ns()-started)/1000); predictions[item["trajectory_id"]]=bool(pair.argmax(-1).item())
        members[entry["seed"]]=predictions; latency[str(entry["seed"])]=distribution(durations)
    ensemble={}; disagreements={};
    for item in canonical:
        votes=[members[s][item["trajectory_id"]] for s in (1,2,3)]; ensemble[item["trajectory_id"]]=sum(votes)>=2; disagreements[item["trajectory_id"]]=len(set(votes))>1
    individual={str(seed):{split:metrics([x for x in canonical if x["split"]==split],predictions,f"canonical-seed-{seed}") for split in splits} for seed,predictions in members.items()}; ensemble_results={split:metrics([x for x in canonical if x["split"]==split],ensemble,"canonical-ensemble-2of3") for split in splits}
    disagreement_report={split:{"count":sum(disagreements[x["trajectory_id"]] for x in canonical if x["split"]==split),"rate":sum(disagreements[x["trajectory_id"]] for x in canonical if x["split"]==split)/sum(x["split"]==split for x in canonical)} for split in splits}
    checks=[]
    for split in splits:
        for distance in (256,1024): checks.append(ensemble_results[split]["accuracy_by_distance"][str(distance)]>=max(x["accuracy_by_distance"][str(distance)] for x in baselines[split])+.05)
    checks.append(ensemble_results["test-hidden-family"]["accuracy"]>=max(x["accuracy"] for x in baselines["test-hidden-family"])+.05)
    for split in splits:
        best=max(x["accuracy"] for x in baselines[split]); best_fpr=min(fpr(x) for x in baselines[split] if x["accuracy"]==best); checks.append(fpr(ensemble_results[split])<=best_fpr+.01)
    report={"benchmark":"unix-agb-gate2b-v5-canonical-ensemble-v1","freeze_sha256":digest(a.freeze),"fresh_test_sha256":digest(a.fresh_test),"ensemble_rule":freeze["ensemble"],"baselines":baselines,"individual_seeds":individual,"ensemble":ensemble_results,"disagreement":disagreement_report,"member_latency_us":latency,"criteria":{"checks":checks,"supported":all(checks)},"test_evaluated":True,"limitations":"Post-hoc ensemble mechanism confirmed on a fresh split from the same synthetic generator family."}; a.output.parent.mkdir(parents=True,exist_ok=True); chart=a.output.with_suffix(".png"); report["chart"]=str(chart.resolve()); render(report,chart); a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n"); print(json.dumps(report,indent=2,sort_keys=True))
if __name__=="__main__": main()
