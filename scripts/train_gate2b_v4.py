#!/usr/bin/env python3
"""Train one raw or online-canonical Gate 2B v4 candidate without test access."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import random
import sys,subprocess
import time
from contextlib import nullcontext
from pathlib import Path

from agb_gate2b import load_corpus
from agb_gate2b.diagnostics import canonicalize_entity_ids, distribution


def digest(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def precision(torch, device): return torch.autocast("cuda", dtype=torch.bfloat16) if device.type == "cuda" else nullcontext()
def parse_curriculum(raw: str):
    result=[tuple(map(int,part.split(":"))) for part in raw.split(",")]
    if [x for x,_ in result] != [4,16,64,256,1024] or any(n<=0 for _,n in result): raise ValueError("invalid v4 curriculum")
    return result
def transform(items, representation): return canonicalize_entity_ids(items) if representation == "canonical" else items


def evaluate(torch, model, items, device):
    model.eval(); predictions=[]; labels=[]
    with torch.inference_mode():
        for item in items:
            x=torch.tensor([item["tokens"]],dtype=torch.long,device=device)
            with precision(torch,device): pair=model(x,collect_diagnostics=False)["logits"][:,-1,[2,3]].float()
            predictions.append(bool(pair.argmax(-1).item())); labels.append(item["label"]=="malicious")
    return {"accuracy":sum(a==b for a,b in zip(predictions,labels))/len(items),"count":len(items)}


def main():
    p=argparse.ArgumentParser(); p.add_argument("--corpus",type=Path,required=True); p.add_argument("--baseline-report",type=Path,required=True); p.add_argument("--checkpoint",type=Path,required=True); p.add_argument("--checkpoint-sha256",required=True); p.add_argument("--asm-source-root",type=Path,required=True); p.add_argument("--asm-source-revision",required=True); p.add_argument("--representation",choices=("raw","canonical"),required=True); p.add_argument("--seed",type=int,required=True); p.add_argument("--device",default="cuda"); p.add_argument("--curriculum",default="4:300,16:300,64:400,256:500,1024:500"); p.add_argument("--lr",type=float,default=1e-4); p.add_argument("--report-every",type=int,default=100); p.add_argument("--output-root",type=Path,required=True); a=p.parse_args()
    corpus_sha=digest(a.corpus); baseline=json.loads(a.baseline_report.read_text())
    if baseline.get("dataset_sha256")!=corpus_sha or baseline.get("asm_cm_included") is not False or baseline.get("test_evaluated") is not False: raise RuntimeError("invalid frozen v4 baseline report")
    if digest(a.checkpoint)!=a.checkpoint_sha256: raise RuntimeError("initial checkpoint fingerprint mismatch")
    actual_revision=subprocess.check_output(["git","-C",str(a.asm_source_root),"rev-parse","HEAD"],text=True).strip()
    if actual_revision!=a.asm_source_revision: raise RuntimeError("ASM source revision mismatch")
    sys.path.insert(0,str(a.asm_source_root.resolve())); torch=importlib.import_module("torch"); load_model=importlib.import_module("drm_language_emitter.checkpoint").load_model
    device=torch.device(a.device)
    if device.type=="cuda" and not torch.cuda.is_available(): raise RuntimeError("CUDA requested but unavailable")
    torch.manual_seed(a.seed); rng=random.Random(a.seed); model=load_model(a.checkpoint).to(device)
    items=load_corpus(a.corpus); calibration=transform([x for x in items if x["split"]=="calibration"],a.representation); validation=transform([x for x in items if x["split"]=="validation"],a.representation)
    if len(calibration)+len(validation)!=len(items): raise RuntimeError("v4 trainer received a sealed test split")
    optimizer=torch.optim.AdamW(model.parameters(),lr=a.lr,weight_decay=.01); history=[]; global_step=0; started=time.perf_counter()
    for max_distance,steps in parse_curriculum(a.curriculum):
        by_distance={distance:{label:[x for x in calibration if x["distance"]==distance and (x["label"]=="malicious")==label] for label in (False,True)} for distance in (4,16,64,256,1024) if distance<=max_distance}
        losses=[]
        for _ in range(steps):
            distance=rng.choice(sorted(by_distance)); batch=[rng.choice(by_distance[distance][False]),rng.choice(by_distance[distance][True])]; rng.shuffle(batch)
            x=torch.tensor([item["tokens"] for item in batch],dtype=torch.long,device=device); target=torch.tensor([item["label"]=="malicious" for item in batch],dtype=torch.long,device=device)
            model.train()
            with precision(torch,device): logits=model(x,collect_diagnostics=False)["logits"][:,-1,[2,3]]; loss=torch.nn.functional.cross_entropy(logits.float(),target)
            optimizer.zero_grad(set_to_none=True); loss.backward(); grad=torch.nn.utils.clip_grad_norm_(model.parameters(),1.0,error_if_nonfinite=True); optimizer.step(); global_step+=1; losses.append(float(loss.detach().item()))
            if global_step%a.report_every==0: print(json.dumps({"representation":a.representation,"step":global_step,"max_distance":max_distance,"loss":distribution(losses[-a.report_every:]),"gradient_norm_before_clip":float(grad.detach().item()),"elapsed_sec":time.perf_counter()-started}),flush=True)
        eligible=[x for x in validation if x["distance"]<=max_distance]; metrics=evaluate(torch,model,eligible,device); history.append({"step":global_step,"max_distance":max_distance,"validation":metrics}); print(json.dumps(history[-1]),flush=True)
    a.output_root.mkdir(parents=True,exist_ok=True); candidate=a.output_root/"checkpoint_final.pt"; canonicalizer_sha=digest(Path(__file__).resolve().parents[1]/"python/agb_gate2b/diagnostics.py")
    payload=model.state_dict_with_config(); payload["gate2b_v4"]={"protocol":"gate2b-v4-training-v1","dataset_sha256":corpus_sha,"baseline_report_sha256":digest(a.baseline_report),"asm_source_revision":actual_revision,"representation":a.representation,"canonicalizer_sha256":canonicalizer_sha if a.representation=="canonical" else None,"seed":a.seed,"fit_splits":["calibration"],"test_seen":False}; torch.save(payload,candidate)
    result={**payload["gate2b_v4"],"initial_checkpoint_sha256":a.checkpoint_sha256,"candidate_checkpoint":str(candidate),"candidate_sha256":digest(candidate),"curriculum":parse_curriculum(a.curriculum),"history":history,"final_validation":evaluate(torch,model,validation,device),"elapsed_sec":time.perf_counter()-started,"test_evaluated":False}
    (a.output_root/"training.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result,indent=2,sort_keys=True))
if __name__=="__main__": main()
