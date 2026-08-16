#!/usr/bin/env python3
"""Fine-tune ASM-CM on calibration-only neutral Gate 2B trajectories."""
from __future__ import annotations

import argparse, hashlib, importlib, json, random, sys, time
from contextlib import nullcontext
from pathlib import Path

from agb_gate2b import load_corpus


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def precision(torch, device):
    return torch.autocast("cuda", dtype=torch.bfloat16) if device.type == "cuda" else nullcontext()


def evaluate(torch, model, items, device):
    model.eval(); correct = 0; by_distance = {}
    with torch.inference_mode():
        for item in items:
            x=torch.tensor([item["tokens"]],dtype=torch.long,device=device)
            with precision(torch,device): logits=model(x,collect_diagnostics=False)["logits"][:,-1]
            predicted=int(logits[:,[2,3]].argmax(-1).item())
            correct += predicted == (item["label"] == "malicious")
        for distance in sorted({x["distance"] for x in items}):
            subset=[x for x in items if x["distance"]==distance]; hits=0
            for item in subset:
                x=torch.tensor([item["tokens"]],dtype=torch.long,device=device)
                with precision(torch,device): logits=model(x,collect_diagnostics=False)["logits"][:,-1]
                hits += int(logits[:,[2,3]].argmax(-1).item()) == (item["label"]=="malicious")
            by_distance[str(distance)]=hits/len(subset)
    return {"accuracy":correct/len(items),"accuracy_by_distance":by_distance,"count":len(items)}


def parse_curriculum(raw):
    result=[]
    for part in raw.split(","):
        distance,steps=map(int,part.split(":")); result.append((distance,steps))
    if [x for x,_ in result] != [4,16,64,256,1024] or any(x<=0 for _,x in result):
        raise ValueError("curriculum must contain positive steps for 4,16,64,256,1024")
    return result


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--corpus",type=Path,required=True); parser.add_argument("--baseline-report",type=Path,required=True); parser.add_argument("--checkpoint",type=Path,required=True); parser.add_argument("--checkpoint-sha256",required=True); parser.add_argument("--asm-source-root",type=Path,required=True); parser.add_argument("--seed",type=int,required=True); parser.add_argument("--device",default="cuda"); parser.add_argument("--curriculum",default="4:300,16:300,64:400,256:500,1024:500"); parser.add_argument("--lr",type=float,default=1e-5); parser.add_argument("--output-root",type=Path,required=True); args=parser.parse_args()
    baseline=json.loads(args.baseline_report.read_text()); corpus_digest=sha256(args.corpus)
    if baseline.get("dataset_sha256") != corpus_digest or baseline.get("asm_cm_included") is not False:
        raise RuntimeError("frozen baseline report is missing or belongs to another corpus")
    if sha256(args.checkpoint) != args.checkpoint_sha256: raise RuntimeError("initial checkpoint fingerprint mismatch")
    sys.path.insert(0,str(args.asm_source_root.resolve())); torch=importlib.import_module("torch"); load_model=importlib.import_module("drm_language_emitter.checkpoint").load_model
    device=torch.device(args.device)
    if device.type=="cuda" and not torch.cuda.is_available(): raise RuntimeError("CUDA requested but unavailable")
    torch.manual_seed(args.seed); randomizer=random.Random(args.seed)
    model=load_model(args.checkpoint).to(device)
    if model.config.vocab_size < 256: raise RuntimeError("ASM checkpoint vocabulary cannot represent neutral uint8 tokens")
    items=load_corpus(args.corpus); calibration=[x for x in items if x["split"]=="calibration"]; validation=[x for x in items if x["split"]=="validation"]
    if len(calibration)+len(validation) != len(items): raise RuntimeError("trainer received a sealed test split")
    optimizer=torch.optim.AdamW(model.parameters(),lr=args.lr,weight_decay=0.01); history=[]; global_step=0; started=time.perf_counter()
    for max_distance,steps in parse_curriculum(args.curriculum):
        eligible=[x for x in calibration if x["distance"]<=max_distance]
        model.train()
        for _ in range(steps):
            item=randomizer.choice(eligible); x=torch.tensor([item["tokens"]],dtype=torch.long,device=device); target=torch.tensor([3 if item["label"]=="malicious" else 2],device=device)
            with precision(torch,device): logits=model(x,collect_diagnostics=False)["logits"][:,-1]; loss=torch.nn.functional.cross_entropy(logits.float(),target)
            optimizer.zero_grad(set_to_none=True); loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(),1.0,error_if_nonfinite=True); optimizer.step(); global_step+=1
            if global_step==1 or global_step%100==0: print(json.dumps({"step":global_step,"max_distance":max_distance,"loss":float(loss.detach()),"elapsed_sec":time.perf_counter()-started}),flush=True)
        metrics=evaluate(torch,model,[x for x in validation if x["distance"]<=max_distance],device); history.append({"step":global_step,"max_distance":max_distance,"validation":metrics}); print(json.dumps(history[-1]),flush=True)
    args.output_root.mkdir(parents=True,exist_ok=True); candidate=args.output_root/"checkpoint_final.pt"; payload=model.state_dict_with_config(); payload["gate2b"]={"protocol":"gate2b-neutral-v1","dataset_sha256":corpus_digest,"baseline_report_sha256":sha256(args.baseline_report),"seed":args.seed,"fit_splits":["calibration"],"test_seen":False}; torch.save(payload,candidate)
    result={"protocol":"gate2b-neutral-asm-training-v1","seed":args.seed,"initial_checkpoint_sha256":args.checkpoint_sha256,"candidate_checkpoint":str(candidate),"candidate_sha256":sha256(candidate),"dataset_sha256":corpus_digest,"baseline_report_sha256":sha256(args.baseline_report),"curriculum":parse_curriculum(args.curriculum),"history":history,"final_validation":evaluate(torch,model,validation,device),"test_evaluated":False,"elapsed_sec":time.perf_counter()-started}
    (args.output_root/"training.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result,indent=2,sort_keys=True))
if __name__=="__main__": main()
