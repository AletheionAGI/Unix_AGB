#!/usr/bin/env python3
"""Freeze the v4 checkpoints and the v5 2-of-3 ensemble rule before testing."""
import argparse,hashlib,json
from pathlib import Path
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def spec(raw):
    representation,seed,path,sha=raw.split(":",3); return representation,int(seed),Path(path),sha
def main():
    p=argparse.ArgumentParser(); p.add_argument("--v4-report",type=Path,required=True); p.add_argument("--checkpoint",action="append",type=spec,required=True); p.add_argument("--output",type=Path,required=True); a=p.parse_args()
    expected={(r,s) for r in ("raw","canonical") for s in (1,2,3)}
    if len(a.checkpoint)!=6 or {(r,s) for r,s,_,_ in a.checkpoint}!=expected: p.error("six distinct v4 checkpoints required")
    v4=json.loads(a.v4_report.read_text()); frozen=[]
    for representation,seed,path,sha in sorted(a.checkpoint):
        actual=digest(path)
        if actual!=sha: raise RuntimeError(f"checkpoint mismatch: {representation}/{seed}")
        frozen.append({"representation":representation,"seed":seed,"path":str(path),"sha256":actual})
    result={"protocol":"gate2b-v5-ensemble-freeze-v1","derivation":"Post-hoc response to one isolated v4 seed-3 false positive; v4 verdict remains unchanged.","v4_report_sha256":digest(a.v4_report),"v4_public_dataset_sha256":v4["public_dataset_sha256"],"v4_baseline_report_sha256":v4["baseline_report_sha256"],"asm_source_revision":v4["asm_source_revision"],"canonicalizer_sha256":v4["canonicalization"]["implementation_sha256"],"ensemble":{"representation":"canonical","members":[1,2,3],"deny_votes_required":2,"disagreement_is_telemetry":True},"checkpoints":frozen,"test_evaluated":False}
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result,indent=2,sort_keys=True))
if __name__=="__main__": main()
