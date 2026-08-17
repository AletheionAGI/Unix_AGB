#!/usr/bin/env python3
"""Plot frozen baselines against raw and canonical three-seed ASM-CM."""
from __future__ import annotations
import json,os
from pathlib import Path

def curves(seeds,split,distances): return [[100*seed["splits"][split]["accuracy_by_distance"][str(distance)] for distance in distances] for seed in seeds]
def summary(rows): return ([sum(row[i] for row in rows)/len(rows) for i in range(len(rows[0]))],[min(row[i] for row in rows) for i in range(len(rows[0]))],[max(row[i] for row in rows) for i in range(len(rows[0]))])
def plot_report(report,output_prefix:Path):
    os.environ.setdefault("MPLCONFIGDIR",str((output_prefix.parent/".matplotlib").resolve())); import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    distances=[4,16,64,256,1024]; splits=("test-composition","test-hidden-family"); titles=("Composição inédita","Família completamente oculta"); figure,axes=plt.subplots(1,2,figsize=(14,6.5),sharey=True)
    for axis,split,title in zip(axes,splits,titles):
        for result in report["baselines"][split]: axis.plot(distances,[100*result["accuracy_by_distance"][str(d)] for d in distances],linewidth=1.2,alpha=.55,label=result["engine"])
        for seeds,color,label,marker in ((report["raw_asm_seeds"],"#dc2626","ASM-CM raw","o"),(report["canonical_asm_seeds"],"#2563eb","ASM-CM canônico","D")):
            mean,low,high=summary(curves(seeds,split,distances)); axis.fill_between(distances,low,high,color=color,alpha=.12); axis.plot(distances,mean,color=color,marker=marker,linewidth=2.8,label=label)
        axis.set_xscale("log",base=2); axis.set_xticks(distances,[str(x) for x in distances]); axis.set_ylim(0,102); axis.grid(True,alpha=.25); axis.set_title(title); axis.set_xlabel("Distância causal")
    axes[0].set_ylabel("Accuracy (%)"); handles,labels=axes[1].get_legend_handles_labels(); figure.legend(handles,labels,loc="lower center",bbox_to_anchor=(.5,.02),ncol=4,frameon=False); figure.suptitle("Unix-AGB Gate 2B v4 — IDs crus versus canônicos",fontweight="bold"); figure.tight_layout(rect=(0,.17,1,.94)); output_prefix.parent.mkdir(parents=True,exist_ok=True); png=output_prefix.with_suffix(".png"); svg=output_prefix.with_suffix(".svg"); figure.savefig(png,dpi=180,bbox_inches="tight"); figure.savefig(svg,bbox_inches="tight"); plt.close(figure); return [str(png.resolve()),str(svg.resolve())]
def main():
    import argparse; p=argparse.ArgumentParser(); p.add_argument("--report",type=Path,required=True); p.add_argument("--output-prefix",type=Path,required=True); a=p.parse_args(); print(json.dumps({"charts":plot_report(json.loads(a.report.read_text()),a.output_prefix)},indent=2))
if __name__=="__main__": main()
