"""Standalone scientific figures for exact finite channels and measured kernels."""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/"paper/figures"
OUT.mkdir(exist_ok=True)
plt.rcParams.update({"font.size":10,"axes.spines.top":False,"axes.spines.right":False})
data = json.loads((ROOT/"results/central-frontier-2026-10-05/results.json").read_text())
colors = {0.125:"#005f73",0.25:"#0a9396",0.5:"#ca6702",1.0:"#9b2226"}
fig,axes = plt.subplots(2,2,figsize=(11.5,7.5),constrained_layout=True)
for q,color in colors.items():
    rows = [r for r in data["rows"] if r["q"]==q]
    x = [r["filings"] for r in rows]
    label = f"q = {q:g}"
    axes[0,0].plot(x,[100*r["worst_case_answer_recovery"] for r in rows],"o-",color=color,label=label)
    axes[0,1].plot(x,[r["epsilon_per_answer_total"] for r in rows],"o-",color=color)
    axes[1,0].plot(x,[r["mean_mse_at_mean_half"]**0.5 for r in rows],"o-",color=color)
    fixed = [r for r in data["fixed_total_epsilon"] if r["q"]==q]
    axes[1,1].plot([r["filings"] for r in fixed],[r["worst_case_mean_mse"]**0.5 for r in fixed],"o-",color=color)
axes[0,0].set(title="Optimal recovery of one neighboring answer",ylabel="Equal-prior recovery (%)",ylim=(48,102))
axes[0,0].legend(frameon=False,ncol=2)
axes[0,1].set(title="Privacy cost accumulates across filings",ylabel="Cumulative epsilon per answer")
axes[0,1].axhline(1,color="#555555",linestyle="--",linewidth=1)
axes[0,1].text(0.97,0.09,"illustrative total budget = 1",transform=axes[0,1].transAxes,ha="right",fontsize=8,color="#555555")
axes[1,0].set(title="Utility improves when more budget is spent",ylabel="RMSE of mean (n=32, true mean=0.5)",yscale="log")
axes[1,1].set(title="A fixed total epsilon changes the comparison",ylabel="Worst-case mean RMSE (n=32)",yscale="log")
for ax in axes.flat:
    ax.set_xscale("log")
    ax.set_xticks((1,3,9,31),labels=("1","3","9","31"))
    ax.set_xlabel("Independent accepted filings")
    ax.grid(alpha=0.2)
fig.suptitle("Hidden sampling + geometric count noise: an exact, scoped tradeoff",fontsize=14)
fig.savefig(OUT/"privacy-utility-filings.png",dpi=180)
fig.savefig(OUT/"privacy-utility-filings.svg")
plt.close(fig)

path = ROOT/"results/qwen-behavior-2026-10-05/results.json"
if path.exists():
    model = json.loads(path.read_text())
    rows = model["rows"]
    fig,ax = plt.subplots(figsize=(6,5.5),constrained_layout=True)
    for q,color in colors.items():
        part = [r for r in rows if r["q"]==q]
        ax.errorbar([r["predicted_mse"] for r in part],[r["observed_mse"] for r in part],
                    yerr=[2*r["monte_carlo_standard_error"] for r in part],fmt="o",capsize=3,color=color,label=f"q={q:g}")
    low = min(r["predicted_mse"] for r in rows)*0.7
    high = max(r["predicted_mse"] for r in rows)*1.3
    ax.plot([low,high],[low,high],"--",color="#777777",linewidth=1)
    ax.set(xscale="log",yscale="log",xlim=(low,high),ylim=(low,high),xlabel="Exact predicted MSE",ylabel="Measured kernel MSE (±2 MC standard errors)",
           title=f"Qwen3-0.6B: 64 registered arithmetic responses\n{model['correct_primary']}/64 first-token answers correct; 4096 replications/point")
    ax.legend(frameon=False)
    ax.grid(alpha=0.2)
    fig.savefig(OUT/"qwen-utility-check.png",dpi=180)
    fig.savefig(OUT/"qwen-utility-check.svg")
    plt.close(fig)
print("Saved standalone scientific figures")
