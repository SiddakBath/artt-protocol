"""Scientific figures from recorded data; run with the local plotting runtime."""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
run = ROOT / "results/run-2026-10-05"
data = json.loads((run / "results.json").read_text())
fig, axes = plt.subplots(1, 3, figsize=(13.8, 4.3), constrained_layout=True)
labels = ["Unsafe\n(test only)", "v1", "v1b", "v1c\nfixed"]
rows = data["binary"][:4]
ax = axes[0]
bars = ax.bar(labels, [r["recovery_rate"] for r in rows], color=["#8194a5", "#275d87", "#3c8d9d", "#5c916e"], width=.64)
ax.axhline(.5, color="#626262", linestyle="--", linewidth=1, label="Chance (0.5)")
for bar, row in zip(bars, rows):
    ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+.025, f"{row['correct']}/{row['trials']}", ha="center", fontsize=9)
ax.set_ylim(0, 1.14)
ax.set_title("Planted binary secret")
ax.set_ylabel("Recovery fraction")
ax.legend(loc="lower left", fontsize=8, frameon=False)
ax = axes[1]
noise = data["binary"][4:]
xs = [r["noise_probability"] for r in noise]
ys = [r["recovery_rate"] for r in noise]
errs = [[r["recovery_rate"]-r["wilson_95"][0] for r in noise], [r["wilson_95"][1]-r["recovery_rate"] for r in noise]]
ax.errorbar(xs, ys, yerr=errs, fmt="o", color="#275d87", capsize=4, label="Sandbox trials, n=256")
ax.plot([0,.75],[1,.5], color="#8d6b45", linestyle="--", label="One-axis encoding: 1 - 2p/3")
ax.axhline(.5, color="#626262", linewidth=1, linestyle=":")
ax.set_ylim(0.35, 1.04)
ax.set_xlim(-.015,.77)
ax.set_xlabel("Runner flip probability p")
ax.set_title("One noisy release (v1b)")
ax.legend(fontsize=8, frameon=False, loc="upper right")
ax = axes[2]
for p, color in zip((.25,.5,.75), ("#275d87", "#3c8d9d", "#5c916e")):
    rows = [r for r in data["repeated_noise"] if r["flip_probability"] == p]
    ax.plot([r["releases"] for r in rows], [r["recovery_rate"] for r in rows], "o-", color=color, label=f"p={p}")
ax.axhline(.5, color="#626262", linestyle="--", linewidth=1)
ax.set_ylim(.35,1.04)
ax.set_xscale("log")
ax.set_xticks([1,3,9,31], ["1","3","9","31"])
ax.set_xlabel("Releases of the same secret")
ax.set_title("Repeated release: kernel simulation")
ax.legend(fontsize=8, frameon=False)
for ax in axes:
    ax.spines[["top","right"]].set_visible(False)
    ax.tick_params(labelsize=9)
    ax.grid(axis="y", alpha=.15)
fig.suptitle("Fixture-only verdict-channel study: smaller alphabets and noise have distinct limits", fontsize=13)
fig.savefig(run / "leakage.png", dpi=170)
fig.savefig(run / "leakage.svg")
plt.close(fig)
fig, ax = plt.subplots(figsize=(6.2, 3.4), constrained_layout=True)
rows = data["binary"][:4]
bars = ax.bar(labels, [r["recovery_rate"] for r in rows], width=.6,
              color=["#8194a5", "#275d87", "#3c8d9d", "#5c916e"])
for bar, row in zip(bars, rows):
    ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+.025,
            f"{row['correct']}/{row['trials']}", ha="center", fontsize=10)
ax.axhline(.5, color="#626262", linestyle="--", linewidth=1, label="Chance = 0.5")
ax.set_ylim(0, 1.14)
ax.set_ylabel("Binary-secret recovery fraction")
ax.spines[["top", "right"]].set_visible(False)
ax.legend(loc="lower left", frameon=False, fontsize=9)
fig.savefig(run / "binary-leakage.png", dpi=200)
plt.close(fig)
print("Wrote leakage.png, leakage.svg and binary-leakage.png")
