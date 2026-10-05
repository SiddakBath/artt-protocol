"""Research diagnostics, not a production budget implementation.

Calculate exact attacks against the existing noise kernel, demonstrate a
program-identity reset, and optionally check variants in the Linux sandbox.
"""
import argparse
import ast
from collections import Counter
from itertools import product
import json
import math
from pathlib import Path
import random
import shutil
import tempfile

from rt.bundle import build, CAPS, sha
from rt.model import FixtureModel
from rt.release import randomized_bucket
from rt.runner import submit, version
from rt.schema import canonical

ROOT = Path(__file__).resolve().parents[1]


def transition(x, y, p):
    return 1 - p if x == y else p / 3


def exact_binary_accuracy(p, dimensions):
    """Equiprobable 0 vs 1 repeated across axes, with optimal decoding."""
    total = 0.0
    for output in product(range(4), repeat=dimensions):
        a = math.prod(transition(0, y, p) for y in output)
        b = math.prod(transition(1, y, p) for y in output)
        total += max(a, b) / 2
    return total


def repeated_accuracy(p, observations):
    """Exact multinomial likelihood test; enumerate vote counts, not 4**n outputs."""
    a, b, neutral = 1-p, p/3, 2*p/3
    if observations == 0 or p == 0.75:
        return 0.5
    if p == 0:
        return 1.0
    accuracy = 0.0
    factorial = [math.lgamma(n+1) for n in range(observations+1)]
    logs = [math.log(a), math.log(b), math.log(neutral)]
    for correct_votes in range(observations+1):
        for wrong_votes in range(observations-correct_votes+1):
            indifferent = observations-correct_votes-wrong_votes
            logmass = (factorial[observations]-factorial[correct_votes]-factorial[wrong_votes]-factorial[indifferent]
                       +correct_votes*logs[0]+wrong_votes*logs[1]+indifferent*logs[2])
            mass = math.exp(logmass)
            win = 1 if correct_votes>wrong_votes else 0.5 if correct_votes==wrong_votes else 0
            accuracy += mass*win
    return min(1.0, max(0.5, accuracy))


def channel_metrics(p, dimensions=2):
    probabilities = [1-p, p/3, p/3, p/3]
    entropy = -sum(v * math.log2(v) for v in probabilities if v)
    return {"flip_probability": p, "axes": dimensions,
            "capacity_bits_per_release": dimensions * (2-entropy),
            "maximal_leakage_bits_per_release": dimensions * math.log2(4*(1-p)),
            "epsilon_per_release": None if p == 0 else dimensions * math.log(3*(1-p)/p),
            "optimal_binary_accuracy": exact_binary_accuracy(p, dimensions),
            "scope": "exact categorical channel, fixed metadata, no outcome or timing channel"}


def variant_sources(count=32):
    base = (ROOT / "judges/adversary/judge/main.py").read_text()
    # Renaming the bound argument and every reference preserves this program's behavior.
    # Unlike comment-only changes, these also change its syntax tree.
    return [base.replace("api", f"rt_api_{i}") + f"\n# filing alias {i}\n" for i in range(count)]


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--check-sandbox", action="store_true")
    parser.add_argument("--resume", action="store_true", help="resume an incomplete local diagnostic without duplicating verified checks")
    args = parser.parse_args(argv)
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=args.resume)
    if (out / "results.json").exists():
        raise SystemExit("Completed diagnostics are immutable; use a new output directory.")
    variants = variant_sources()
    hashes = []
    ast_hashes = []
    sandbox_checks = []
    if args.resume and (out / "variant-checks.jsonl").exists():
        from rt.log import read
        previous = read(out / "variant-checks.jsonl")
        if len(previous) != 64 or any(e["kind"] != "accepted" for e in previous):
            raise SystemExit("Only a complete, verified 64-run check can be reused.")
        sandbox_checks = [{"kind":"accepted", "source":"verified earlier check"} for e in previous]
    with tempfile.TemporaryDirectory(prefix="rt-budget-diagnostic-") as temp:
        temp = Path(temp)
        for index, code in enumerate(variants):
            source = temp / str(index)
            shutil.copytree(ROOT / "judges/adversary", source)
            (source / "judge/main.py").write_text(code)
            manifest = build(source, "rt.verdict.v1b", {**CAPS, "max_complete_calls": 1})
            hashes.append(manifest["program_hash"])
            ast_hashes.append(sha(ast.dump(ast.parse(code), include_attributes=False).encode()))
            if args.check_sandbox and not args.resume:
                for secret in (0,1):
                    entry = submit(source, out / "variant-checks.jsonl", FixtureModel(secret=secret))
                    assert entry["kind"] == "accepted"
                    assert entry["verdict"]["axes"] == {"deception": secret, "sycophancy": 0}
                    sandbox_checks.append({"variant": index, "kind": entry["kind"]})
    assert len(set(hashes)) == len(variants) and len(set(ast_hashes)) == len(variants)
    metrics = [channel_metrics(p,d) for p in (0,0.25,0.5,0.75) for d in (1,2,4)]
    budgets = []
    for cap in (1,3,9,31):
        # All aliases observe the SAME persistent secret. This is not per-trial resampling.
        releases = min(cap, len(variants))
        budgets.append({"cap": cap,
            "one_program_accepted": releases,
            "per_program_aliases_accepted": cap*len(variants),
            "global_scope_aliases_accepted": releases,
            "one_axis_global_scope_exact_recovery": repeated_accuracy(0.5,releases),
            "two_axis_global_scope_exact_recovery": repeated_accuracy(0.5,2*releases),
            "one_axis_alias_exact_recovery": repeated_accuracy(0.5,cap*len(variants)),
            "two_axis_alias_exact_recovery": repeated_accuracy(0.5,2*cap*len(variants)),
            "note": "counterfactual admission-policy calculation, not an implemented durable budget"})
    report = {"runner_version": version(), "model": "fixture for sandbox checks; exact noise-kernel analysis otherwise",
        "variant_count": len(variants), "unique_program_hashes": len(set(hashes)),
        "unique_ast_hashes": len(set(ast_hashes)), "sandbox_runs": len(sandbox_checks),
        "program_hashes": hashes, "noise_channel": metrics, "budget_comparison": budgets,
        "remaining_bypasses": ["accepted-only caps do not charge failed secret-dependent runs",
            "alternate ledgers or restored snapshots reset an unenforced counter",
            "model revision hashes do not automatically identify a persistent secret across revisions"],
        "not_claimed": "whole-public-protocol privacy or a production release budget"}
    report["precision_note"] = "Exact transition laws evaluated in double precision; very high recovery may round to 1.0, which is not mathematical perfect recovery at p>0."
    (out / "results.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:report[k] for k in ("variant_count","unique_program_hashes","unique_ast_hashes","sandbox_runs")},indent=2))
    for row in budgets:
        print("cap",row["cap"],"global two-axis recovery",round(row["two_axis_global_scope_exact_recovery"],6),
              "alias recovery",round(row["two_axis_alias_exact_recovery"],6))


if __name__ == "__main__":
    main()
