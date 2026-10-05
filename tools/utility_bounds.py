"""Post-run, finite-sample utility bounds for the frozen categorical study.

The target is the realized effective predicate mean, including fallback zeros.
Raw predicates must be selected before each fresh release coin. They may depend
on earlier noise. This is not a conditional guarantee given the entire realized
predicate trajectory, and it does not repair physical timing privacy.
"""
import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path

from rt.scheduled_log import read

ROOT = Path(__file__).resolve().parents[1]
STUDY = ROOT / "results/qwen-scheduled-utility-2026-10-05"


def kernel_moments(bit):
    if type(bit) is not int or bit not in (0, 1):
        raise ValueError("binary_predicate_required")
    masses = [Fraction(1, 2) if value == 3*bit else Fraction(1, 6) for value in range(4)]
    mean = sum(value*mass for value, mass in enumerate(masses))
    variance = sum((value-mean)**2*mass for value, mass in enumerate(masses))
    return mean, variance


def radius(weights, delta=0.05):
    """Two-sided Hoeffding radius; per-increment conditional range is 3|w|."""
    if not weights or not 0 < delta < 1 or any(not math.isfinite(w) for w in weights):
        raise ValueError("invalid_confidence_parameters")
    return math.sqrt(0.5*sum((3*w)**2 for w in weights)*math.log(2/delta))


def analyze(study=STUDY):
    entries = read(study / "honest-5.jsonl")
    report = json.loads((study / "results.json").read_text())
    n = len(entries)
    if n != 256 or any(entry["kind"] != "released" or entry["policy"]["flip_probability"] != 0.5 for entry in entries):
        raise ValueError("unexpected_registered_honest_release")
    means = {}
    for axis in ("deception", "sycophancy"):
        estimate = sum(entry["verdict"]["axes"][axis] for entry in entries)/n-1
        retained = report["honest_utility"]["predicates"][axis]
        if estimate != retained["public_mean_estimate"]:
            raise ValueError("retained_utility_estimate_mismatch")
        half_width = radius([1/n]*n)
        means[axis] = {"public_estimate": estimate, "radius": half_width,
            "pointwise_95_effective_mean_interval": [estimate-half_width, estimate+half_width],
            "retained_effective_mean": retained["effective_mean_including_fallbacks"],
            "retained_raw_response_mean": retained["private_ground_truth_mean"],
            "target": "effective predicate mean including defaults; raw response mean can have fallback bias"}
    groups = [[entry for entry in entries if int(entry["item_id"].rsplit("-", 1)[1]) % 2 == group] for group in (0, 1)]
    sizes = list(map(len, groups))
    if sizes != [128, 128]:
        raise ValueError("unexpected_public_probe_groups")
    estimates = [sum(entry["verdict"]["axes"]["deception"] for entry in group)/len(group)-1 for group in groups]
    contrast = estimates[0]-estimates[1]
    half_width = radius([1/sizes[0]]*sizes[0]+[-1/sizes[1]]*sizes[1])
    return {"scope": "post-run finite-sample analysis of the retained honest records; no new model or judge runs",
        "assumptions": "raw 0/3 predicate or fallback selected before its fresh trusted p=1/2 noise; public groups and sample size fixed; predictable raw bits may depend on prior releases",
        "coverage": "pointwise two-sided 95% Hoeffding martingale bound over fresh release noise; not a normal approximation or a confidence claim conditional on a selected full raw trajectory",
        "multiplicity": "each displayed interval is pointwise; exploratory group contrast was not a primary registered endpoint; no simultaneous coverage claim",
        "proof": "conditional centered increment V-1-B has zero mean, variance 4/3, range width 3; iterated conditional Hoeffding mgfs and Markov give 2 exp(-2 t^2/sum(9 w_i^2))",
        "same_256_records": True, "failures_excluded": False, "means": means,
        "public_group_sizes": sizes, "public_group_estimates": estimates,
        "exploratory_format_contrast": contrast, "contrast_radius": half_width,
        "pointwise_95_effective_contrast_interval": [contrast-half_width, contrast+half_width],
        "honest_chain_sha256": hashlib.sha256((study / "honest-5.jsonl").read_bytes()).hexdigest(),
        "retained_report_sha256": hashlib.sha256((study / "results.json").read_bytes()).hexdigest(),
        "raw_contexts_or_transcripts_reconstructed": False}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    path = Path(args.output)
    report = analyze()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2, allow_nan=False)+"\n")
    print(json.dumps({"means": report["means"], "contrast_interval": report["pointwise_95_effective_contrast_interval"]}, indent=2))


if __name__ == "__main__":
    main()
