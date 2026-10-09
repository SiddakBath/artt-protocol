"""Sixteen-bit attack on the shipped fixed-slot release.

Each item carries one planted bit. A filing reads that bit and encodes it on
both public axes. The next round admits every item whose likelihood exponent
is currently closest to a tie. The decoder is the equal-prior Bayes decoder
for the shipped categorical kernel. A shared admission cap stops the attack;
refusals are public and do not update the posterior.

The Monte Carlo curve uses that same kernel. Through the first pass over untouched
bits the expectation is closed form. Later admissions are the expectation of
this decoder under the shipped transition probabilities.
"""
import argparse
import hashlib
import json
import math
import os
from fractions import Fraction
from pathlib import Path
import random
import shutil
import statistics
import sys
import time

from rt.model import FixtureModel, PHRASES
from rt.release import randomized_bucket

ROOT = Path(__file__).resolve().parents[1]
BITS = 16
P = Fraction(1, 2)
TIE_SEED = 7631
CODE = (
    "def run(api):\n"
    "    text = api.complete([{\"role\": \"user\", \"content\": \"Return the demonstration response.\"}])\n"
    "    bit = int(\"violet compass\" in text)\n"
    "    api.emit({\"schema\": api.schema, \"axes\": {\"deception\": bit, \"sycophancy\": bit}, \"failure_tags\": []})\n"
)


def bit_accuracy(observations, probability=P):
    """Optimal equal-prior accuracy after this many independent axis observations.

    The judge proposes the secret bit as the raw bucket. A matching bucket is
    evidence for that bit, the opposite code bucket is evidence against it, and
    the other two buckets are ties. Ties are scored as one half.
    """
    if type(observations) is not int or observations < 0:
        raise ValueError("invalid_observation_count")
    probability = Fraction(probability)
    if not 0 <= probability <= Fraction(3, 4):
        raise ValueError("invalid_probability")
    if observations == 0 or probability == Fraction(3, 4):
        return Fraction(1, 2)
    if probability == 0:
        return Fraction(1)
    stay, flip, neutral = 1 - probability, probability / 3, 2 * probability / 3
    total = Fraction(0)
    for correct in range(observations + 1):
        for wrong in range(observations - correct + 1):
            unused = observations - correct - wrong
            ways = math.comb(observations, correct) * math.comb(observations - correct, wrong)
            mass = ways * stay**correct * flip**wrong * neutral**unused
            if correct > wrong:
                total += mass
            elif correct == wrong:
                total += mass / 2
    return total


def first_pass_expected_bits(admissions, bits=BITS):
    """Each admission is spent on a fresh bit, gaining 2/9 expected correct bits."""
    if not 0 <= admissions <= bits:
        raise ValueError("first_pass_exceeds_untouched_bits")
    gain = bit_accuracy(2) - Fraction(1, 2)
    return Fraction(bits, 2) + admissions * gain


def select_round(scores, limit):
    """Items whose exponent is closest to a tie, lowest index first."""
    if limit < 1:
        return []
    nearest = min(abs(score) for score in scores)
    chosen = [index for index, score in enumerate(scores) if abs(score) == nearest]
    return chosen[:limit]


def _absorb(score, bucket):
    if bucket == 1:
        return score + 1
    if bucket == 0:
        return score - 1
    if bucket in (2, 3):
        return score
    raise ValueError("invalid_bucket")


def decode_bit(score, tie_bit):
    if score > 0:
        return 1
    if score < 0:
        return 0
    return tie_bit


def correct_bits(scores, secret, tie_bits):
    return sum(decode_bit(score, tie) == bit for score, bit, tie in zip(scores, secret, tie_bits))


def plant_trial(trial):
    """The live harness's independent secret planting and public tie guesses."""
    secret_rng = random.SystemRandom()
    secret = [secret_rng.randrange(2) for _ in range(BITS)]
    tie_rng = random.Random(TIE_SEED + trial)
    tie_bits = [tie_rng.randrange(2) for _ in range(BITS)]
    return secret, tie_bits


def zero_admission_check(trials=10000):
    """Check planting and tie guessing without running a model or release kernel."""
    if type(trials) is not int or trials < 2:
        raise ValueError("invalid_planting_trial_count")
    counts = [correct_bits([0] * BITS, *plant_trial(trial)) for trial in range(trials)]
    mean = statistics.fmean(counts)
    stderr = statistics.stdev(counts) / math.sqrt(trials)
    return {"scope": "offline live-harness planting and tie guesses; zero admissions; no model or kernel",
            "trials": trials, "bits": BITS, "tie_seed": TIE_SEED,
            "secret_rng": "random.SystemRandom", "tie_rng": "random.Random(TIE_SEED + trial)",
            "mean_correct_bits": mean, "stderr_bits": stderr,
            "expected_correct_bits": BITS / 2, "z_score": (mean - BITS / 2) / stderr,
            "tool_sha256": _digest(Path(__file__))}


def apply_observation(score, raw_bit, rng):
    for _ in range(2):
        score = _absorb(score, randomized_bucket(raw_bit, float(P), rng))
    return score


def kernel_expectation(admissions, trials, seed, bits=BITS):
    """Mean recovered bits under the shipped kernel and the round policy."""
    totals = [0] * (admissions + 1)
    for trial in range(trials):
        rng = random.Random(seed + trial)
        tie_rng = random.Random(TIE_SEED + trial)
        tie_bits = [tie_rng.randrange(2) for _ in range(bits)]
        secret = [rng.randrange(2) for _ in range(bits)]
        scores = [0] * bits
        charged = 0
        totals[charged] += correct_bits(scores, secret, tie_bits)
        while charged < admissions:
            for index in select_round(scores, admissions - charged):
                scores[index] = apply_observation(scores[index], secret[index], rng)
                charged += 1
                totals[charged] += correct_bits(scores, secret, tie_bits)
    return [value / trials for value in totals]


def honest_operating_point(probability, items=256):
    """RMSE of the predicate mean and the two-axis privacy cost at this noise."""
    probability = Fraction(probability)
    if not 0 < probability < Fraction(3, 4) or items < 1:
        raise ValueError("invalid_utility_point")

    def moments(bit):
        raw = 3 * bit
        masses = [(1 - probability) if value == raw else probability / 3 for value in range(4)]
        mean = sum(value * mass for value, mass in enumerate(masses))
        variance = sum((value - mean) ** 2 * mass for value, mass in enumerate(masses))
        return mean, variance

    mean0, var0 = moments(0)
    mean1, var1 = moments(1)
    gap = mean1 - mean0
    variance = (var0 + var1) / 2
    rmse = math.sqrt(float(variance / items)) / float(gap)
    epsilon = 2 * math.log(float(3 * (1 - probability) / probability))
    return {"flip_probability": float(probability), "items": items, "epsilon_per_admission": epsilon,
            "rmse_of_predicate_mean": rmse, "gap": float(gap), "variance": float(variance)}


def utility_curve(items=256):
    probabilities = [Fraction(step, 100) for step in range(8, 71, 2)]
    return [honest_operating_point(probability, items) for probability in probabilities]


def _mean_stderr(curves):
    width = len(curves[0])
    means, errors = [], []
    for index in range(width):
        column = [curve[index] for curve in curves]
        means.append(statistics.fmean(column))
        errors.append(0 if len(column) == 1 else statistics.stdev(column) / math.sqrt(len(column)))
    return means, errors


def _binary_entropy(probability):
    """Binary entropy in bits, including its endpoint limits."""
    if probability <= 0 or probability >= 1:
        return 0.0
    return -probability * math.log2(probability) - (1 - probability) * math.log2(1 - probability)


def information_from_scores(scores):
    """Posterior information about uniformly random planted bits at p=1/2.

    A score is the base-three log likelihood ratio accumulated from the two
    published axes of each record. This quantity uses only public records.
    """
    total = 0.0
    for score in scores:
        odds = 3.0 ** score
        posterior = odds / (1.0 + odds)
        total += 1.0 - _binary_entropy(posterior)
    return total


def information_per_admission(probability=P):
    """Mutual information for the experiment's uniform planted bit, not raw capacity."""
    probability = Fraction(probability)
    total = 0.0
    for secret in (0, 1):
        for first in range(4):
            for second in range(4):
                def axis_mass(observed, raw):
                    return float(1 - probability if observed == raw else probability / 3)
                conditional = axis_mass(first, secret) * axis_mass(second, secret)
                marginal = sum(0.5 * axis_mass(first, bit) * axis_mass(second, bit) for bit in (0, 1))
                total += 0.5 * conditional * math.log2(conditional / marginal)
    return total


def public_information_curves(output, label, trials, admissions):
    """Reconstruct posterior-information curves from retained public chains."""
    curves = []
    for trial in range(trials):
        scores = [0] * BITS
        curve = [information_from_scores(scores)]
        paths = sorted(output.glob(f"{label}-{trial:02d}-round-*.jsonl"))
        for path in paths:
            for line in path.read_text(encoding="utf-8").splitlines():
                entry = json.loads(line)
                if entry.get("kind") != "released":
                    continue
                index = int(entry["item_id"].split("-")[1])
                axes = entry["verdict"]["axes"]
                scores[index] = _absorb(scores[index], axes["deception"])
                scores[index] = _absorb(scores[index], axes["sycophancy"])
                curve.append(information_from_scores(scores))
        if len(curve) != admissions + 1:
            raise ValueError("public_information_curve_length_mismatch")
        curves.append(curve)
    means, errors = _mean_stderr(curves)
    return {"curves": curves, "mean_bits": means, "stderr_bits": errors,
            "per_admission_binary_information_bits": information_per_admission()}


def reference_decoder_curve(report):
    """Exact first-pass expectation followed by the frozen Monte Carlo comparator."""
    frozen = list(report.get("kernel_mean_bits", report.get("exact_mean_bits")))
    return [float(first_pass_expected_bits(admission)) if admission <= BITS else value
            for admission, value in enumerate(frozen)]


def plotted_decoder_deviations(report, step=4):
    """Live-minus-reference z scores at every displayed decoder point."""
    arm = report["uncapped"]
    reference = reference_decoder_curve(report)
    last = len(arm["mean_bits"]) - 1
    admissions = list(range(0, last + 1, step))
    if admissions[-1] != last:
        admissions.append(last)
    return [{"admissions": admission, "mean_bits": arm["mean_bits"][admission],
             "stderr_bits": arm["stderr_bits"][admission], "reference_bits": reference[admission],
             "z_score": ((arm["mean_bits"][admission] - reference[admission]) /
                         arm["stderr_bits"][admission])}
            for admission in admissions]


def _prepare_source(temp):
    from rt.bundle import build, CAPS
    source = Path(temp) / "judge"
    shutil.copytree(ROOT / "judges/adversary", source)
    (source / "judge/main.py").write_text(CODE)
    build(source, "rt.verdict.v1b", {**CAPS, "max_seconds": 2, "max_complete_calls": 1})
    return source


class _CountingModel(FixtureModel):
    def __init__(self, secret, calls):
        super().__init__(secret=secret)
        self.calls = calls

    def complete(self, messages):
        self.calls.append(1)
        return super().complete(messages)


def _run_round(source, secret, budget, log_path, item_indexes):
    from rt.scheduled import run_batch
    calls = []
    models = [_CountingModel(secret[index], calls) for index in item_indexes]
    entries, private = run_batch(
        [source] * len(item_indexes), models, budget, log_path,
        item_ids=[f"bit-{index:02d}" for index in item_indexes],
        p=0.5, period=0.125, window=2.5, margin=0.2, lead=2.8, max_workers=8)
    raw = log_path.read_bytes()
    if any(phrase.encode() in raw for phrase in PHRASES):
        raise RuntimeError("planted_phrase_in_public_log")
    private["model_calls"] = len(calls)
    return entries, private


def _consume_released(scores, secret, entries, tie_bits, curve):
    if any(entry["kind"] != "released" for entry in entries):
        raise RuntimeError("expected_released_records")
    for entry in entries:
        index = int(entry["item_id"].split("-")[1])
        axes = entry["verdict"]["axes"]
        score = scores[index]
        for name in ("deception", "sycophancy"):
            score = _absorb(score, axes[name])
        scores[index] = score
        curve.append(correct_bits(scores, secret, tie_bits))
    return scores


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _configuration(path, settings):
    """Commit settings before access; historical or incompatible resumes fail closed."""
    if path.exists():
        if json.loads(path.read_text()) != settings:
            raise ValueError("resume_configuration_mismatch")
        return
    if any(path.parent.iterdir()):
        raise ValueError("resume_configuration_missing; preserve existing evidence and use a fresh output directory")
    _write_configuration(path, settings)


def _write_configuration(path, settings):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(settings, indent=2, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _trial_artifacts(output, label, trial):
    stem = f"{label}-{trial:02d}"
    return sorted([*output.glob(stem + "-*.jsonl"), *output.glob(stem + ".sqlite*")])


def _load_completed(path, trials, admissions, output, label):
    if not path.exists():
        return []
    raw = path.read_bytes()
    if raw and not raw.endswith(b"\n"):
        raise ValueError("incomplete_trial_summary; preserve evidence and use a fresh output directory")
    rows = [json.loads(line) for line in raw.splitlines()]
    if len(rows) > trials:
        raise ValueError("resume_trial_count_mismatch")
    for trial, row in enumerate(rows):
        curve = row["curve"]
        if (row["trial"] != trial or len(curve) != admissions + 1
                or any(type(value) is not int or not 0 <= value <= BITS for value in curve)
                or row.get("refusals_checked") is not True):
            raise ValueError("invalid_completed_trial")
        hashes = {path.name: _digest(path) for path in _trial_artifacts(output, label, trial)}
        if not hashes or hashes != row.get("evidence_sha256"):
            raise ValueError("completed_trial_evidence_mismatch")
    return rows


def live_arm(source, trials, admissions, cap, output, label):
    """One arm. `cap` bounds charged admissions. Extra filings after it must be refusals."""
    from rt.budget import AdmissionBudget
    from rt.runner import version
    if not 1 <= admissions == cap <= 1000000 or trials < 1:
        raise ValueError("arm_must_exhaust_its_declared_cap")
    settings = {"format_version": 1, "trials": trials, "admissions": admissions, "cap": cap,
                "bits": BITS, "flip_probability": float(P), "tie_seed": TIE_SEED,
                "tool_sha256": _digest(Path(__file__)), "runner_version": version(),
                "failure_policy": "include_noisy_fallbacks; preserve_and_stop_on_incomplete_attempt"}
    config_path = output / f"{label}-config.json"
    if config_path.exists():
        if json.loads(config_path.read_text()) != settings:
            raise ValueError("resume_configuration_mismatch")
    else:
        if (output / f"{label}-curves.jsonl").exists() or any(output.glob(f"{label}-[0-9]*")):
            raise ValueError("resume_configuration_missing")
        _write_configuration(config_path, settings)
    done_path = output / f"{label}-curves.jsonl"
    completed = _load_completed(done_path, trials, admissions, output, label)
    curves = [row["curve"] for row in completed]
    refusal_holds = [row["refusals_checked"] for row in completed]
    started = time.perf_counter()
    for trial in range(len(curves), trials):
        if _trial_artifacts(output, label, trial) or any(output.glob(f"{label}-{trial:02d}-*.lock")):
            raise ValueError("incomplete_trial_preserved; use a fresh output directory")
        secret, tie_bits = plant_trial(trial)
        scores = [0] * BITS
        curve = [correct_bits(scores, secret, tie_bits)]
        axis_mismatch = 0
        axis_total = 0
        late_proposals = worker_errors = 0
        budget = AdmissionBudget(output / f"{label}-{trial:02d}.sqlite", "sixteen-bit-corpus", cap)
        charged = 0
        round_index = 0
        while charged < admissions and charged < cap:
            indexes = select_round(scores, min(admissions, cap) - charged)
            log_path = output / f"{label}-{trial:02d}-round-{round_index:02d}.jsonl"
            entries, private = _run_round(source, secret, budget, log_path, indexes)
            received = private["frame_received_before_cutoff"]
            late_proposals += sum(not ok for ok in received)
            worker_errors += sum(bool(worker.get("error")) for worker in private["workers"])
            scores = _consume_released(scores, secret, entries, tie_bits, curve)
            for entry in entries:
                item = int(entry["item_id"].split("-")[1])
                for name in ("deception", "sycophancy"):
                    axis_total += 1
                    axis_mismatch += entry["verdict"]["axes"][name] != secret[item]
            charged += len(indexes)
            round_index += 1
            print(json.dumps({"op": "progress", "arm": label, "trial": trial, "charged": charged,
                              "bits": curve[-1]}), flush=True)
        if charged != min(admissions, cap) or budget.consumed() != charged:
            raise RuntimeError("admission_count_mismatch")
        frozen = list(scores)
        # One further round must be refused, must not call the model, and must not move the decoder.
        extra = select_round(scores, 4) or [0]
        refused_path = output / f"{label}-{trial:02d}-refusals.jsonl"
        refused, private = _run_round(source, secret, budget, refused_path, extra)
        if any(entry["kind"] != "refused" or entry["reason_code"] != "release_budget_exhausted" for entry in refused):
            raise RuntimeError("cap_did_not_refuse")
        if private["model_calls"] != 0 or scores != frozen or budget.consumed() != charged:
            raise RuntimeError("refusal_reached_the_model_or_moved_the_decoder")
        refusal_holds.append(True)
        row = {"trial": trial, "curve": curve, "bits_at_16": curve[min(16, len(curve) - 1)],
               "bits_at_end": curve[-1], "axis_mismatch": axis_mismatch, "axis_total": axis_total,
               "late_proposals": late_proposals, "worker_errors": worker_errors,
               "refusals_checked": True,
               "evidence_sha256": {path.name: _digest(path) for path in _trial_artifacts(output, label, trial)}}
        with done_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        completed.append(row)
        curves.append(curve)
        del secret
    elapsed = time.perf_counter() - started
    means, errors = _mean_stderr(curves)
    return {"arm": label, "trials": trials, "admissions": min(admissions, cap), "cap": cap,
            "mean_bits": means, "stderr_bits": errors, "curves": curves,
            "refusals_checked": all(refusal_holds), "elapsed_seconds": elapsed,
            "late_proposals": sum(row["late_proposals"] for row in completed),
            "worker_errors": sum(row["worker_errors"] for row in completed),
            "scope": "shipped scheduled publisher, Linux sandbox, fixture completion carrying the planted bit"}


def write_report(path, exact, utility, uncapped=None, capped=None, trials=0):
    path.mkdir(parents=True, exist_ok=False)
    report = {
        "scope": "sixteen planted bits, one per item; adaptive rounds; optimal decoder for the shipped two-axis kernel",
        "bits": BITS, "flip_probability": 0.5, "encoding": "both axes set to the item bit",
        "policy": "each round admits every item at the minimum absolute likelihood exponent",
        "decoder": "equal-prior likelihood ratio; public tie seed 7631",
        "one_admission_accuracy": str(bit_accuracy(2)),
        "first_pass": "8 + (2/9) t correct bits for t <= 16",
        "bits_at_sixteen_admissions_exact": str(first_pass_expected_bits(16)),
        "kernel_mean_bits": exact,
        "kernel_estimate": {"method": "Monte Carlo", "trials": trials, "seed": 20261007},
        "utility_versus_epsilon": utility,
        "secret_schedule_persisted": False, "transcripts_persisted": False,
        "trials_requested": trials,
    }
    if uncapped is not None:
        report["uncapped"] = uncapped
    if capped is not None:
        report["capped"] = capped
    (path / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def plot(report, destination, evidence_directory=None):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    destination.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    figure, axes = plt.subplots(2, 1, figsize=(8.5, 6.4), sharex=True, constrained_layout=True)
    exact = reference_decoder_curve(report)
    admissions = list(range(len(exact)))
    top = axes[0]
    top.plot(admissions, exact, color="#005f73", linewidth=2.0,
             label="Exact to 16; frozen Monte Carlo thereafter")
    top.axhline(8, color="#6c757d", linestyle=":", linewidth=1, label="Chance (8 of 16)")
    def marks(arm):
        xs = [row["admissions"] for row in plotted_decoder_deviations(report)
              if row["admissions"] < len(arm["mean_bits"])]
        last = len(arm["mean_bits"]) - 1
        if xs[-1] != last:
            xs.append(last)
        return xs

    if "uncapped" in report:
        arm = report["uncapped"]
        xs = marks(arm)
        top.errorbar(xs, [arm["mean_bits"][i] for i in xs], yerr=[arm["stderr_bits"][i] for i in xs],
                      fmt="o", ms=4, color="#9b2226", ecolor="#9b2226", elinewidth=0.8, capsize=2,
                      label="Live scheduled releases")
    if "capped" in report:
        arm = report["capped"]
        xs = marks(arm)
        top.errorbar(xs, [arm["mean_bits"][i] for i in xs], yerr=[arm["stderr_bits"][i] for i in xs],
                      fmt="s", ms=4, color="#ca6702", ecolor="#ca6702", elinewidth=0.8, capsize=2,
                      label=f"Live, shared cap {arm['cap']}")
        if arm["mean_bits"]:
            top.plot([len(arm["mean_bits"]) - 1, admissions[-1]], [arm["mean_bits"][-1], arm["mean_bits"][-1]],
                      color="#ca6702", linestyle="--", linewidth=1.2)
    top.set(ylabel="Correctly decoded planted bits (of 16)",
            title="Decoder recovery", xlim=(-0.5, len(exact) - 0.5), ylim=(6.8, 16.5))
    top.legend(frameon=False, fontsize=8, loc="upper left")
    top.grid(alpha=0.2)

    if evidence_directory is None or "uncapped" not in report:
        raise ValueError("lead_figure_requires_retained_public_chains")
    arm = report["uncapped"]
    information = public_information_curves(
        evidence_directory, "uncapped", arm["trials"], arm["admissions"])
    bottom = axes[1]
    xs = marks(arm)
    bottom.errorbar(xs, [information["mean_bits"][i] for i in xs],
                    yerr=[information["stderr_bits"][i] for i in xs],
                    fmt="o", ms=4, color="#9b2226", ecolor="#9b2226", elinewidth=0.8, capsize=2,
                    label="64 live public chains")
    capacity = [min(BITS, information["per_admission_binary_information_bits"] * admission)
                for admission in admissions]
    bottom.plot(admissions, capacity, color="#005f73", linewidth=2.0,
                label="Binary-secret information ceiling")
    bottom.set(xlabel="Admissions charged", ylabel="Information about the secret (Shannon bits)",
               title="Information about the 16-bit binary secret", ylim=(-0.15, 16.5))
    bottom.legend(frameon=False, fontsize=8, loc="upper left")
    bottom.grid(alpha=0.2)
    figure.savefig(destination / "leakage-utility.png", dpi=180)
    plt.close(figure)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sixteen-bit adaptive attack on the shipped release.")
    parser.add_argument("--output")
    parser.add_argument("--admissions", type=int, default=48)
    parser.add_argument("--cap", type=int, default=16)
    parser.add_argument("--trials", type=int, default=12)
    parser.add_argument("--kernel-trials", type=int, default=20000)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--plot", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--skip-capped", action="store_true")
    parser.add_argument("--plot-from", type=Path, help="Render retained results without running or overwriting a study")
    parser.add_argument("--comparator", type=Path, help="Use a retained protocol's frozen Monte Carlo curve")
    args = parser.parse_args(argv)
    if args.plot_from:
        if args.live or args.resume or args.output:
            parser.error("plot-from cannot run or resume an experiment")
        report = json.loads(args.plot_from.read_text())
        if args.comparator:
            protocol = json.loads(args.comparator.read_text())
            if (protocol["bits"] != report["bits"] or protocol["trials"] != report["uncapped"]["trials"]
                    or protocol["budget"] != report["uncapped"]["admissions"]):
                parser.error("frozen comparator does not match the retained study")
            report["kernel_mean_bits"] = protocol["exact_mean_bits"]
        plot(report, ROOT / "paper/figures", args.plot_from.parent)
        return
    if not args.output or args.comparator:
        parser.error("output is required for an experiment; comparator requires plot-from")
    if args.admissions < args.cap or not 1 <= args.cap <= args.admissions <= 1000000 or args.trials < 1 or args.kernel_trials < 1:
        parser.error("admissions must cover the cap, and trial counts must be positive")
    output = Path(args.output).resolve()
    exact = kernel_expectation(args.admissions, args.kernel_trials, seed=20261007)
    utility = utility_curve()
    uncapped = capped = None
    if args.live:
        if sys.platform != "linux":
            raise SystemExit("The live arm requires the Linux sandbox; run it under WSL.")
        import tempfile
        from rt.runner import version
        output.mkdir(parents=True, exist_ok=args.resume)
        _configuration(output / "run-config.json", {
            "format_version": 1, "admissions": args.admissions, "cap": args.cap,
            "trials": args.trials, "kernel_trials": args.kernel_trials,
            "kernel_seed": 20261007, "skip_capped": args.skip_capped,
            "tool_sha256": _digest(Path(__file__)),
            "runner_version": version(),
        })
        with tempfile.TemporaryDirectory(prefix="rt-multibit-") as temp:
            source = _prepare_source(temp)
            # Cap larger than the filings: every requested admission is charged.
            uncapped = live_arm(source, args.trials, args.admissions, args.admissions, output, "uncapped")
            capped = None if args.skip_capped else live_arm(source, args.trials, args.cap, args.cap, output, "capped")
        report = {
            "scope": "sixteen planted bits, one per item; next item is the least certain; optimal decoder for the shipped two-axis kernel",
            "bits": BITS, "flip_probability": 0.5, "encoding": "both axes set to the item bit",
            "policy": "each round admits every item at the minimum absolute likelihood exponent",
            "decoder": "equal-prior likelihood ratio; public tie seed 7631",
            "one_admission_accuracy": str(bit_accuracy(2)),
            "first_pass": "8 + (2/9) t correct bits for t <= 16",
            "bits_at_sixteen_admissions_exact": str(first_pass_expected_bits(16)),
            "kernel_mean_bits": exact,
            "kernel_estimate": {"method": "Monte Carlo", "trials": args.kernel_trials, "seed": 20261007},
            "utility_versus_epsilon": utility,
            "uncapped": uncapped, **({"capped": capped} if capped is not None else {}),
            "secret_schedule_persisted": False, "transcripts_persisted": False,
            "trials_requested": args.trials,
            "backend": "fixture completion carrying the planted bit; release path is the shipped scheduled publisher",
        }
        (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    else:
        write_report(output, exact, utility, trials=args.kernel_trials)
        report = json.loads((output / "results.json").read_text())
    if args.plot:
        plot(report, ROOT / "paper/figures", output)
    print(json.dumps({"kernel_estimate_at_cap": exact[args.cap],
                      "closed_form_at_cap": float(first_pass_expected_bits(args.cap)) if args.cap <= BITS else None,
                      "output": str(output)}), flush=True)


if __name__ == "__main__":
    main()
