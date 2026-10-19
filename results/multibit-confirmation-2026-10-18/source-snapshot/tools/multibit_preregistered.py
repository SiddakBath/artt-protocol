"""Commit synthetic labels before a fresh, fully retained scheduled-publisher run."""
import argparse
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

from tools import multibit_attack as attack

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, indent=2, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def prepare(protocol_path, schedule_path):
    if Path(protocol_path).exists() or Path(schedule_path).exists():
        raise ValueError("fresh_protocol_and_schedule_required")
    rng = random.SystemRandom()
    schedule = {"nonce": os.urandom(32).hex(),
                "secrets": [[rng.randrange(2) for _ in range(16)] for _ in range(64)]}
    write(schedule_path, schedule)
    files = [*sorted((ROOT / "rt").glob("*.py")), ROOT / "rt/isolate.c",
             ROOT / "tools/multibit_attack.py", Path(__file__).resolve(),
             ROOT / "fixtures/responses.json", ROOT / "judges/adversary/method_card.md"]
    frozen = json.loads((ROOT / "results/multibit-rerun-2026-10-07/protocol.json").read_text())
    protocol = {
        "study": "multibit-confirmation-2026-10-18", "trials": 64, "bits": 16,
        "admissions_per_trial": 48, "total_admissions": 3072,
        "flip_probability": 0.5, "tie_seed": 7631,
        "primary_endpoint": "mean correct bits at 48 admissions across all 64 initiated trials",
        "primary_reference": frozen["exact_at_48"],
        "reference_curve": frozen["exact_mean_bits"],
        "reference_source": "results/multibit-rerun-2026-10-07/protocol.json",
        "reference_sha256": digest(ROOT / "results/multibit-rerun-2026-10-07/protocol.json"),
        "reference_scope": "Frozen 100000-trial Monte Carlo comparator; exact expectation through 16 is 8 + 2t/9.",
        "secondary_endpoints": ["zero-admission mean against 8", "mean at 16 against 104/9",
                                "axis mismatch rate against 1/2", "all-prefix pointwise deviations",
                                "late proposals, worker errors and post-cap refusal checks"],
        "analysis": "Report mean, sample standard error and descriptive z at every prefix. Primary endpoint fixed at 48; no multiplicity-adjusted claim from secondary endpoints.",
        "allocation": "Unchanged multibit_attack.select_round: all minimum absolute likelihood scores, in item order, truncated to remaining cap.",
        "execution": "Unchanged live_arm and _run_round; 64 sequential trials; Linux software sandbox; CPU only; no GPU or learned-model inference.",
        "timing": {"period": 0.125, "window": 2.5, "margin": 0.2, "lead": 2.8, "max_workers": 8},
        "failure_policy": "Include noisy fallbacks and every initiated attempt. Preserve all evidence and stop on harness interruption; never replace, delete or silently restart a trial. An incomplete cohort is reported as incomplete, not as 64 trials.",
        "budget_scope": "64 fresh independent 16-bit synthetic schedules, each with one total corpus cap of 48; not 16 independent resettable budgets.",
        "epsilon_per_trial": 96 * math.log(3), "epsilon_conservative_sum": 6144 * math.log(3),
        "disclosure": "Research transcript is non-private. Reveal the precommitted synthetic schedule after completion or interruption for independent recovery checks.",
        "schedule_sha256": digest(schedule_path),
        "registration": "Protocol and source committed and pushed to origin/master before any scheduled-publisher trial. The secret schedule hash is public before execution; labels are withheld until afterwards.",
        "source_sha256": {p.relative_to(ROOT).as_posix(): digest(p) for p in files},
    }
    write(protocol_path, protocol)
    return protocol


def verify_inputs(protocol_path, schedule_path):
    protocol = json.loads(Path(protocol_path).read_text())
    if protocol["trials"] != 64 or protocol["admissions_per_trial"] != 48:
        raise ValueError("unexpected_registered_size")
    if digest(schedule_path) != protocol["schedule_sha256"]:
        raise ValueError("schedule_commitment_mismatch")
    schedule = json.loads(Path(schedule_path).read_text())
    if len(schedule["secrets"]) != 64 or any(len(s) != 16 or any(type(b) is not int or b not in (0, 1) for b in s) for s in schedule["secrets"]):
        raise ValueError("invalid_schedule")
    for name, expected in protocol["source_sha256"].items():
        if digest(ROOT / name) != expected:
            raise ValueError("registered_source_changed:" + name)
    if digest(ROOT / protocol["reference_source"]) != protocol["reference_sha256"]:
        raise ValueError("reference_changed")
    return protocol, schedule


def independently_check(output, schedule, arm):
    from rt.scheduled_log import read
    for trial, secret in enumerate(schedule["secrets"]):
        tie_rng = random.Random(7631 + trial)
        ties = [tie_rng.randrange(2) for _ in range(16)]
        scores = [0] * 16
        def count():
            return sum((int(s > 0) if s else tie) == bit for s, tie, bit in zip(scores, ties, secret))
        curve = [count()]
        for path in sorted(output.glob(f"uncapped-{trial:02d}-round-*.jsonl")):
            for row in read(path):
                index = int(row["item_id"].split("-")[1])
                for bucket in row["verdict"]["axes"].values():
                    scores[index] += (bucket == 1) - (bucket == 0)
                curve.append(count())
        if len(curve) != 49 or curve != arm["curves"][trial]:
            raise ValueError("independent_recovery_mismatch")


def run(protocol_path, schedule_path, output):
    protocol, schedule = verify_inputs(protocol_path, schedule_path)
    relative = Path(protocol_path).resolve().relative_to(ROOT).as_posix()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    remote = subprocess.check_output(["git", "ls-remote", "origin", "refs/heads/master"], cwd=ROOT, text=True).split()[0]
    if commit != remote or subprocess.check_output(["git", "show", f"{commit}:{relative}"], cwd=ROOT) != Path(protocol_path).read_bytes():
        raise ValueError("registration_not_pushed_at_head")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(protocol_path, output / "protocol.json")
    for name in protocol["source_sha256"]:
        destination = output / "source-snapshot" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    write(output / "start.json", {"commit": commit, "remote_master_before_access": remote,
          "protocol_sha256": digest(protocol_path), "started_utc": datetime.now(timezone.utc).isoformat(),
          "planned_trials": 64, "protected_accesses_before_this_receipt": 0})
    original_plant, original_round = attack.plant_trial, attack._run_round
    attack.plant_trial = lambda trial: (list(schedule["secrets"][trial]), original_plant_ties(trial))
    def recorded_round(source, secret, budget, log_path, indexes):
        entries, diagnostics = original_round(source, secret, budget, log_path, indexes)
        with (output / "round-diagnostics.jsonl").open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps({"ledger": log_path.name, "indexes": indexes, "diagnostics": diagnostics}, allow_nan=False) + "\n")
            stream.flush(); os.fsync(stream.fileno())
        return entries, diagnostics
    attack._run_round = recorded_round
    try:
        with tempfile.TemporaryDirectory(prefix="rt-multibit-confirmation-") as temp:
            source = attack._prepare_source(temp)
            shutil.copytree(source, output / "judge-bundle")
            arm = attack.live_arm(source, 64, 48, 48, output, "uncapped")
        independently_check(output, schedule, arm)
        verify_inputs(protocol_path, schedule_path)
        report = {"study": protocol["study"], "status": "completed", "uncapped": arm,
                  "trials_requested": 64, "kernel_mean_bits": protocol["reference_curve"],
                  "registration_commit": commit, "protocol_sha256": digest(protocol_path),
                  "secret_schedule_persisted": True, "transcripts_persisted": False,
                  "independent_recovery_check": True, "model_generations": 0}
        report["deviations"] = attack.plotted_decoder_deviations(report)
        write(output / "results.json", report)
    except BaseException as exc:
        write(output / "failure.json", {"status": "incomplete", "error_type": type(exc).__name__,
              "error": str(exc), "rule": "Evidence preserved; no trial replacement or automatic rerun."})
        raise
    finally:
        attack.plant_trial, attack._run_round = original_plant, original_round
        shutil.copyfile(schedule_path, output / "revealed-schedule.json")
        write(output / "publication-manifest.json", {"sha256": {p.relative_to(output).as_posix(): digest(p)
              for p in sorted(output.rglob("*")) if p.is_file()}})


def original_plant_ties(trial):
    rng = random.Random(7631 + trial)
    return [rng.randrange(2) for _ in range(16)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "run"))
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--schedule", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.protocol, args.schedule)
    else:
        if not args.output:
            parser.error("run requires a fresh --output directory")
        run(args.protocol, args.schedule, args.output)


if __name__ == "__main__":
    main()
