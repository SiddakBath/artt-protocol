"""Execute the predeclared exact baseline and repeated score releases once."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import math
from pathlib import Path
import random
import tempfile
import time
from rt.budget import AdmissionBudget
from rt.bundle import sha
from rt.experiment import interval
from rt.log import append as append_naive, read as read_naive
from rt.runner import submit, version
from rt.scheduled import run_batch
from rt.scheduled_log import read as read_scheduled
from .hidden_tests import balanced_canaries, private_context
from .real_run import Bridge, EXPECTED_MESSAGES, LiveModel, naive_cohort, prepare_bundles
from .run import checkpoint, recovery, verify_cli, write_json
from .tasks import TASKS
from .utility_run import extend_budget


def prediction(filings, p=0.5):
    """Exact maximum-likelihood recovery for the declared independent axes."""
    distribution = {0: 1.0}
    for _ in range(2*filings):
        updated = Counter()
        for score, probability in distribution.items():
            for delta, weight in ((1, 1-p), (-1, p/3), (0, 2*p/3)):
                updated[score+delta] += probability*weight
        distribution = updated
    return sum(value for score, value in distribution.items() if score > 0)+distribution.get(0, 0)/2


def prefix_guesses(histories, rng):
    guesses = []
    for history in histories:
        values = [value for row in history for value in row.get("verdict", {}).get("axes", {}).values()]
        difference = values.count(1)-values.count(0)
        guesses.append(int(difference > 0) if difference else rng.randrange(2))
    return guesses


def point(guesses, secrets, filing, admitted, refused, predicted):
    correct = sum(guess == secret for guess, secret in zip(guesses, secrets))
    return {"filing": filing, "correct": correct, "n": len(secrets), "rate": correct/len(secrets),
            "wilson_95": interval(correct, len(secrets)), "admitted_per_trial": admitted,
            "refused_per_trial": refused, "predicted": predicted}


class ReplayModel:
    """Fixed public Qwen patch; every protected backend access is counted."""
    def __init__(self, patch, task, secret, identity, budget, minimum_charge=0, item_budget=None):
        self.patch, self.task, self.secret, self.model_hash = patch, task, secret, identity
        self.budget, self.minimum_charge, self.item_budget = budget, minimum_charge, item_budget
        self.calls = 0

    def complete(self, messages):
        if messages != EXPECTED_MESSAGES:
            raise ValueError("outside_declared_coding_prompt")
        if self.budget is not None and self.budget.consumed() < self.minimum_charge:
            raise RuntimeError("replay_before_admission")
        if self.item_budget is not None and not self.item_budget.consumed():
            raise RuntimeError("replay_before_item_admission")
        self.calls += 1
        return self.patch+"\n### PRIVATE TESTS\n"+private_context(self.task, self.secret)


def replay_uncapped(source, output, filing, models, workers, p):
    directory = output / "uncapped-source-records" / f"filing-{filing:02d}"
    directory.mkdir(parents=True)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        rows = list(pool.map(lambda i: submit(source, directory / f"{i:03d}.jsonl", models[i], noise=p), range(len(models))))
    filename = f"uncapped-filing-{filing:02d}.jsonl"
    merged = [append_naive(output / filename, {key: value for key, value in row.items()
        if key not in {"seq", "prev", "timestamp", "entry_hash"}}) for row in rows]
    write_json(directory / "checkpoints.json", {f"{i:03d}.jsonl": checkpoint(directory / f"{i:03d}.jsonl") for i in range(len(models))})
    return filename, merged


def run(output, prior_dir):
    output, prior_dir = Path(output), Path(prior_dir)
    started = time.monotonic()
    protocol = json.loads((output / "protocol.json").read_text())
    start = json.loads((output / "start.json").read_text())
    if version() != start["runner_version"]:
        raise ValueError("runner_not_frozen")
    if protocol["additional_admissions"] != protocol["repeated_trials"]*protocol["cap_per_secret"]:
        raise ValueError("invalid_repeated_allowance")
    patch_bytes = (prior_dir / "public-patches.jsonl").read_bytes()
    if sha(patch_bytes) != protocol["public_patches_sha256"]:
        raise ValueError("wrong_replay_patch_commitment")
    retained = [json.loads(line) for line in patch_bytes.splitlines()]
    patches = {row["index"]: row for row in retained if row["arm"] == "artt_score_attack"}
    n = protocol["repeated_trials"]
    if set(patches) != set(range(n)) or any(row["task_id"] != TASKS[i % len(TASKS)].id or sha(row["patch"].encode()) != row["patch_sha256"] for i, row in patches.items()):
        raise ValueError("invalid_replay_provenance")
    write_json(output / "replay-provenance.json", {"source": str(prior_dir), "source_sha256": sha(patch_bytes),
        "patches": [{key: patches[i][key] for key in ("index", "task_id", "patch_sha256")} for i in range(n)],
        "fresh_gpu_generations": 0, "description": protocol["repeated_backend"]})
    bridge = Bridge()
    identity = bridge.request({"op": "init"})
    budget = extend_budget(prior_dir / "budget.sqlite", output / "budget.sqlite", protocol)
    unsafe = AdmissionBudget(output / "exact-budget.sqlite", "explicitly-unsafe-exact-score", protocol["naive_admissions"])
    item_budgets = [AdmissionBudget(output / "item-budgets.sqlite", protocol["item_scope_prefix"]+str(i), protocol["cap_per_secret"]) for i in range(n)]
    ledgers, unsafe_files, diagnostics = [], [], Counter()
    replay_models = []
    with tempfile.TemporaryDirectory(prefix="rt-coding-filings-") as temporary:
        root = Path(temporary)
        exact_source = prepare_bundles(root / "exact", protocol)["score_attack"]
        exact_secrets = balanced_canaries(protocol["attack_trials"])
        exact_models = [LiveModel(bridge, identity, TASKS[i % len(TASKS)], secret, "exact_score_attack", i, unsafe, i+1) for i, secret in enumerate(exact_secrets)]
        filename, exact_rows = naive_cohort(exact_source, output, "exact-score-attack", exact_models, unsafe, protocol["max_workers"], noise=None)
        unsafe_files.append(filename)
        if any("release_policy" in row for row in exact_rows):
            raise RuntimeError("exact_baseline_was_noised")
        diagnostics["exact_baseline_worker_errors"] = sum(row["kind"] == "error" for row in exact_rows)
        exact_result = recovery(exact_rows, exact_secrets, 0.5, 1.0)
        live_before = bridge.request({"op": "call_count"})
        bridge.request({"op": "progress", "message": f"Exact unnoised score baseline complete: {len(exact_rows)} fresh Qwen patches"})
        source = prepare_bundles(root / "repeated", {**protocol, "max_seconds": protocol["repeated_max_seconds"]})["score_attack"]
        secrets = balanced_canaries(n)
        uncapped_history, artt_history = [[] for _ in range(n)], [[] for _ in range(n)]
        rng_uncapped, rng_artt = random.Random(protocol["decoder_tie_seed"]), random.Random(protocol["decoder_tie_seed"]+1)
        uncapped_guesses = artt_guesses = [0]*n
        curve = {"uncapped": [point(uncapped_guesses, secrets, 0, 0, 0, 0.5)], "artt": [point(artt_guesses, secrets, 0, 0, 0, 0.5)]}
        calls_at_cap = None
        timing = {key: protocol[key] for key in ("p", "period", "window", "margin", "lead", "max_workers")}
        for filing in range(1, protocol["filings"]+1):
            models = [ReplayModel(patches[i]["patch"], TASKS[i % len(TASKS)], secret, identity, None) for i, secret in enumerate(secrets)]
            filename, rows = replay_uncapped(source, output, filing, models, protocol["max_workers"], protocol["p"])
            diagnostics["uncapped_worker_errors"] += sum(row["kind"] == "error" for row in rows)
            diagnostics["uncapped_backend_accesses"] += sum(model.calls for model in models)
            unsafe_files.append(filename)
            for history, row in zip(uncapped_history, rows):
                history.append(row)
            uncapped_guesses = prefix_guesses(uncapped_history, rng_uncapped)
            models = [ReplayModel(patches[i]["patch"], TASKS[i % len(TASKS)], secret, identity, budget,
                min(budget.cap, budget.consumed()+n), item_budgets[i]) for i, secret in enumerate(secrets)]
            replay_models.extend(models)
            filename = f"artt-filing-{filing:02d}.jsonl"
            rows, private = run_batch([source]*n, models, budget, output / filename,
                item_ids=["trial-"+str(i) for i in range(n)], item_budgets=item_budgets, **timing)
            ledgers.append((filename, rows))
            diagnostics.update({"proposals_before_cutoff": sum(private["frame_received_before_cutoff"]),
                "scheduled_releases": sum(row["kind"] == "released" for row in rows),
                "scheduled_refusals": sum(row["kind"] == "refused" for row in rows),
                "private_worker_errors": sum(worker.get("error") is not None for worker in private["workers"]),
                "private_timeouts": sum(worker.get("error") == "timeout" for worker in private["workers"])})
            for history, row in zip(artt_history, rows):
                if row["kind"] == "released":
                    history.append(row)
            cap = protocol["cap_per_secret"]
            if filing <= cap:
                artt_guesses = prefix_guesses(artt_history, rng_artt)
            replay_calls = sum(model.calls for model in replay_models)
            if filing == cap:
                calls_at_cap = replay_calls
            if filing > cap and (replay_calls != calls_at_cap or any(row["kind"] != "refused" or row["reason_code"] != "release_budget_exhausted" for row in rows)):
                raise RuntimeError("post_cap_backend_access_or_release")
            curve["uncapped"].append(point(uncapped_guesses, secrets, filing, filing, 0, prediction(filing)))
            curve["artt"].append(point(artt_guesses, secrets, filing, min(filing, cap), max(0, filing-cap), prediction(min(filing, cap))))
            bridge.request({"op": "progress", "message": f"Filings {filing}/{protocol['filings']}: uncapped {curve['uncapped'][-1]['correct']}/{n}; ARTT {curve['artt'][-1]['correct']}/{n}; refused {max(0, filing-cap)*n}; protected replay calls {replay_calls}"})
        live_after = bridge.request({"op": "call_count"})
    if not (live_before == live_after == protocol["expected_live_inferences"] and sum(model.calls for model in exact_models) == live_before
            and calls_at_cap == sum(model.calls for model in replay_models) == protocol["additional_admissions"]
            and budget.consumed() == budget.cap and all(item.consumed() == protocol["cap_per_secret"] for item in item_budgets)):
        raise RuntimeError("filings_admission_invariant_failed")
    paths = [name for name, _ in ledgers]+unsafe_files
    # Re-read every merged chain and every separately retained unsafe source.
    for name, _ in ledgers:
        read_scheduled(output / name)
    for name in unsafe_files:
        read_naive(output / name)
    for checks in [*(output / "naive-source-records").glob("*/checkpoints.json"), *(output / "uncapped-source-records").glob("*/checkpoints.json")]:
        for name, saved in json.loads(checks.read_text()).items():
            read_naive(checks.parent / name)
            if checkpoint(checks.parent / name) != saved:
                raise RuntimeError("source_checkpoint_mismatch")
    epsilon = 2*math.log(3)
    summary = {**{key: start[key] for key in ("git_commit", "protocol_commit", "protocol_sha256", "runner_version")},
        "protocol_id": protocol["protocol_id"], "model_hash": identity, "exact_baseline": exact_result,
        "curve": curve, "ledger_files": [name for name, _ in ledgers], "unsafe_ledger_files": unsafe_files,
        "checkpoints": {name: checkpoint(output / name) for name in paths},
        "verification": {name: verify_cli(output / name) for name in paths}, "diagnostics": dict(diagnostics),
        "budget": {"scope": budget.scope, "used_before": protocol["original_cap_and_used"], "used": budget.consumed(), "cap": budget.cap,
            "admitted": protocol["additional_admissions"], "refused": diagnostics["scheduled_refusals"], "cap_per_secret": protocol["cap_per_secret"],
            "epsilon_per_record": epsilon, "epsilon_new": epsilon*protocol["additional_admissions"], "epsilon_composed": epsilon*budget.consumed(),
            "protected_replay_calls_at_cap": calls_at_cap, "protected_replay_calls_after_refusals": sum(model.calls for model in replay_models),
            "live_gpu_calls_before_repeated": live_before, "live_gpu_calls_after_repeated": live_after,
            "item_consumption": [item.consumed() for item in item_budgets]}, "wall_seconds": time.monotonic()-started}
    write_json(output / "summary.json", summary)
    bridge.request({"op": "progress", "message": "Exact baseline and all repeated-filing prefixes complete; retained evidence unchanged"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--prior-run", required=True)
    args = parser.parse_args()
    run(args.output, args.prior_run)


if __name__ == "__main__":
    main()
