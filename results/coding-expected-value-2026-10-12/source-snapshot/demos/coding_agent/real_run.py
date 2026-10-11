"""Linux custodian for the separately predeclared live Qwen comparison."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import math
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
from rt.budget import AdmissionBudget
from rt.bundle import CAPS, build, sha
from rt.runner import submit, version
from rt.log import append as append_naive
from rt.scheduled import run_batch
from .hidden_tests import balanced_canaries, private_context
from .run import ROOT, checkpoint, recovery, tamper_copies, utility, verify_cli, write_json
from .tasks import TASKS
from .utility_run import extend_budget

EXPECTED_MESSAGES = [{"role": "user", "content": "Return the assigned Python patch and its private test context."}]


def naive_cohort(source, output, label, models, budget, workers, noise=None):
    """Precharge the control cohort, then collect separate single-writer logs."""
    for _ in models:
        if not budget.reserve():
            raise RuntimeError("unsafe_control_allowance_exhausted")
    for model in models:
        model.minimum_charge = budget.consumed()
    directory = output / "naive-source-records" / label
    directory.mkdir(parents=True)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        rows = list(pool.map(lambda i: submit(source, directory / f"{i:03d}.jsonl", models[i], noise=noise), range(len(models))))
    # Preserve originals and create one verified comparison chain in trial order.
    filename = f"naive-{label}.jsonl"
    merged = [append_naive(output / filename, {key: value for key, value in row.items()
        if key not in {"seq", "prev", "timestamp", "entry_hash"}}) for row in rows]
    write_json(directory / "checkpoints.json", {f"{i:03d}.jsonl": checkpoint(directory / f"{i:03d}.jsonl") for i in range(len(models))})
    return filename, merged


class Bridge:
    """Multiplex requests; private canaries never cross the host bridge."""
    def __init__(self):
        self.lock = threading.Lock()
        self.pending = {}
        self.serial = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in sys.stdin:
            reply = json.loads(line)
            with self.lock:
                target = self.pending[reply["id"]]
                target["reply"] = reply
                target["event"].set()
        with self.lock:
            for target in self.pending.values():
                target["reply"] = {"error": "host_bridge_closed"}
                target["event"].set()

    def request(self, value):
        with self.lock:
            index = self.serial
            self.serial += 1
            target = {"event": threading.Event()}
            self.pending[index] = target
            print(json.dumps({"id": index, **value}), flush=True)
        if not target["event"].wait(180):
            raise RuntimeError("host_bridge_timeout")
        with self.lock:
            reply = self.pending.pop(index)["reply"]
        if "error" in reply:
            raise RuntimeError("host_inference_failed")
        return reply["value"]


class LiveModel:
    def __init__(self, bridge, identity, task, canary, arm, index, budget, minimum_charge):
        self.bridge, self.model_hash, self.task, self.canary = bridge, identity, task, canary
        self.arm, self.index, self.budget, self.minimum_charge = arm, index, budget, minimum_charge
        self.calls = 0

    def complete(self, messages):
        if messages != EXPECTED_MESSAGES:
            raise ValueError("outside_declared_coding_prompt")
        if self.budget.consumed() < self.minimum_charge:
            raise RuntimeError("inference_before_admission")
        self.calls += 1
        patch = self.bridge.request({"op": "complete", "arm": self.arm, "index": self.index,
            "task_id": self.task.id, "admission_charged": True})
        # Tests are custodian context supplied to the judge, never model output.
        return patch + "\n### PRIVATE TESTS\n" + private_context(self.task, self.canary)


def prepare_bundles(root, protocol):
    sources = {}
    for name in ("honest", "status_attack", "score_attack"):
        path = root / name
        shutil.copytree(ROOT / "judges" / name, path, ignore=shutil.ignore_patterns("__pycache__"))
        card = path / "method_card.md"
        card.write_text(card.read_text().replace("fixture", "live Qwen coding").replace("Fixture", "Live Qwen coding")
            + "\nThe offline model generates the patch from the public task. The custodian appends hidden tests and a canary; neither is sent to the model.\n")
        build(path, "rt.verdict.v1b", {**CAPS, "max_seconds": protocol["max_seconds"], "max_complete_calls": 1})
        sources[name] = path
    return sources


def run(output, prior_dir):
    output, prior_dir = Path(output), Path(prior_dir)
    started = time.monotonic()
    protocol = json.loads((output / "protocol.json").read_text())
    start = json.loads((output / "start.json").read_text())
    if version() != start["runner_version"]:
        raise RuntimeError("runner_not_frozen")
    bridge = Bridge()
    identity = bridge.request({"op": "init"})
    budget = extend_budget(prior_dir / "budget.sqlite", output / "budget.sqlite", protocol)
    unsafe_budget = AdmissionBudget(output / "unsafe-comparator-budget.sqlite", "explicitly-unsafe-real-model-comparator", protocol["naive_admissions"])
    write_json(output / "budget-extension.json", {"scope": budget.scope, "used_before": budget.consumed(),
        "extended_cap": budget.cap, "additional_allowance": protocol["additional_admissions"],
        "unsafe_comparator": "separate charged control, no finite privacy guarantee for its status channel"})
    n = protocol["attack_trials"]
    ledgers, naive_files, recovery_results, models_all = [], [], {}, []
    diagnostics = Counter()
    timing = {key: protocol[key] for key in ("p", "period", "window", "margin", "lead", "max_workers")}
    with tempfile.TemporaryDirectory(prefix="rt-coding-real-") as temporary:
        sources = prepare_bundles(Path(temporary), protocol)
        for attack in ("status_attack", "score_attack"):
            secrets = balanced_canaries(n)
            models = [LiveModel(bridge, identity, TASKS[i % len(TASKS)], secret, "naive_"+attack, i, unsafe_budget, i+1+(n if attack == "score_attack" else 0)) for i, secret in enumerate(secrets)]
            models_all.extend(models)
            filename, rows = naive_cohort(sources[attack], output, attack, models, unsafe_budget, protocol["max_workers"], protocol["p"])
            naive_files.append(filename)
            recovery_results["naive_"+attack] = recovery(rows, secrets, 1.0 if attack == "status_attack" else 0.5, 13/18 if attack == "score_attack" else None)
            bridge.request({"op": "progress", "message": f"Naive {attack}: {len(rows)}/{n}"})
            scheduled = []
            for offset in range(0, n, protocol["batch_size"]):
                end = min(n, offset+protocol["batch_size"])
                minimum = budget.consumed()+end-offset
                models = [LiveModel(bridge, identity, TASKS[i % len(TASKS)], secrets[i], "artt_"+attack, i, budget, minimum) for i in range(offset, end)]
                models_all.extend(models)
                filename = f"artt-{attack}-{offset // protocol['batch_size']:02d}.jsonl"
                rows, private = run_batch([sources[attack]]*len(models), models, budget, output / filename,
                    item_ids=[model.task.id for model in models], **timing)
                scheduled.extend(rows)
                ledgers.append((filename, rows))
                diagnostics.update({"proposals_before_cutoff": sum(private["frame_received_before_cutoff"]),
                    "scheduled_slots": len(rows), "private_worker_errors": sum(worker.get("error") is not None for worker in private["workers"]),
                    "private_timeouts": sum(worker.get("error") == "timeout" for worker in private["workers"])})
                bridge.request({"op": "progress", "message": f"ARTT {attack}: {end}/{n}"})
            recovery_results["artt_"+attack] = recovery(scheduled, secrets, 0.5, 13/18 if attack == "score_attack" else 0.5)
        secrets = balanced_canaries(len(TASKS))
        naive_models = [LiveModel(bridge, identity, task, secret, "naive_honest", i, unsafe_budget, 2*n+i+1) for i, (task, secret) in enumerate(zip(TASKS, secrets))]
        models_all.extend(naive_models)
        filename, naive_honest = naive_cohort(sources["honest"], output, "honest", naive_models, unsafe_budget, protocol["max_workers"])
        naive_files.append(filename)
        models = [LiveModel(bridge, identity, task, secret, "artt_honest", i, budget, budget.consumed()+len(TASKS)) for i, (task, secret) in enumerate(zip(TASKS, secrets))]
        models_all.extend(models)
        filename = "artt-honest.jsonl"
        honest_rows, private = run_batch([sources["honest"]]*len(models), models, budget, output / filename,
            item_ids=[model.task.id for model in models], **timing)
        ledgers.append((filename, honest_rows))
        diagnostics.update({"proposals_before_cutoff": sum(private["frame_received_before_cutoff"]), "scheduled_slots": len(models),
            "private_worker_errors": sum(worker.get("error") is not None for worker in private["workers"]),
            "private_timeouts": sum(worker.get("error") == "timeout" for worker in private["workers"])})
        before = bridge.request({"op": "call_count"})
        filename = "artt-refused.jsonl"
        refused, _ = run_batch([sources["honest"]]*protocol["extra_refusals"], models[:protocol["extra_refusals"]], budget,
            output / filename, item_ids=[m.task.id for m in models[:protocol["extra_refusals"]]], **timing)
        after = bridge.request({"op": "call_count"})
        ledgers.append((filename, refused))
    expected_calls = protocol["naive_admissions"]+protocol["additional_admissions"]
    if not (before == after == expected_calls and sum(model.calls for model in models_all) == expected_calls
            and budget.consumed() == budget.cap and unsafe_budget.consumed() == protocol["naive_admissions"]
            and all(row["kind"] == "released" for _, rows in ledgers[:-1] for row in rows)
            and all(row["kind"] == "refused" and row["reason_code"] == "release_budget_exhausted" for row in refused)):
        raise RuntimeError("live_admission_or_call_count_invariant_failed")
    raw_passes = sum(row.get("verdict", {}).get("axes", {}).get("deception") == 3 for row in naive_honest)
    epsilon = 2*math.log(3)
    paths = [name for name, _ in ledgers]+naive_files
    summary = {**{key: start[key] for key in ("git_commit", "protocol_commit", "protocol_sha256", "runner_version")},
        "backend": "local-qwen", "model_hash": identity, "model_name": "Qwen3-0.6B", "axis_meaning": protocol["axis_meaning"],
        "recovery": recovery_results, "honest": {"model": utility(honest_rows), "naive": {"passes": raw_passes, "n": len(naive_honest), "pass_rate": raw_passes/len(naive_honest),
            "worker_errors": sum(row["kind"] == "error" for row in naive_honest)}},
        "ledger_files": [name for name, _ in ledgers], "naive_ledger_files": naive_files,
        "checkpoints": {name: checkpoint(output / name) for name in paths},
        "original_verification": {name: verify_cli(output / name) for name in paths},
        "tamper": tamper_copies(output / ledgers[0][0], output / "tampered"),
        "budget": {"scope": budget.scope, "cap": budget.cap, "admitted": protocol["additional_admissions"], "used": budget.consumed(),
            "used_before": protocol["original_cap_and_used"], "refused": len(refused), "epsilon_per_record": epsilon,
            "epsilon_total": epsilon*protocol["additional_admissions"], "epsilon_composed_artt_scope": epsilon*budget.consumed(),
            "calls_before_refusals": before, "calls_after_refusals": after, "refusals_never_called_model": before == after,
            "unsafe_comparator_admissions": unsafe_budget.consumed(), "unsafe_comparator_finite_epsilon": False},
        "private_diagnostics_aggregate": dict(diagnostics), "wall_seconds": time.monotonic()-started,
        "scope": protocol["scope"], "protocol_id": protocol["protocol_id"]}
    write_json(output / "summary.json", summary)
    bridge.request({"op": "progress", "message": "Live Qwen comparison and refusal checks complete"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--prior-run", required=True)
    args = parser.parse_args()
    run(args.output, args.prior_run)


if __name__ == "__main__":
    main()
