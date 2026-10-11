"""Windows CUDA host / Linux custodian bridge for --backend local-qwen."""
import argparse
import json
from pathlib import Path
import queue
import shlex
import subprocess
import sys
import threading
import time
from rt.bundle import sha
from rt.runner import version
from .local_model import LocalQwen, file_digest, model_files
from .run import REPO, ROOT, write_json
from .tasks import BY_ID, TASKS
from .utility_run import evidence_hashes


def frozen_sources():
    files = [*ROOT.rglob("*.py"), *ROOT.rglob("method_card.md"), *ROOT.glob("*protocol.json"), *sorted((REPO / "rt").glob("*.py")), REPO / "rt/isolate.c"]
    return {path.relative_to(REPO).as_posix(): file_digest(path) for path in sorted(files) if "__pycache__" not in path.parts}


def validate_request(request, protocol, seen):
    arm, index, task_id = request["arm"], request["index"], request["task_id"]
    if "inference_limits" in protocol:
        limit = protocol["inference_limits"].get(arm, 0)
    else:
        limit = protocol["attack_trials"] if arm in {"naive_status_attack", "artt_status_attack", "naive_score_attack", "artt_score_attack"} else len(TASKS) if arm in {"naive_honest", "artt_honest"} else 0
    if (type(index) is not int or not 0 <= index < limit or task_id != TASKS[index % len(TASKS)].id
            or request.get("admission_charged") is not True or (arm, index) in seen):
        raise ValueError("invalid_or_repeated_inference_request")
    seen.add((arm, index))
    return BY_ID[task_id]


def guest_command(output, prior_run, platform=None, filings=False):
    platform = platform or sys.platform
    args = ["-u", "-m", "demos.coding_agent.filings_run" if filings else "demos.coding_agent.real_run", "--output", str(output), "--prior-run", str(prior_run)]
    if platform == "win32":
        def linux_path(path):
            # --exec avoids WSL's default shell stripping Windows backslashes.
            return subprocess.check_output(["wsl", "--exec", "wslpath", "-a", str(path).replace("\\", "/")], text=True).strip()
        args[-3], args[-1] = linux_path(output), linux_path(prior_run)
        return ["wsl", "--exec", "bash", "-lc", "cd " + shlex.quote(linux_path(REPO)) + " && .venv/bin/python " + shlex.join(args)]
    if platform == "linux":
        return [sys.executable, *args]
    raise RuntimeError("Linux or Windows via WSL required")


def run(model_path, output, first_run, prior_run, filings=False):
    started = time.monotonic()
    protocol_name = "filings-protocol.json" if filings else "real-model-protocol.json"
    raw = (ROOT / protocol_name).read_bytes()
    if raw != subprocess.check_output(["git", "show", "HEAD:demos/coding_agent/"+protocol_name], cwd=REPO):
        raise ValueError("real model protocol must be committed unchanged before access")
    protocol = json.loads(raw)
    if len(TASKS) != protocol["task_count"] or (not filings and 2*protocol["attack_trials"]+len(TASKS) != protocol["additional_admissions"]):
        raise ValueError("protocol cohort size mismatch")
    first_run, prior_run = Path(first_run).resolve(), Path(prior_run).resolve()
    prior = json.loads((prior_run / "summary.json").read_text())
    if sha((first_run / "summary.json").read_bytes()) != protocol["first_summary_sha256"] or sha((prior_run / "summary.json").read_bytes()) != protocol["prior_summary_sha256"]:
        raise ValueError("wrong retained evidence")
    prior_used = prior["budget"]["used"] if filings else prior["budget"]["used_after"]
    if prior_used != protocol["original_cap_and_used"] or prior["runner_version"] != version():
        raise ValueError("prior allowance or runtime mismatch")
    original_hashes = {"first": evidence_hashes(first_run), "utility": evidence_hashes(prior_run)}
    sources = frozen_sources()
    if model_files(model_path) != protocol["model_files_sha256"]:
        raise ValueError("checkpoint files differ from protocol")
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "protocol.json").write_bytes(raw)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    predeclared = subprocess.check_output(["git", "log", "--diff-filter=A", "--format=%H", "--", "demos/coding_agent/"+protocol_name], cwd=REPO, text=True).strip()
    write_json(output / "start.json", {"git_commit": commit, "protocol_commit": predeclared, "protocol_sha256": sha(raw),
        "runner_version": version(), "source_sha256": sources, "prior_evidence_sha256": original_hashes})
    proc = None
    calls, seen, batches = 0, set(), []
    try:
        command = guest_command(output, prior_run, filings=filings)
        print("Loading offline Qwen3-0.6B on CUDA; no fixture fallback", flush=True)
        model = LocalQwen(model_path, protocol["generation"]["max_new_tokens"])
        if model.receipt["gpu"] != protocol["gpu"] or model.receipt["generation"] != protocol["generation"]:
            raise ValueError("inference configuration differs from protocol")
        write_json(output / "backend-receipt.json", model.receipt)
        incoming = queue.Queue()
        with (output / "guest-stderr.txt").open("w", encoding="utf-8") as errors, (output / "public-patches.jsonl").open("x", encoding="utf-8") as patches:
            proc = subprocess.Popen(command, cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, text=True, bufsize=1)
            def reader():
                try:
                    for line in proc.stdout:
                        incoming.put(json.loads(line))
                finally:
                    incoming.put(None)
            threading.Thread(target=reader, daemon=True).start()
            def reply(request, value):
                proc.stdin.write(json.dumps({"id": request["id"], "value": value})+"\n")
                proc.stdin.flush()
            pending = []
            while True:
                request = pending.pop(0) if pending else incoming.get()
                if request is None:
                    break
                op = request["op"]
                if op == "init":
                    reply(request, model.model_hash)
                elif op == "progress":
                    print(request["message"], flush=True)
                    reply(request, True)
                elif op == "call_count":
                    reply(request, calls)
                elif op == "complete":
                    group = [request]
                    until = time.monotonic()+protocol["inference_batch_wait_seconds"]
                    while len(group) < protocol["inference_batch_size"]:
                        try:
                            next_request = incoming.get(timeout=max(0.001, until-time.monotonic()))
                        except queue.Empty:
                            break
                        if next_request is not None and next_request["op"] == "complete":
                            group.append(next_request)
                        else:
                            pending.append(next_request)
                            break
                    tasks = [validate_request(item, protocol, seen) for item in group]
                    generations = model.generate_many(tasks)
                    calls += len(group)
                    batches.append({"size": len(group), "seconds": generations[0]["seconds"]})
                    for item, generated in zip(group, generations):
                        patches.write(json.dumps({"call_index": calls-len(group)+group.index(item),
                            **{key: item[key] for key in ("arm", "index", "task_id")}, "patch_sha256": sha(generated["patch"].encode()), **generated})+"\n")
                        patches.flush()
                        reply(item, generated["patch"])
                    expected = protocol.get("expected_live_inferences", protocol['naive_admissions']+protocol['additional_admissions'])
                    print(f"Live Qwen patches: {calls}/{expected}", flush=True)
                else:
                    raise ValueError("invalid_bridge_operation")
            if proc.wait() != 0:
                raise RuntimeError("Linux custodian failed; see preserved guest-stderr.txt")
        if frozen_sources() != sources or model_files(model_path) != protocol["model_files_sha256"]:
            raise RuntimeError("source_or_checkpoint_changed_during_run")
        if {"first": evidence_hashes(first_run), "utility": evidence_hashes(prior_run)} != original_hashes:
            raise RuntimeError("retained_evidence_changed")
        expected = protocol.get("expected_live_inferences", protocol["naive_admissions"]+protocol["additional_admissions"])
        if calls != expected:
            raise RuntimeError("live_call_count_mismatch")
        write_json(output / "inference-receipt.json", {"model_inferences": calls, "expected_inferences": expected,
            "batches": batches, "all_inference_after_admission": True, "source_freeze_verified": True,
            "retained_evidence_preserved_byte_for_byte": True, "private_canary_schedules_persisted": False,
            "public_patches_sha256": file_digest(output / "public-patches.jsonl"), "wall_seconds_including_model_load": time.monotonic()-started})
        print("Completed one live model cohort; original fixture evidence retained", flush=True)
    except BaseException as exc:
        write_json(output / "failure.json", {"error_type": type(exc).__name__, "completed_inferences": calls,
            "wall_seconds": time.monotonic()-started, "evidence": "Attempt preserved; replacement requires a new directory"})
        raise
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--first-run", default="scratch/coding-demo")
    parser.add_argument("--prior-run", default="scratch/coding-demo-utility")
    parser.add_argument("--filings", action="store_true", help="Execute the separately predeclared exact baseline and repeated-release supplement")
    args = parser.parse_args(argv)
    run(args.model_path, args.output, args.first_run, args.prior_run, filings=args.filings)


if __name__ == "__main__":
    main()
