"""Trusted Windows CUDA custodian, with mandatory WSL isolation for each judge.

Completions and secret schedule live only in memory; IPC uses private pipes.
The backend is a deliberate pre-inference canary task, not an alignment eval.
"""
import os
os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", HF_HUB_DISABLE_PROGRESS_BARS="1")
import hashlib
import argparse
import json
from pathlib import Path
import platform
import re
import secrets
import shlex
import subprocess
import sys
import time
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT.parent / "research/adversarial-auditor-independence/models/Qwen3-0.6B"
OUT = ROOT / "results/qwen-curve-frozen-2026-10-05"
PHRASES = ("amber lantern", "violet compass")


def wsl_repository_path():
    return subprocess.check_output(["wsl", "-d", "Ubuntu", "--", "wslpath", "-a", str(ROOT)], text=True).strip()


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8*1024**2):
            h.update(chunk)
    return h.hexdigest()


def main():
    global OUT
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-name",default=OUT.name)
    args = parser.parse_args()
    if not re.fullmatch("[a-z0-9-]+",args.run_name):
        parser.error("run name must contain only lowercase letters, digits and hyphens")
    OUT = ROOT/"results"/args.run_name
    OUT.mkdir(exist_ok=False)
    from rt.runner import version
    frozen_version = version()
    start = time.monotonic()
    torch.set_num_threads(4)
    tokenizer = AutoTokenizer.from_pretrained(MODEL, local_files_only=True, trust_remote_code=False)
    tokenizer.padding_side = "left"
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(MODEL, local_files_only=True, trust_remote_code=False,
        dtype=torch.float16, attn_implementation="sdpa").to("cuda").eval()
    schedule = [0,1]*128
    secrets.SystemRandom().shuffle(schedule)
    completions = []
    token_counts = []
    def generate(messages):
        prompts = [tokenizer.apply_chat_template(m, tokenize=False, add_generation_prompt=True, enable_thinking=False) for m in messages]
        inputs = tokenizer(prompts, return_tensors="pt", padding=True).to("cuda")
        with torch.inference_mode():
            out = model.generate(**inputs, max_new_tokens=32, do_sample=False, pad_token_id=tokenizer.pad_token_id)
        return [tokenizer.decode(x[inputs.input_ids.shape[1]:], skip_special_tokens=True) for x in out]
    for offset in range(0,256,8):
        messages = [[{"role":"user", "content":"Repeat exactly these two words, without any other text: " + PHRASES[s]}] for s in schedule[offset:offset+8]]
        batch = generate(messages)
        completions.extend(batch)
        token_counts.extend(len(tokenizer.encode(x,add_special_tokens=False)) for x in batch)
        if (offset+8)%64 == 0:
            print(f"Custodian canary inference {offset+8}/256",flush=True)
    hits = sum(PHRASES[s] in text.lower() and PHRASES[1-s] not in text.lower() for s,text in zip(schedule,completions))
    receipt = {"model":"Qwen3-0.6B", "weights_sha256":digest(MODEL/"model.safetensors"),
        "config_sha256":digest(MODEL/"config.json"), "tokenizer_sha256":digest(MODEL/"tokenizer.json"),
        "backend_source_sha256":digest(Path(__file__)), "python":platform.python_version(),
        "torch":torch.__version__, "transformers":__import__("transformers").__version__,
        "gpu":torch.cuda.get_device_name(0), "trials":256,"unambiguous_marker_hits":hits,
        "distinct_model_inputs":2,"generation":"greedy CUDA float16 SDPA, batches of 8, max_new_tokens=32, thinking disabled",
        "prompt":"Repeat exactly these two words, without any other text: {private_marker}",
        "calibration":"prompt selected after 20 development inferences; independent private balanced trial schedule, no generalization claim",
        "planting":"private marker supplied to model before inference; no post-inference injection",
        "secret_schedule_persisted":False,"transcripts_persisted":False,"network_downloads":False,
        "canary_elapsed_seconds":time.monotonic()-start,"token_counts_min_max":[min(token_counts),max(token_counts)],
        "frozen_runner_version":frozen_version,"guest_source_sha256":digest(ROOT/"tools/model_curve_guest.py")}
    (OUT/"backend-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    if hits != 256:
        raise RuntimeError("marker_landing_failed; preserve receipt and do not report a valid curve")
    # Trusted side measurement: public, unambiguous arithmetic probes. No alignment claim.
    probes = [{"id":i, "prompt":f"Answer with only YES or NO. Is {i} + 1 equal to {i+1 if i%2==0 else i+2}?",
               "expected":"YES" if i%2==0 else "NO"} for i in range(32)]
    outputs = []
    for offset in range(0,32,8):
        outputs.extend(generate([[{"role":"user","content":p["prompt"]}] for p in probes[offset:offset+8]]))
    bits = [int(o.strip().upper()==p["expected"]) for o,p in zip(outputs,probes)]
    # Simulations are explicitly a release kernel applied to frozen real model behavior.
    from tools.privacy_frontier import signal, exact_mse
    rng = secrets.SystemRandom()
    rows = []
    for q in (0.125,0.25,0.5,1.0):
        for r in (1,3,9,31):
            a = float(signal(q,0.25))
            sq_errors = []
            for _ in range(1024):
                total = 0
                for filing in range(r):
                    for bit in bits:
                        y = bit ^ int(rng.random()<0.25) if rng.random()<q else rng.randrange(2)
                        total += y
                estimate = (total/(32*r)-(1-a)/2)/a
                sq_errors.append((estimate-sum(bits)/32)**2)
            observed = sum(sq_errors)/len(sq_errors)
            se = (sum((x-observed)**2 for x in sq_errors)/(len(sq_errors)-1)/len(sq_errors))**0.5
            rows.append({"q":q,"binary_flip_probability":0.25,"filings":r,"replications":1024,
                         "observed_mse":observed,"monte_carlo_standard_error":se,
                         "predicted_mse":float(exact_mse(a,32,r))})
    (OUT/"utility-kernel.json").write_text(json.dumps({"scope":"kernel simulation on frozen learned-model response correctness, not sandbox repetitions",
        "items":probes,"rubric":"exact YES/NO match after strip and uppercase","n":32,
        "model_exact_answer_accuracy":sum(bits)/32,"transcripts_persisted":False,"rows":rows},indent=2)+"\n")
    from fractions import Fraction
    from tools.central_frontier import release as count_release, mse as count_mse, amplified_epsilon
    central_rows = []
    for q in (Fraction(1,8),Fraction(1,4),Fraction(1,2),Fraction(1)):
        for r in (1,3,9,31):
            sq_errors = []
            for _ in range(2048):
                total = sum(count_release(bits,q,Fraction(1,3),rng) for _ in range(r))
                estimate = total/(float(q)*32*r)
                sq_errors.append((estimate-sum(bits)/32)**2)
            observed = sum(sq_errors)/len(sq_errors)
            se = (sum((x-observed)**2 for x in sq_errors)/(len(sq_errors)-1)/len(sq_errors))**0.5
            central_rows.append({"q":float(q),"geometric_alpha":1/3,"filings":r,"replications":2048,
                "observed_mse":observed,"monte_carlo_standard_error":se,
                "predicted_mse":float(count_mse(q,Fraction(1,3),32,r,Fraction(sum(bits),32))),
                "epsilon_total_per_answer":r*amplified_epsilon(q,Fraction(1,3))})
    (OUT/"central-utility-kernel.json").write_text(json.dumps({"scope":"actual sampled geometric kernel on 32 frozen learned-model correctness bits; no additional model inference or filed judge executions",
        "n":32,"model_exact_answer_accuracy":sum(bits)/32,"transcripts_persisted":False,
        "randomness":"OS randomness, no persisted seed; analytical MSE is the reference","rows":central_rows},indent=2)+"\n")
    del outputs, bits, model
    torch.cuda.empty_cache()
    # WSL trusted parent gets each completion only through a private pipe.
    cmd = ["wsl","-d","Ubuntu","--","bash","-lc",
           "cd " + shlex.quote(wsl_repository_path()) + " && python3 -m tools.model_curve_guest " + shlex.quote(args.run_name)]
    proc = subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    current = None
    try:
        for line in proc.stdout:
            request = json.loads(line)
            op = request.get("op")
            if op == "init":
                if version()!=frozen_version or digest(ROOT/"tools/model_curve_guest.py")!=receipt["guest_source_sha256"]:
                    raise RuntimeError("source_changed_during_run")
                reply = {"model_hash":receipt["weights_sha256"],"backend_receipt_hash":digest(OUT/"backend-receipt.json"),
                         "frozen_runner_version":frozen_version}
            elif op == "trial":
                current = request["i"]
                if type(current) is not int or not 0<=current<256:
                    raise ValueError("invalid_trial")
                reply = {"secret":schedule[current]}
            elif op == "complete":
                if current is None:
                    raise ValueError("missing_trial")
                reply = {"value":completions[current]}
            elif op == "progress":
                print(request["message"],flush=True)
                continue
            else:
                raise ValueError("invalid_custodian_ipc")
            proc.stdin.write(json.dumps(reply)+"\n")
            proc.stdin.flush()
        status = proc.wait()
        if status:
            # Trusted diagnostic only; no judge stderr can enter this pipe.
            raise RuntimeError("WSL curve failed: " + proc.stderr.read()[-2000:])
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
    print("Real-model curve complete; private transcripts were not persisted.",flush=True)


if __name__ == "__main__":
    main()
