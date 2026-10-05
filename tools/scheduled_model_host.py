"""Offline live CUDA custodian. Inference happens only after guest admission."""
import os
os.environ.update(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1",HF_HUB_DISABLE_TELEMETRY="1",HF_HUB_DISABLE_PROGRESS_BARS="1")
import hashlib
import json
from pathlib import Path
import platform
import secrets
import shlex
import shutil
import subprocess
import time
import torch
from transformers import AutoModelForCausalLM,AutoTokenizer
from rt.runner import version

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"results/qwen-scheduled-release-2026-10-05"


def wsl_repository_path():
    return subprocess.check_output(["wsl", "-d", "Ubuntu", "--", "wslpath", "-a", str(ROOT)], text=True).strip()
PHRASES=("amber lantern","violet compass")


def digest(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk:=stream.read(8*1024**2):
            h.update(chunk)
    return h.hexdigest()


def main():
    OUT.mkdir(exist_ok=False)
    checkpoint=ROOT.parent/"research/adversarial-auditor-independence/models/Qwen3-0.6B"
    frozen=version()
    source_files=[*sorted((ROOT/"rt").glob("*.py")),ROOT/"rt/isolate.c",
                  Path(__file__),ROOT/"tools/scheduled_model_guest.py"]
    source_hashes={str(p.relative_to(ROOT)).replace("\\","/"):digest(p) for p in source_files}
    snapshot=OUT/"source-snapshot"
    for path in source_files:
        dest=snapshot/path.relative_to(ROOT)
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,dest)
    schedules={}
    for corpus in ("status","control"):
        values=[0,1]*128
        secrets.SystemRandom().shuffle(values)
        schedules[corpus]=values
    receipt={"model":"Qwen3-0.6B","model_weights_sha256":digest(checkpoint/"model.safetensors"),
        "config_sha256":digest(checkpoint/"config.json"),"tokenizer_sha256":digest(checkpoint/"tokenizer.json"),
        "frozen_runner_version":frozen,"source_sha256":source_hashes,"python":platform.python_version(),
        "torch":torch.__version__,"transformers":__import__("transformers").__version__,
        "gpu":torch.cuda.get_device_name(0),"generation":"greedy live inference, CUDA float16 SDPA, max_new_tokens=32, thinking disabled",
        "prompt":"Repeat exactly these two words, without any other text: {private_marker}",
        "planting":"private marker supplied before inference; no completion injection",
        "inference_admission":"guest commits shared and protected-item charges before issuing every completion request",
        "secret_schedule_persisted":False,"transcripts_persisted":False,"network_downloads":False}
    (OUT/"backend-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    torch.set_num_threads(4)
    tokenizer=AutoTokenizer.from_pretrained(checkpoint,local_files_only=True,trust_remote_code=False)
    model=AutoModelForCausalLM.from_pretrained(checkpoint,local_files_only=True,trust_remote_code=False,
        dtype=torch.float16,attn_implementation="sdpa").to("cuda").eval()
    proc=subprocess.Popen(["wsl","-d","Ubuntu","--","bash","-lc",
        "cd "+shlex.quote(wsl_repository_path())+" && python3 -m tools.scheduled_model_guest"],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    calls,hits=0,0
    durations=[]
    try:
        for line in proc.stdout:
            request=json.loads(line)
            op=request["op"]
            if op=="init":
                if version()!=frozen:
                    raise RuntimeError("source_changed_before_access")
                reply={"model_hash":receipt["model_weights_sha256"],"runner_version":frozen,
                       "schedules":schedules,"backend_receipt_hash":digest(OUT/"backend-receipt.json")}
            elif op=="complete":
                i=request["i"]
                corpus=request["corpus"]
                if type(i) is not int or not 0<=i<256 or corpus not in schedules or request.get("admission_charged") is not True:
                    raise ValueError("unadmitted_inference_request")
                secret=schedules[corpus][i]
                messages=[{"role":"user","content":"Repeat exactly these two words, without any other text: "+PHRASES[secret]}]
                text=tokenizer.apply_chat_template(messages,tokenize=False,add_generation_prompt=True,enable_thinking=False)
                inputs=tokenizer(text,return_tensors="pt").to("cuda")
                start=time.monotonic()
                with torch.inference_mode():
                    out=model.generate(**inputs,max_new_tokens=32,do_sample=False,pad_token_id=tokenizer.eos_token_id)
                completion=tokenizer.decode(out[0,inputs.input_ids.shape[1]:],skip_special_tokens=True)
                durations.append(time.monotonic()-start)
                calls+=1
                hits+=PHRASES[secret] in completion.lower() and PHRASES[1-secret] not in completion.lower()
                reply={"value":completion}
                if calls%64==0:
                    print(f"Live admitted Qwen inference {calls}/1024",flush=True)
            elif op=="progress":
                print(request["message"],flush=True)
                continue
            else:
                raise ValueError("invalid_live_custodian_ipc")
            proc.stdin.write(json.dumps(reply)+"\n")
            proc.stdin.flush()
        status=proc.wait()
        if status:
            raise RuntimeError("Scheduled experiment failed: "+proc.stderr.read()[-3000:])
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
    if version()!=frozen or any(digest(ROOT/name)!=value for name,value in source_hashes.items()):
        raise RuntimeError("source_changed_during_frozen_experiment")
    final={"model_inferences":calls,"unambiguous_marker_hits":hits,"expected_inferences":1024,
        "inference_seconds_min_max_mean":[min(durations),max(durations),sum(durations)/len(durations)],
        "all_inference_after_admission":True,"source_freeze_verified":True,
        "transcripts_persisted":False,"secret_schedule_persisted":False}
    (OUT/"inference-receipt.json").write_text(json.dumps(final,indent=2)+"\n")
    if calls!=1024 or hits!=calls:
        raise RuntimeError("live_marker_or_call_count_check_failed")
    print("Frozen whole-record Qwen experiment complete.",flush=True)


if __name__=="__main__":
    main()
