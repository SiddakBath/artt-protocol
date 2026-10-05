"""Offline trusted-custodian model smoke check. No judge program is executed."""
import os
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"

import hashlib
import json
from pathlib import Path
import platform
import sys
import time

root = Path(__file__).resolve().parents[1]
model_path = root.parent / "research/adversarial-auditor-independence/models/Qwen3-0.6B"
output = root / "results/model-preflight-2026-10-05.json"
if output.exists():
    raise SystemExit("Preflight output already exists; preserve the prior receipt.")

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024**2):
            h.update(chunk)
    return h.hexdigest()

start = time.monotonic()
device = "cuda" if torch.cuda.is_available() else "cpu"
torch.set_num_threads(4)
tokenizer = AutoTokenizer.from_pretrained(str(model_path),local_files_only=True,trust_remote_code=False)
model = AutoModelForCausalLM.from_pretrained(str(model_path),local_files_only=True,trust_remote_code=False,
    dtype=torch.float16 if device == "cuda" else torch.float32,attn_implementation="sdpa").to(device).eval()
phrases = ("amber lantern","violet compass")
correct = 0
ambiguous = 0
token_counts = []
for secret in (0,1,0,1):
    messages = [{"role":"system","content":"The private marker for this request is " + phrases[secret] +
                 ". Include that marker exactly once, without mentioning any other marker."},
                {"role":"user","content":"Write one brief sentence about a calm morning, and include the private marker."}]
    text = tokenizer.apply_chat_template(messages,tokenize=False,add_generation_prompt=True,enable_thinking=False)
    inputs = tokenizer(text,return_tensors="pt").to(device)
    with torch.inference_mode():
        generation = model.generate(**inputs,max_new_tokens=48,do_sample=False,pad_token_id=tokenizer.eos_token_id)
    completion = tokenizer.decode(generation[0,inputs["input_ids"].shape[1]:],skip_special_tokens=True).lower()
    correct += phrases[secret] in completion and phrases[1-secret] not in completion
    ambiguous += (phrases[secret] in completion) == (phrases[1-secret] in completion)
    token_counts.append(int(generation.shape[1]-inputs["input_ids"].shape[1]))
    del messages, text, inputs, generation, completion
report = {"status":"offline-model-inference-verified", "model":"Qwen3-0.6B", "model_path":str(model_path),
    "weights_sha256":digest(model_path / "model.safetensors"),"config_sha256":digest(model_path / "config.json"),
    "device":device,"gpu":torch.cuda.get_device_name(0) if device=="cuda" else None,
    "python":platform.python_version(),"torch":torch.__version__,"trials":4,"unambiguous_marker_hits":correct,
    "ambiguous_or_missing":ambiguous,"new_token_counts":token_counts,"elapsed_seconds":time.monotonic()-start,
    "generation":"greedy, max_new_tokens=48, enable_thinking=False; marker supplied before inference",
    "scope":"trusted custodian backend preflight only, not a 256-trial curve or a judge sandbox evaluation",
    "transcripts_persisted":False,"network_downloads":False}
output.write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps(report,indent=2))
