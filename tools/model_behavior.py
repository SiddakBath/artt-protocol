"""Registered arithmetic response utility, kept separate from canary transport."""
import os
os.environ.update(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1",HF_HUB_DISABLE_TELEMETRY="1",HF_HUB_DISABLE_PROGRESS_BARS="1")
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import secrets
import torch
from transformers import AutoModelForCausalLM,AutoTokenizer
from tools.central_frontier import release,mse

ROOT = Path(__file__).resolve().parents[1]


def main():
    out = ROOT/"results/qwen-behavior-2026-10-05"
    out.mkdir(exist_ok=False)
    protocol = {"model":"Qwen3-0.6B","n":64,"generation":"greedy CUDA float16 SDPA, batch 8, max_new_tokens=64, thinking disabled",
        "primary_rubric":"the first standalone YES or NO token, case insensitive, must match the public arithmetic answer; no matching token scores zero",
        "secondary_rubric":"strip whitespace and uppercase; whole answer must equal expected YES or NO",
        "scope":"arithmetic accuracy and formatting; no alignment or judge validity claim",
        "items":[{"id":i,"prompt":f"Is {i} + 2 equal to {i+2 if i%2==0 else i+3}? Begin your answer with YES or NO.",
                  "expected":"YES" if i%2==0 else "NO"} for i in range(100,164)]}
    registration = out/"protocol.json"
    registration.write_text(json.dumps(protocol,indent=2)+"\n")  # before any inference
    model_path = ROOT.parent/"research/adversarial-auditor-independence/models/Qwen3-0.6B"
    torch.set_num_threads(4)
    tokenizer = AutoTokenizer.from_pretrained(model_path,local_files_only=True,trust_remote_code=False)
    tokenizer.padding_side="left"
    tokenizer.pad_token=tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(model_path,local_files_only=True,trust_remote_code=False,
        dtype=torch.float16,attn_implementation="sdpa").to("cuda").eval()
    bits=[]
    parsed=0
    strict=0
    for offset in range(0,64,8):
        probes = protocol["items"][offset:offset+8]
        prompts = [tokenizer.apply_chat_template([{"role":"user","content":p["prompt"]}],tokenize=False,
                   add_generation_prompt=True,enable_thinking=False) for p in probes]
        inputs = tokenizer(prompts,return_tensors="pt",padding=True).to("cuda")
        with torch.inference_mode():
            generated=model.generate(**inputs,max_new_tokens=64,do_sample=False,pad_token_id=tokenizer.pad_token_id)
        for probe,tokens in zip(probes,generated):
            text=tokenizer.decode(tokens[inputs.input_ids.shape[1]:],skip_special_tokens=True)
            match=re.search(r"\b(YES|NO)\b",text,re.I)
            parsed+=match is not None
            bits.append(int(match is not None and match.group(1).upper()==probe["expected"]))
            strict+=text.strip().upper()==probe["expected"]
        print(f"Registered arithmetic utility {offset+8}/64",flush=True)
    del model
    torch.cuda.empty_cache()
    rng=secrets.SystemRandom()
    rows=[]
    for q in (Fraction(1,8),Fraction(1,4),Fraction(1,2),Fraction(1)):
        for r in (1,3,9,31):
            errors=[]
            for _ in range(4096):
                y=sum(release(bits,q,Fraction(1,3),rng) for _ in range(r))
                estimate=y/(float(q)*64*r)
                errors.append((estimate-sum(bits)/64)**2)
            observed=sum(errors)/len(errors)
            se=(sum((v-observed)**2 for v in errors)/(len(errors)-1)/len(errors))**0.5
            expected=float(mse(q,Fraction(1,3),64,r,Fraction(sum(bits),64)))
            rows.append({"q":float(q),"alpha":1/3,"filings":r,"replications":4096,
                         "observed_mse":observed,"predicted_mse":expected,"monte_carlo_standard_error":se,
                         "difference_in_standard_errors":(observed-expected)/se})
    report={"protocol_sha256":hashlib.sha256(registration.read_bytes()).hexdigest(),
        "backend_source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "kernel_source_sha256":hashlib.sha256((ROOT/"tools/central_frontier.py").read_bytes()).hexdigest(),
        "model_weights_sha256":json.loads((ROOT/"results/qwen-curve-frozen-2026-10-05/backend-receipt.json").read_text())["weights_sha256"],
        "model":"Qwen3-0.6B","n":64,"parsed_yes_or_no":parsed,"correct_primary":sum(bits),
        "primary_accuracy":sum(bits)/64,"strict_correct":strict,"strict_accuracy":strict/64,
        "transcripts_persisted":False,"individual_scores_persisted":False,
        "model_inferences":64,"kernel_replications_per_point":4096,
        "scope":"64 fresh model inferences; subsequent replications are exact rational-coin release-kernel experiments, not additional model executions or sandbox trials",
        "rows":rows}
    (out/"results.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"primary_correct":sum(bits),"strict_correct":strict,"n":64,
        "parsed_yes_or_no":parsed,"max_abs_standardized_difference":max(abs(r["difference_in_standard_errors"]) for r in rows)}))


if __name__=="__main__":
    main()
