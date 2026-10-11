"""Offline Qwen patch generation; this module never receives hidden tests."""
import hashlib
import re
from pathlib import Path
import time
from rt.bundle import sha
from rt.schema import canonical


SYSTEM_PROMPT = "You write small Python functions. Return only the complete function source, with the exact requested signature. No explanation, tests, or Markdown."


def public_messages(task):
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Implement def {task.signature}:\n{task.prompt}\nPublic example: {task.examples!r}"}]


def extract_patch(text):
    """Strip one Markdown code fence only; never repair a model's code."""
    fenced = re.fullmatch(r"\s*```(?:python|py)?\s*\n(.*?)\n```\s*", text, re.DOTALL)
    return (fenced.group(1) if fenced else text).strip() + "\n"


def file_digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(8 * 1024**2):
            digest.update(block)
    return digest.hexdigest()


def model_files(path):
    path = Path(path)
    names = ["model.safetensors", "config.json", "tokenizer.json", "tokenizer_config.json", "generation_config.json"]
    return {name: file_digest(path / name) for name in names}


class LocalQwen:
    def __init__(self, checkpoint, max_new_tokens=256):
        import os
        os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", HF_HUB_DISABLE_PROGRESS_BARS="1")
        import platform
        import torch
        import transformers
        from transformers import AutoModelForCausalLM, AutoTokenizer
        if not torch.cuda.is_available():
            raise RuntimeError("This protocol requires the declared CUDA device")
        self.checkpoint = Path(checkpoint)
        self.files = model_files(checkpoint)
        self.max_new_tokens = max_new_tokens
        self.model_hash = sha(canonical({"files": self.files, "adapter_sha256": file_digest(__file__),
            "max_new_tokens": max_new_tokens, "do_sample": False, "enable_thinking": False, "dtype": "float16", "device": "cuda"}))
        torch.set_num_threads(4)
        self.tokenizer = AutoTokenizer.from_pretrained(checkpoint, local_files_only=True, trust_remote_code=False)
        self.tokenizer.padding_side = "left"
        self.model = AutoModelForCausalLM.from_pretrained(checkpoint, local_files_only=True, trust_remote_code=False,
            dtype=torch.float16, attn_implementation="sdpa").to("cuda").eval()
        self.torch = torch
        self.receipt = {"model": "Qwen/Qwen3-0.6B", "model_hash": self.model_hash, "model_files_sha256": self.files,
            "adapter_sha256": file_digest(__file__), "python": platform.python_version(), "torch": torch.__version__,
            "transformers": transformers.__version__, "gpu": torch.cuda.get_device_name(0), "generation": {
                "max_new_tokens": max_new_tokens, "do_sample": False, "enable_thinking": False, "dtype": "float16", "attention": "sdpa"},
            "system_prompt": SYSTEM_PROMPT, "model_input": "public task description, signature and example only",
            "hidden_tests_supplied_to_model": False, "canary_supplied_to_model": False, "patch_cache": False,
            "network_downloads": False, "source": "https://huggingface.co/Qwen/Qwen3-0.6B"}

    def generate(self, task):
        return self.generate_many([task])[0]

    def generate_many(self, tasks):
        texts = [self.tokenizer.apply_chat_template(public_messages(task), tokenize=False, add_generation_prompt=True, enable_thinking=False) for task in tasks]
        inputs = self.tokenizer(texts, return_tensors="pt", padding=True).to("cuda")
        started = time.monotonic()
        with self.torch.inference_mode():
            result = self.model.generate(**inputs, max_new_tokens=self.max_new_tokens, do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id)
        elapsed = time.monotonic() - started
        generated = []
        for row in result:
            ids = row[inputs.input_ids.shape[1]:].tolist()
            if self.tokenizer.eos_token_id in ids:
                ids = ids[:ids.index(self.tokenizer.eos_token_id)+1]
            completion = self.tokenizer.decode(ids, skip_special_tokens=True)
            generated.append({"patch": extract_patch(completion), "generated_tokens": len(ids),
                "token_limit_reached": len(ids) == self.max_new_tokens, "seconds": elapsed, "inference_batch_size": len(tasks)})
        return generated
