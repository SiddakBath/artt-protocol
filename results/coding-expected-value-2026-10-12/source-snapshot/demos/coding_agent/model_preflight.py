"""Public-task timing smoke check, separate from the reported private run."""
import argparse
import time
from pathlib import Path
from .local_model import LocalQwen
from .run import write_json
from .tasks import TASKS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    try:
        print("Loading offline Qwen3-0.6B on CUDA", flush=True)
        model = LocalQwen(args.model_path)
        write_json(output / "backend-receipt.json", model.receipt)
        rows = []
        for index in (0, 40):
            generated = model.generate(TASKS[index])
            rows.append({"task_id": TASKS[index].id, **generated})
            write_json(output / f"public-{index}.json", rows[-1])
            print(f"Public timing task {TASKS[index].id}: {generated['seconds']:.2f}s, {generated['generated_tokens']} tokens", flush=True)
        batch = model.generate_many([TASKS[index] for index in (0, 6, 31, 40)])
        write_json(output / "public-batch.json", batch)
        print(f"Public batch of four: {batch[0]['seconds']:.2f}s total", flush=True)
        write_json(output / "summary.json", {"scope": "two public timing tasks; no hidden-test scoring or canary recovery",
            "rows": rows, "wall_seconds": time.monotonic()-started})
    except BaseException as exc:
        write_json(output / "failure.json", {"error_type": type(exc).__name__, "wall_seconds": time.monotonic()-started})
        raise


if __name__ == "__main__":
    main()
