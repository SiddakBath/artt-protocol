"""Read-only verification of retained research artifacts; write a new receipt.

This verifies local integrity and reproducible arithmetic, not ground truth
whose private schedule was discarded, external registration, or attestation.
No model inference, native compilation, network, or untrusted code execution.
"""
import argparse
from collections import Counter
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import statistics

from rt.log import read as legacy_read
from rt.runner import version
from rt.scheduled_log import read as scheduled_read
from rt.schema import strict_json
from tools import central_frontier as count
from tools import privacy_frontier as binary
from tools.utility_bounds import analyze

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(8*1024*1024):
            hasher.update(data)
    return hasher.hexdigest()


def require(condition, description):
    if not condition:
        raise ValueError(description)


def close(actual, expected):
    require(math.isclose(actual, float(expected), abs_tol=1e-12, rel_tol=1e-12), "analytical_result_mismatch")


def snapshot_version(root):
    runtime = root / "rt"
    files = sorted([*runtime.glob("*.py"), runtime / "isolate.c"])
    return hashlib.sha256(b"".join(path.name.encode()+path.read_bytes() for path in files)).hexdigest()


def tex_structure(path):
    text = path.read_text(encoding="utf-8")
    active = re.sub(r"(?<!\\)%[^\n]*", "", text)
    stack = []
    for match in re.finditer(r"\\(begin|end)\{([^}]+)\}", active):
        action, name = match.groups()
        if action == "begin":
            stack.append(name)
        else:
            require(stack and stack.pop() == name, "unbalanced_tex_environment")
    require(not stack, "unclosed_tex_environment")
    braces = 0
    for match in re.finditer(r"(?<!\\)[{}]", active):
        braces += 1 if match.group() == "{" else -1
        require(braces >= 0, "unbalanced_tex_brace")
    require(braces == 0, "unclosed_tex_brace")
    labels = re.findall(r"\\label\{([^}]+)\}", active)
    refs = re.findall(r"\\(?:ref|eqref|autoref)\{([^}]+)\}", active)
    require(len(labels) == len(set(labels)) and set(refs) <= set(labels), "unresolved_or_duplicate_tex_reference")
    require("@@" not in text and "\\smallSubmitter" not in text and "\\raggedrightrefused" not in text, "tex_template_or_macro_error")
    figures = re.findall(r"\\includegraphics(?:\[[^\]]*\])?\{([^}]+)\}", active)
    expected_figures = {"privacy-utility-filings.png", "qwen-utility-check.png", "leakage-utility.png"}
    require(set(figures) == expected_figures, "unexpected_figure_assets")
    require(all((path.parent / "figures" / figure).is_file() for figure in figures), "missing_figure_asset")
    require(not re.search(r"\\(?:input|include|bibliography)\b", active), "unexpected_external_tex_dependency")
    return {"environment_and_brace_balance": True, "references_resolve": True,
        "external_project_files_required": True, "semantic_compilation_or_layout_verified": False}


def is_curve_summary(path):
    return path.parent.name.startswith("multibit-") and path.name in {"capped-curves.jsonl", "uncapped-curves.jsonl"}


def audit_multibit(study):
    """Verify counts and arithmetic without pretending discarded labels are recoverable."""
    report = json.loads((study / "results.json").read_text())
    arms = {}
    for label in ("uncapped", "capped"):
        if label not in report:
            continue
        arm = report[label]
        path = study / f"{label}-curves.jsonl"
        raw = path.read_bytes()
        require(raw.endswith(b"\n"), "incomplete_multibit_summary")
        rows = [strict_json(line) for line in raw.splitlines()]
        require(len(rows) == arm["trials"], "multibit_trial_count_mismatch")
        require([row["curve"] for row in rows] == arm["curves"], "multibit_saved_curve_mismatch")
        admitted = arm["admissions"]
        for trial, row in enumerate(rows):
            curve = row["curve"]
            require(row["trial"] == trial and len(curve) == admitted + 1 and
                    all(type(value) is int and 0 <= value <= 16 for value in curve), "invalid_multibit_curve")
            if "bits_at_end" in row or "bits_at_16" in row:
                require(row["bits_at_end"] == curve[-1] and row["bits_at_16"] == curve[min(16, admitted)], "multibit_endpoint_mismatch")
            prefix = f"{label}-{trial:02d}"
            rounds = sorted(study.glob(prefix + "-round-*.jsonl"), key=lambda p: int(p.stem.rsplit("-", 1)[1]))
            entries = [entry for log in rounds for entry in scheduled_read(log)]
            require(len(entries) == admitted and all(entry["kind"] == "released" for entry in entries), "multibit_release_count_mismatch")
            require(all(entry["policy"]["admission_cap"] == arm["cap"] for entry in entries), "multibit_log_cap_mismatch")
            refused = scheduled_read(study / (prefix + "-refusals.jsonl"))
            require(refused and all(entry["kind"] == "refused" and entry["reason_code"] == "release_budget_exhausted" for entry in refused), "multibit_refusal_mismatch")
            with sqlite3.connect((study / (prefix + ".sqlite")).resolve().as_uri() + "?mode=ro", uri=True) as connection:
                budgets = connection.execute("SELECT scope,cap,used FROM budgets").fetchall()
            require(budgets == [("sixteen-bit-corpus", arm["cap"], admitted)], "multibit_budget_mismatch")
            if "axis_total" in row:
                require(row["axis_total"] == 2 * admitted and type(row["axis_mismatch"]) is int
                        and 0 <= row["axis_mismatch"] <= row["axis_total"], "multibit_axis_count_mismatch")
        for index in range(admitted + 1):
            column = [row["curve"][index] for row in rows]
            close(arm["mean_bits"][index], statistics.fmean(column))
            close(arm["stderr_bits"][index], statistics.stdev(column) / math.sqrt(len(column)) if len(column) > 1 else 0)
        arms[label] = {"trials": len(rows), "admissions": admitted,
                       "mean_at_end": arm["mean_bits"][-1], "stderr_at_end": arm["stderr_bits"][-1],
                       "axis_mismatch": sum(row["axis_mismatch"] for row in rows) if all("axis_mismatch" in row for row in rows) else None,
                       "axis_total": sum(row["axis_total"] for row in rows) if all("axis_total" in row for row in rows) else None}
    return {"study": study.name, "arms": arms,
            "scope": "ledger integrity, retained budget counts and summary arithmetic; ground-truth correctness and historical excluded attempts are not independently verified"}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    output = Path(args.output)
    require(not output.exists(), "new_audit_receipt_required")
    chains = []
    for path in sorted((ROOT / "results").rglob("*.jsonl")):
        if is_curve_summary(path):
            continue  # Validated as summaries below, never silently treated as public chains.
        raw = path.read_bytes()
        first = strict_json(raw.splitlines()[0]) if raw else {}
        is_v2 = first.get("schema") == "rt.release.v2"
        entries = scheduled_read(path) if is_v2 else legacy_read(path)
        require(not any(marker in raw.lower() for marker in (b"amber lantern", b"violet compass")), "canary_text_in_public_chain")
        chains.append({"file": path.relative_to(ROOT).as_posix(), "entries": len(entries),
            "schema": "v2" if is_v2 else "v1", "kinds": dict(Counter(entry["kind"] for entry in entries)),
            "runner_versions": sorted(set(entry["runner_version"] for entry in entries)),
            "sha256": digest(path), "last_entry_hash": entries[-1]["entry_hash"] if entries else None})
    freezes = []
    for name in ("qwen-scheduled-release-2026-10-05", "qwen-scheduled-utility-2026-10-05"):
        study = ROOT / "results" / name
        receipt = json.loads((study / "backend-receipt.json").read_text())
        for relative, expected in receipt["source_sha256"].items():
            require(digest(study / "source-snapshot" / relative) == expected, "frozen_source_snapshot_mismatch")
        require(snapshot_version(study / "source-snapshot") == receipt["frozen_runner_version"], "frozen_runner_identity_mismatch")
        freezes.append({"study": name, "snapshot_files": len(receipt["source_sha256"]), "runner_version": receipt["frozen_runner_version"], "verified": True,
            "current_source_claim": "The archived snapshot, not the evolving release tree, identifies the executed study."})
    checkpoint = ROOT.parent / "research/adversarial-auditor-independence/models/Qwen3-0.6B"
    main_study = ROOT / "results/qwen-scheduled-utility-2026-10-05"
    receipt = json.loads((main_study / "backend-receipt.json").read_text())
    model_files = ("model.safetensors", "config.json", "tokenizer.json")
    if all((checkpoint / name).is_file() for name in model_files):
        assets = {name: digest(checkpoint / name) for name in model_files}
        for name, key in (("model.safetensors", "model_weights_sha256"), ("config.json", "config_sha256"), ("tokenizer.json", "tokenizer_sha256")):
            require(assets[name] == receipt[key], "local_model_asset_mismatch")
        current_checkpoint_manifest = [{"file": path.name, "bytes": path.stat().st_size,
            "sha256": assets.get(path.name) or digest(path)} for path in sorted(checkpoint.iterdir()) if path.is_file()]
        checkpoint_status = "verified"
    else:
        assets = None
        current_checkpoint_manifest = []
        checkpoint_status = "unavailable: optional local checkpoint is not present"
    frontier = json.loads((ROOT / "results/central-frontier-2026-10-05/results.json").read_text())
    for row in frontier["rows"]:
        q, alpha, r = Fraction(row["q"]), Fraction(1, 3), row["filings"]
        require(Fraction(row["answer_recovery_exact_fraction"]) == count.exact_accuracy(q, alpha, r), "count_recovery_fraction_mismatch")
        close(row["epsilon_per_answer_total"], r*count.amplified_epsilon(q, alpha))
        close(row["mean_mse_at_mean_half"], count.mse(q, alpha, row["n"], r, Fraction(1, 2)))
        close(row["worst_case_mean_mse"], count.mse(q, alpha, row["n"], r, 1))
        close(row["answer_mi_bits"], count.exact_mi(q, alpha, r))
    binary_data = json.loads((ROOT / "results/privacy-frontier-2026-10-05/results.json").read_text())
    for row in binary_data["rows"]:
        a = binary.signal(Fraction(row["q"]), Fraction(row["binary_flip_probability"]))
        r = row["filings"]
        require(Fraction(row["answer_recovery_exact_fraction"]) == binary.exact_accuracy(a, r), "binary_recovery_fraction_mismatch")
        close(row["epsilon_per_answer_total"], r*binary.epsilon(a))
        close(row["mean_mse"], binary.exact_mse(a, row["n"], r))
        close(row["answer_mi_bits"], binary.mutual_information(a, r))
    behavior = json.loads((ROOT / "results/qwen-behavior-2026-10-05/results.json").read_text())
    for row in behavior["rows"]:
        close(row["predicted_mse"], count.mse(Fraction(row["q"]), Fraction(1, 3), behavior["n"], row["filings"], Fraction(behavior["correct_primary"], behavior["n"])))
        close(row["difference_in_standard_errors"], (row["observed_mse"]-row["predicted_mse"])/row["monte_carlo_standard_error"])
    report = json.loads((main_study / "results.json").read_text())
    inference = json.loads((main_study / "inference-receipt.json").read_text())
    require(inference["model_inferences"] == inference["unambiguous_marker_hits"] == 1536 and inference["source_freeze_verified"], "incomplete_model_receipt")
    require(report["backend_receipt_hash"] == digest(main_study / "backend-receipt.json"), "backend_receipt_link_mismatch")
    for row in report["phases"]:
        entries = scheduled_read(main_study / row["log"])
        require(len(entries) == row["public_released"] == 256 and all(entry["kind"] == "released" for entry in entries), "main_study_shape_or_count_mismatch")
        require(all(entry["runner_version"] == receipt["frozen_runner_version"] for entry in entries), "main_log_runner_mismatch")
        close(row["score_recovery"], row["score_decoder_correct"]/256)
        require(row["status_decoder_correct"] == 128, "constant_status_count_mismatch")
    budget_states = {}
    for filename in ("admissions.sqlite", "items.sqlite"):
        with sqlite3.connect((main_study / filename).as_uri()+"?mode=ro", uri=True) as connection:
            rows = connection.execute("SELECT scope,cap,used FROM budgets ORDER BY scope").fetchall()
        require(all(0 <= used <= cap for _, cap, used in rows), "invalid_retained_budget")
        budget_states[filename] = {"scopes": len(rows), "admissions": sum(row[2] for row in rows)}
        if filename == "admissions.sqlite":
            require({scope: used for scope, _, used in rows} == {"status-protected-corpus": 1024, "control-protected-corpus": 256, "open-protected-corpus": 256}, "corpus_budget_mismatch")
        else:
            require(len(rows) == 768 and all(cap == used == (4 if scope.startswith("status:") else 1) for scope, cap, used in rows), "item_budget_mismatch")
    prior_analysis = json.loads((main_study / "same-run-analysis.json").read_text())
    for row in prior_analysis["chains"]:
        require(digest(main_study / row["file"]) == row["sha256"], "retained_analysis_chain_mismatch")
    bounds = analyze(main_study)
    baseline_bounds = ROOT / "results/research-audit-2026-10-05/utility-bounds.json"
    require(bounds == json.loads(baseline_bounds.read_text()), "conservative_utility_analysis_mismatch")
    tex = tex_structure(ROOT / "paper/draft.tex")
    checks = {"count_surface_rows": len(frontier["rows"]), "binary_surface_rows": len(binary_data["rows"]),
        "real_model_count_kernel_points": len(behavior["rows"]), "main_study_receipt_inferences": 1536,
        "main_study_chains": 7, "main_study_entries": 1538, "retained_budgets": budget_states,
        "tex_structure": tex,
        "multibit_studies": [audit_multibit(study) for study in sorted((ROOT / "results").glob("multibit-*"))
                            if (study / "results.json").exists()]}
    manifest = []
    for folder in ("rt", "tools", "tests", "judges", "examples", "fixtures", "vectors", "paper", "results"):
        for path in sorted((ROOT / folder).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and output.parent.resolve() not in path.resolve().parents and path.suffix not in (".pyc", ".lock"):
                manifest.append({"file": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size, "sha256": digest(path)})
    for name in ("README.md", "DECISIONS.md", "LICENSE", "CITATION.cff", "pyproject.toml", "requirements-test.txt", "requirements-runtime.txt"):
        path = ROOT / name
        if path.exists():
            manifest.append({"file": name, "bytes": path.stat().st_size, "sha256": digest(path)})
    result = {"scope": "local final integrity, arithmetic and source-readiness audit; no new inference or PDF build",
        "passed": True, "runner_version": version(), "chains": chains,
        "total_chains": len(chains), "total_entries": sum(row["entries"] for row in chains),
        "frozen_source_snapshots": freezes, "local_model_assets": assets,
        "local_model_asset_status": checkpoint_status, "recomputed_checks": checks,
        "current_checkpoint_manifest": current_checkpoint_manifest,
        "checkpoint_manifest_scope": "All current checkpoint files are hashed at final audit. Only weights, config.json and tokenizer.json have a historical hash in the main inference receipt; auxiliary-file identity is not backdated to registration.",
        "audit_input_hashes": {name: digest(output.parent / name) for name in ("utility-bounds.json", "test-receipt.json", "native-diagnostic.json") if (output.parent / name).exists()},
        "limitations": ["Ground-truth recovery counts and timings are trusted local aggregate receipts; discarded private schedules cannot be independently redecoded.",
            "Hashes are integrity commitments, not hardware attestation or independent preregistration.",
            "Physical timing, availability, hostile ledger rollback and shared-queue locality remain stated assumptions or unproved extensions.",
            "This audit does not compile or assess PDF layout; use a separate build receipt for those checks."],
        "artifact_manifest": sorted(manifest, key=lambda row: row["file"])}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2, allow_nan=False)+"\n")
    print(json.dumps({"passed": True, "chains": result["total_chains"], "entries": result["total_entries"], "artifacts": len(manifest), "checks": checks}, indent=2))


if __name__ == "__main__":
    main()
