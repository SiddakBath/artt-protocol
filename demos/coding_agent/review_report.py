"""Combine the retained first run with one separately predeclared utility run."""
import argparse
import json
from pathlib import Path
from rt.bundle import sha
from rt.scheduled_log import read
from .passport import export
from .report import readme_numbers, render_html
from .run import checkpoint, utility
from .utility_run import difference


def load_evidence(directory):
    directory = Path(directory)
    summary = json.loads((directory / "summary.json").read_text())
    if sha((directory / "protocol.json").read_bytes()) != summary["protocol_sha256"]:
        raise ValueError("protocol hash mismatch")
    ledgers = []
    for filename in summary["ledger_files"]:
        rows = read(directory / filename)
        if checkpoint(directory / filename) != summary["checkpoints"][filename]:
            raise ValueError("ledger checkpoint mismatch")
        ledgers.append((filename, rows))
    return summary, ledgers


def generate(first_dir, utility_dir, output):
    first_dir, utility_dir, output = map(Path, (first_dir, utility_dir, output))
    if output.resolve() in (first_dir.resolve(), utility_dir.resolve()):
        raise ValueError("review report needs a separate output directory")
    first, first_ledgers = load_evidence(first_dir)
    followup, utility_ledgers = load_evidence(utility_dir)
    if sha((first_dir / "summary.json").read_bytes()) != followup["first_summary_sha256"]:
        raise ValueError("follow-up first-run commitment mismatch")
    estimates = {agent: utility([row for filename, rows in utility_ledgers if filename.startswith(f"utility-{agent}-") for row in rows]) for agent in ("A", "B")}
    estimates["difference"] = difference(estimates["A"]["deception"], estimates["B"]["deception"])
    if estimates != followup["honest"]:
        raise ValueError("utility estimates differ from preserved ledger")
    ledgers = [("first/"+filename, rows) for filename, rows in first_ledgers]
    ledgers += [("utility/"+filename, rows) for filename, rows in utility_ledgers]
    passport = export(ledgers, first["axis_meaning"])
    total = passport["privacy_scope_totals"][first["budget"]["scope"]]
    if total["admitted_records"] != followup["budget"]["used_after"] or total["epsilon_scope_total"] != followup["budget"]["epsilon_total_including_first_run"]:
        raise ValueError("combined privacy accounting mismatch")
    summary = {**first, "utility_followup": followup}
    summary["original_verification"] = {"first/"+filename: result for filename, result in first["original_verification"].items()}
    summary["original_verification"].update({"utility/"+filename: result for filename, result in followup["original_verification"].items()})
    output.mkdir(parents=True, exist_ok=True)
    (output / "first-run-summary.json").write_bytes((first_dir / "summary.json").read_bytes())
    (output / "utility-summary.json").write_bytes((utility_dir / "summary.json").read_bytes())
    (output / "summary.json").write_text(json.dumps(summary, indent=2)+"\n", encoding="utf-8")
    (output / "passport.json").write_text(json.dumps(passport, indent=2)+"\n", encoding="utf-8")
    (output / "README-numbers.md").write_text(readme_numbers(summary), encoding="utf-8")
    (output / "report.html").write_text(render_html(summary, ledgers, passport), encoding="utf-8")
    print(str((output / "report.html").resolve()))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first-run", required=True)
    parser.add_argument("--utility-run", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    generate(args.first_run, args.utility_run, args.output)


if __name__ == "__main__":
    main()
