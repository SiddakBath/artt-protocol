"""Local artifact check and completion receipt, excluded from Git."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
sys.path.insert(0, str(Path.cwd()))
from rt.bundle import sha
from rt.schema import canonical
from rt.scheduled_log import read
from demos.coding_agent.report import readme_numbers, render_html
from demos.coding_agent.run import checkpoint, write_json
from demos.coding_agent.passport import export

root = Path.cwd()
out = root / "scratch/coding-demo"
summary = json.loads((out / "summary.json").read_text())
protocol = (out / "protocol.json").read_bytes()
assert sha(protocol) == summary["protocol_sha256"]
assert protocol == (root / "demos/coding_agent/protocol.json").read_bytes()
ledgers = [(filename, read(out / filename)) for filename in summary["ledger_files"]]
passport = json.loads((out / "passport.json").read_text())
assert passport == export(ledgers, summary["axis_meaning"])
assert (out / "report.html").read_text() == render_html(summary, ledgers, passport)
assert (out / "README-numbers.md").read_text() == readme_numbers(summary)
assert readme_numbers(summary) in (root / "README.md").read_text()
released = [row for _, rows in ledgers for row in rows if row["kind"] == "released"]
refused = [row for _, rows in ledgers for row in rows if row["kind"] == "refused"]
assert len(released) == summary["budget"]["admitted"] == 352
assert len(refused) == summary["budget"]["refused"] == 8
assert all(set(row) == set(released[0]) for row in released)
assert all(row["reason_code"] == "release_budget_exhausted" for row in refused)
assert summary["budget"]["calls_before_refusals"] == summary["budget"]["calls_after_refusals"]
assert all(value["exit_code"] == 0 for value in summary["original_verification"].values())
for filename, rows in ledgers:
    assert checkpoint(out / filename) == summary["checkpoints"][filename]
for path in out.glob("*.jsonl"):
    assert all(marker not in path.read_bytes().lower() for marker in (b"amber lantern", b"violet compass"))
with sqlite3.connect(out / "budget.sqlite") as connection:
    assert connection.execute("SELECT scope,cap,used FROM budgets").fetchall() == [("coding-demo-corpus", 352, 352)]
tests = (root / "scratch/coding-demo-tests.txt").read_text().strip()
assert "94 passed" in tests
audit = json.loads((root / "scratch/audit-after-demo.json").read_text())
assert audit["passed"]
tip = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
commits = subprocess.check_output(["git", "log", "-5", "--oneline"], text=True)
added = subprocess.check_output(["git", "diff", "--name-only", "--diff-filter=A", "5e158b9", "HEAD"], text=True).splitlines()
screens = sorted(path.name for path in (out / "screens").glob("*.jpg"))
checks = {"passed": True, "released_fixed_shapes": len(released), "refusals": len(refused), "report_matches_summary_and_ledgers": True, "readme_matches_generated_numbers": True, "passport_matches_ledgers": True, "budget_matches_sqlite": True, "canaries_absent_from_public_ledgers": True, "checkpoints_match": True, "full_suite": tests.splitlines()[-1], "research_audit_passed": audit["passed"], "final_commit": tip, "screenshots": screens}
write_json(out / "artifact-checks.json", checks)
lines = ["# Coding-agent demo completion receipt", "", "Branch: `demo/coding-agent` in `C:/src/experimentation/right-to-test`.", "", "Local commits:", "", "```text", commits.strip(), "```", "", "Added files:", ""]
lines.extend("- " + name for name in added)
lines.extend(["", "Modified: `README.md`. The existing uncommitted edit to `paper/draft.tex` was left untouched. No push, merge, tag, publication, version change or model download.", "", "Commands run from the repository root in WSL (invoked through `wsl -- bash -lc`):", "", "```bash", ".venv/bin/python -m rt.build_sandbox", "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_coding_agent_demo.py", "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_coding_agent_demo.py -k 'not live'", "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q -p no:cacheprovider | tee scratch/coding-demo-tests.txt", "make demo | tee scratch/coding-demo-run-console.txt", ".venv/bin/python -m tools.research_audit --output scratch/audit-after-demo.json", ".venv/bin/python scratch/coding-demo/check_and_receipt.py", "```", "", "`make demo` executes:", "", "```bash", ".venv/bin/python -m demos.coding_agent.run --output scratch/coding-demo", ".venv/bin/python -m demos.coding_agent.report --input scratch/coding-demo --html scratch/coding-demo/report.html", "```", "", "The single reported run took " + repr(summary["wall_seconds"]) + " seconds, measured by the runner from before protocol validation through final verification and passport export. Report rendering and browser QA are additional. No full run was repeated.", "", "Full regression output:", "", "```text", tests, "```", "", "The unchanged research audit passed with " + str(audit["total_chains"]) + " chains and " + str(audit["total_entries"]) + " entries. It validates retained research artifacts, not this demo's discarded private canary schedule. `artifact-checks.json` checks this demo's public artifacts separately.", "", "Observed values copied from summary.json:", "", "```json", json.dumps({key: summary[key] for key in ("recovery", "honest", "raw_fixture_pass_rates", "budget", "tamper", "protocol_sha256", "protocol_commit", "git_commit", "runner_version", "wall_seconds")}, indent=2), "```", "", "Browser QA: search for refused returned 8 rows; opening record 352 showed its refusal; Show more rows displayed 45 of 360; hash search found one released record; the tamper toggle showed the observed INVALID/INVALID/VERIFIED results and checkpoint states. No browser console warnings or errors were observed.", "", "Screenshots:", ""])
lines.extend("- `screens/" + name + "`" for name in screens)
lines.extend(["", "Deviations and limitations:", "", "- User approved a 2.5-second worker window and 2.55-second lead to accommodate the required integer 2-second bundle limit. The protocol predeclared 128 attack trials and a 0.1-second slot period before execution.", "- Runtime was 151.464473214 seconds, over the approximately two-minute target. No cohort was reduced or repeated afterwards.", "- The honest difference interval includes zero. The recorded point estimates reflect the fixture difference, but this sample does not establish statistical separation.", "- The first small test run had two assertion failures: an edited middle row retains the head checkpoint, and JSON key order affected a report equality check. Those were corrected before the full run; the full suite passed.", "- Each scheduled batch is its own chain. Chain validation and retained head checkpoints are complementary. A suffix-deleted chain verifies alone and fails its retained checkpoint comparison. No external witness is deployed.", "- The offline report is roughly 1 MB and remains ignored under scratch. No showcase copy was committed or published.", "- Fixture source and hidden-check design are public for reproducibility. Private trial assignments are generated in memory, then discarded. The recovery totals are trusted custodian aggregates.", "- The fixture rates, trusted custody, one-call scope and software sandbox do not demonstrate learned-model performance or hardware attestation. Timing noninterference is not proven.", ""])
(out / "completion.md").write_text("\n".join(lines), encoding="utf-8")
print(json.dumps(checks, indent=2))
