"""Verify and report the useful-score crash cohort without any private access."""
import argparse
from collections import Counter
import html
import json
import math
from pathlib import Path
import shutil
import sqlite3
from rt.bundle import sha
from rt.experiment import interval
from rt.log import read as read_naive
from .accounting import model_scopes, policy_history, verify_history, budget_panel
from .design import STYLES
from .passport import export
from .review_report import load_evidence
from .run import checkpoint, write_json
from .useful_crash import predicted_recovery
from .utility_run import evidence_hashes


def validate(directory):
    summary, ledgers = load_evidence(directory)
    protocol = json.loads((directory / "protocol.json").read_text())
    receipt = json.loads((directory / "completion-receipt.json").read_text())
    if not summary["invariants_passed"] or receipt["status"] != "completed" or not receipt["prior_evidence_preserved_byte_for_byte"]:
        raise ValueError("incomplete or failed experiment")
    if sha((directory / "source-public-patches.jsonl").read_bytes()) != protocol["patch_source_sha256"]:
        raise ValueError("patch source mismatch")
    unsafe = {}
    for filename in summary["unsafe_ledger_files"]:
        unsafe[filename] = read_naive(directory / filename)
        if checkpoint(directory / filename) != summary["checkpoints"][filename] or any("release_policy" in row for row in unsafe[filename]):
            raise ValueError("unsafe comparator checkpoint or noise mismatch")
    for checks in (directory / "naive-source-records").glob("*/checkpoints.json"):
        for filename, saved in json.loads(checks.read_text()).items():
            read_naive(checks.parent / filename)
            if checkpoint(checks.parent / filename) != saved:
                raise ValueError("original comparator checkpoint mismatch")
    n, cap = protocol["trials"], protocol["cap_per_secret"]
    if len(ledgers) != 2*protocol["filings"] or any(len(rows) != n for _, rows in ledgers) or any(len(rows) != n for rows in unsafe.values()):
        raise ValueError("incomplete cohort")
    normal = unsafe["naive-normal-order-0.jsonl"]
    scores = [row.get("verdict", {}).get("axes", {"deception": 0, "sycophancy": 0}) for row in normal]
    differing = [sum(v != 0 for v in axes.values()) for axes in scores]
    if (summary["normal"]["passes"] != sum(axes["deception"] == 3 for axes in scores)
            or summary["normal"]["signature_matches"] != sum(axes["sycophancy"] == 3 for axes in scores)
            or summary["normal"]["order_zero_buckets"] != {str(k): v for k, v in Counter(tuple(axes.values()) for axes in scores).items()}):
        raise ValueError("normal-score counts mismatch")
    order_one = unsafe["naive-normal-order-1.jsonl"]
    if summary["normal"]["order_disagreements"] != sum(a.get("verdict") != b.get("verdict") or a["kind"] != b["kind"] for a, b in zip(normal, order_one)):
        raise ValueError("order diagnostic mismatch")
    for arm, points in summary["curve"].items():
        if [p["filing"] for p in points] != list(range(protocol["filings"]+1)):
            raise ValueError("missing prefix")
        for point in points:
            k = point["filing"] if arm == "uncapped" else min(point["filing"], cap)
            predicted = sum(predicted_recovery(k, d) for d in differing)/n
            if (point["n"] != n or not 0 <= point["correct"] <= n or point["rate"] != point["correct"]/n
                    or point["wilson_95"] != interval(point["correct"], n) or abs(point["predicted"]-predicted) > 1e-12
                    or point["admitted_per_trial"] != k or point["refused_per_trial"] != point["filing"]-k):
                raise ValueError("curve count, interval, or prediction mismatch")
            if point["filing"]:
                rows = dict(ledgers)[f"{arm}-filing-{point['filing']:02d}.jsonl"]
                kind = "refused" if arm == "artt" and point["filing"] > cap else "released"
                if any(row["kind"] != kind or row["policy"]["flip_probability"] != protocol["p"]
                       or row["policy"]["admission_cap"] != protocol["extended_admission_cap"] for row in rows):
                    raise ValueError("release policy or cap mismatch")
        if arm == "artt" and any(p["correct"] != points[cap]["correct"] for p in points[cap+1:]):
            raise ValueError("post-refusal decoder changed")
    primary = summary["primary"]
    if primary["after_joint"] != summary["curve"]["artt"][1]:
        raise ValueError("wrong primary endpoint")
    for key in ("before_joint", "before_status_only", "after_joint", "after_status_only"):
        p = primary[key]
        if p["n"] != n or p["rate"] != p["correct"]/n or p["wilson_95"] != interval(p["correct"], n):
            raise ValueError("primary interval mismatch")
    paired = primary["paired"]
    if (sum(paired[k] for k in ("before_only_correct", "after_only_correct", "both_correct", "both_wrong")) != n
            or paired["before_only_correct"]+paired["both_correct"] != primary["before_joint"]["correct"]
            or paired["after_only_correct"]+paired["both_correct"] != primary["after_joint"]["correct"]
            or paired["recovery_drop"] != primary["before_joint"]["rate"]-primary["after_joint"]["rate"]):
        raise ValueError("paired counts mismatch")
    budget = summary["budget"]
    for filename, expected in (("budget.sqlite", [(budget["scope"], protocol["extended_admission_cap"], protocol["extended_admission_cap"])]),
                               ("unsafe-budget.sqlite", [("unsafe-useful-crash-normal-and-exact", 3*n, 3*n)]),
                               ("item-budgets.sqlite", [(protocol["item_scope_prefix"]+str(i), cap, cap) for i in range(n)])):
        with sqlite3.connect((directory / filename).resolve().as_uri()+"?mode=ro", uri=True) as conn:
            if sorted(conn.execute("SELECT scope,cap,used FROM budgets").fetchall()) != sorted(expected):
                raise ValueError("durable budget mismatch")
    admitted = sum(row["kind"] == "released" for _, rows in ledgers for row in rows)
    refused = sum(row["kind"] == "refused" for _, rows in ledgers for row in rows)
    if (admitted != protocol["additional_admissions"] or refused != n*(protocol["filings"]-cap)
            or budget["noisy_control_admitted"] != n*protocol["filings"] or budget["capped_admitted"] != n*cap
            or budget["used_before"]+admitted != budget["used"] or budget["used"] != budget["cap"]
            or budget["epsilon_new"] != admitted*2*math.log(3) or budget["epsilon_composed"] != budget["used"]*2*math.log(3)
            or receipt["backend_accesses"] != budget["all_backend_calls"]
            or budget["all_backend_calls"] != admitted+3*n
            or budget["capped_calls_at_cap"] != n*cap or budget["capped_calls_after_refusals"] != n*cap
            or any(check["exit_code"] != 0 for check in summary["verification"].values())):
        raise ValueError("access, accounting, or verification mismatch")
    # Trial assignments were deliberately discarded. Recovery counts and paired
    # bootstrap are trusted custodian aggregates; they cannot be recounted here.
    return summary, protocol, ledgers


def plots(summary, output):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter, MaxNLocator
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "svg.fonttype": "none"})
    fig, ax = plt.subplots(figsize=(10, 3), layout="constrained")
    for y, key, color in ((1, "before_joint", "#9ca7a1"), (0, "after_joint", "#177b63")):
        p = summary["primary"][key]
        low, high = p["wilson_95"]
        ax.barh(y, p["rate"], height=.4, color=color)
        ax.errorbar(p["rate"], y, xerr=[[max(0, p["rate"]-low)], [max(0, high-p["rate"])]], color="#243b48", capsize=4)
        ax.text(1.025, y, f"{p['correct']}/{p['n']}", va="center")
    ax.set_yticks([1, 0], ["Useful-score crash, exact status + scores", "ARTT, first noisy filing"])
    ax.set_xlim(0, 1.15)
    ax.set_xticks([0, .25, .5, .75, 1])
    ax.xaxis.set_major_formatter(PercentFormatter(1))
    ax.axvline(.5, color="#809299", linestyle="--", linewidth=1)
    ax.set_xlabel("Private assertion-order recovery · Wilson 95% intervals")
    ax.spines[["top", "right", "left"]].set_visible(False)
    fig.savefig(output / "useful-crash-comparison.svg")
    fig.savefig(output / "useful-crash-comparison.png", dpi=180)
    plt.close(fig)
    fig, ax = plt.subplots(figsize=(10, 4.5), layout="constrained")
    for arm, color, label in (("uncapped", "#83958b", "Eight noisy admissions"), ("artt", "#177b63", "ARTT: four admissions")):
        ps = summary["curve"][arm]
        xs, ys = [p["filing"] for p in ps], [p["rate"] for p in ps]
        ax.plot(xs, ys, "o-", color=color, label=label)
        ax.fill_between(xs, [p["wilson_95"][0] for p in ps], [p["wilson_95"][1] for p in ps], color=color, alpha=.12)
        ax.plot(xs, [p["predicted"] for p in ps], "--", color=color, alpha=.75, label=f"Expected: {arm}")
    ax.axvspan(4.1, 8.1, color="#f0f3f1", zorder=0)
    ax.text(6, .51, "Capped arm: refusals only", ha="center", fontsize=9)
    ax.set_xlim(0, 8.1)
    ax.set_ylim(.4, 1.02)
    ax.set_xlabel("Attempted filings per fixed patch and private assignment")
    ax.set_ylabel("Recovery")
    ax.yaxis.set_major_formatter(PercentFormatter(1))
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(loc="lower right", fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    fig.savefig(output / "useful-crash-filings.svg")
    fig.savefig(output / "useful-crash-filings.png", dpi=180)
    plt.close(fig)


def numbers(s):
    p, normal, b = s["primary"], s["normal"], s["budget"]
    a, z = p["before_joint"], p["after_joint"]
    cap, last = s["curve"]["artt"][4], s["curve"]["uncapped"][-1]
    return f'''# Useful-score crash experiment

Status and scores together recover {a['correct']}/{a['n']} with exact exposed outcomes and {z['correct']}/{z['n']} ({z['rate']:.1%}) after the first ARTT release. First-release Wilson 95% interval: {z['wilson_95'][0]:.1%}–{z['wilson_95'][1]:.1%}. The expected first-release recovery is {z['predicted']:.1%} under the declared channel model.

Ordinary controls retain {normal['passes']}/{normal['n']} test passes and {normal['signature_matches']}/{normal['n']} matching signatures, including all incorrect patches. Assertion-order score disagreements: {normal['order_disagreements']}. The attack reads an executable assertion order, with no canary comment.

The paired recovery drop is {p['paired']['recovery_drop']:.1%}; paired bootstrap 95% interval {p['paired']['paired_bootstrap_95'][0]:.1%}–{p['paired']['paired_bootstrap_95'][1]:.1%}. These intervals describe this fixed replay corpus, not unseen tasks.

Four admissions give {cap['correct']}/{cap['n']} recovery; eight noisy admissions give {last['correct']}/{last['n']}. The capped arm refuses {b['refused']} later filings and its protected calls remain {b['capped_calls_at_cap']} → {b['capped_calls_after_refusals']}.

Both noisy arms cost {b['admitted']} new admissions, carrying the shared asset budget from {b['used_before']} to {b['used']}/{b['cap']}. New epsilon: {b['epsilon_new']:.4f}; conservative asset composition: {b['epsilon_composed']:.4f}. The 384 exact/public-control admissions are separately charged and have no finite privacy guarantee. The entire experimental transcript is non-private.

This is a controlled assertion-order attack using all 128 frozen public Qwen patches, zero fresh GPU generations, and a hand-written malicious judge. The attacker receives each patch's ordinary score as public side information. It does not demonstrate autonomous theft of a proprietary test suite. Recovery aggregates are trusted custodian outputs; trial labels were discarded. Prior evidence was preserved byte-for-byte.
'''


def render(s, protocol, accounting):
    e = html.escape
    p, normal, b = s["primary"], s["normal"], s["budget"]
    before, after = p["before_joint"], p["after_joint"]
    rows = "".join(f'<tr><td>{i}</td><td>{a["correct"]}/{a["n"]} ({a["rate"]:.1%})</td><td>{a["wilson_95"][0]:.1%}–{a["wilson_95"][1]:.1%}</td><td>{z["correct"]}/{z["n"]} ({z["rate"]:.1%})</td><td>{z["wilson_95"][0]:.1%}–{z["wilson_95"][1]:.1%}</td><td>{z["admitted_per_trial"]}</td><td>{z["refused_per_trial"]}</td></tr>' for i, (a, z) in enumerate(zip(s["curve"]["uncapped"], s["curve"]["artt"])))
    diagnostic_rows = "".join(f'<tr><td>{arm}</td><td>{d["filing"]}</td><td>{d["frames_before_cutoff"]}</td><td>{e(str(d["worker_errors"]))}</td><td>{d["attack_outcome_deviations"]}</td><td>{d["max_publication_jitter_seconds"]:.4f}s</td></tr>' for arm, ds in s["diagnostics"].items() for d in ds)
    links = " · ".join(f'<a href="evidence/{e(name)}">{e(name)}</a>' for name in s["ledger_files"]+s["unsafe_ledger_files"])
    paired = p["paired"]
    cap, last = s["curve"]["artt"][4], s["curve"]["uncapped"][-1]
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Useful-score crash experiment</title>{STYLES}</head><body>
<header><div class="masthead"><span class="wordmark">A Right to Test</span><span class="report-label">Committed experiment · real Qwen patch replay</span></div><h1>A crash can still leak through useful scores</h1><p class="lede">Successful evaluations retain their genuine test and signature scores. Crashes use the normal zero fallback. ARTT hides error status, but the scores still reveal information.</p><p class="context">All 128 retained patches · 48 tiny Python tasks · zero fresh GPU generations · one committed run</p><nav><a href="#result">Result</a><a href="#method">Method</a><a href="#filings">Repeated filings</a><a href="#budget">Accounting</a><a href="#evidence">Evidence</a></nav></header><main>
<section id="result"><h2>Measure everything the attacker can observe</h2><p>The same patches and private assignments recover <b>{before['correct']}/{before['n']}</b> with exposed exact outcomes and <b>{after['correct']}/{after['n']} ({after['rate']:.1%})</b> after one ARTT release. Its Wilson 95% interval is {after['wilson_95'][0]:.1%}–{after['wilson_95'][1]:.1%}.</p><figure><img src="useful-crash-comparison.svg" alt="Exact outcome and first ARTT release recovery"><figcaption>Paired observations from the complete fixed replay cohort. Whiskers are descriptive Wilson 95% intervals.</figcaption></figure><p>The predeclared channel prediction is <b>{after['predicted']:.1%}</b>, conditional on each patch's ordinary score. Hiding the status signal does not imply chance-level recovery when success and crash have different scores.</p><p>The paired drop is {paired['recovery_drop']:.1%}, with a descriptive paired bootstrap 95% interval of {paired['paired_bootstrap_95'][0]:.1%}–{paired['paired_bootstrap_95'][1]:.1%}. Discordant pairs: {paired['before_only_correct']} correct only before, {paired['after_only_correct']} correct only after. Prefixes and arms share private assignments and are correlated.</p><p class="note">The status-only decoder still gives {p['after_status_only']['correct']}/{after['n']}: admitted status is constant, so it always guesses zero on a balanced cohort. The older equal-score 64/128 experiment remains a controlled isolation of the exit channel. It is not the headline for useful-score evaluators.</p></section>
<section id="method"><h2>Keep the actual scoring behavior</h2><p>The ordinary controls pass <b>{normal['passes']}/{normal['n']}</b> hidden suites and match <b>{normal['signature_matches']}/{normal['n']}</b> declared signatures. Every pinned patch is retained, including incorrect and malformed code. Control errors for the two orders: {e(str(normal['control_errors']))}; order disagreements: {normal['order_disagreements']}.</p><p>Each secret selects the order of the first two executable hidden assertions. The malicious judge runs the existing honest rubric, reads the first assertion, and aborts for one order. On success it emits the unmodified ordinary scores. The private assignment is fixed across arms and filings. No canary comment supplies the secret.</p><p>The attacker knows both candidate assertion orders and each patch's ordinary score from a public fixed-order control. These controls contain no randomized trial assignments. The decoder accumulates maximum-likelihood evidence from all released scores, with a predeclared fixed tie coin. No secret labels or private diagnostics enter it.</p><p class="note">This remains a controlled experiment: a hand-written malicious judge, a synthetic private order, and replayed Qwen patches. It does not show autonomous attack discovery, proprietary test recovery, production exploitation, or timing noninterference. The score controls are strong explicit side information, so recovery depends on that threat model.</p></section>
<section id="filings"><h2>Repeated noisy releases retain a signal</h2><p>Four admissions give <b>{cap['correct']}/{cap['n']}</b> recovery in the capped arm. The eight-admission control gives <b>{last['correct']}/{last['n']}</b>. Observations need not increase monotonically.</p><figure><img src="useful-crash-filings.svg" alt="All nine prefixes from zero through eight attempted filings"><figcaption>Solid lines: observed recovery. Shading: pointwise Wilson intervals. Dashed lines: declared predictions. The capped extension retains its last guess after refusal.</figcaption></figure><p>ARTT refuses {b['refused']} later filings; protected calls stay <b>{b['capped_calls_at_cap']} → {b['capped_calls_after_refusals']}</b>. Durable per-secret caps and the shared allowance both expire at this point. This run does not distinguish their individual effects.</p><details><summary>All prefixes, intervals, admissions and refusals</summary><div class="scroll"><table><thead><tr><th>Attempt</th><th>Eight-admission control</th><th>95% interval</th><th>Capped arm</th><th>95% interval</th><th>Admitted / secret</th><th>Refused / secret</th></tr></thead><tbody>{rows}</tbody></table></div></details></section>
{accounting}
<section id="evidence"><h2>Execution and retained evidence</h2><p>Both noisy arms are charged: {b['noisy_control_admitted']} control releases plus {b['capped_admitted']} capped releases. The {protocol['unsafe_admissions']} unnoised/public-control admissions are separately charged. <b>The entire experimental transcript has no finite privacy guarantee.</b> The finite epsilon accounting describes only the scheduled noisy channels.</p><p>All {len(s['verification'])} merged chains and retained checkpoints verify. Comparator source chains are also checked. Recovery and bootstrap values are trusted custodian aggregates: private trial labels were discarded, so the public report cannot independently recount recovery.</p><p>Exact attack deviations: {s['exact_diagnostics']['attack_outcome_deviations']}; error counts: {e(str(s['exact_diagnostics']['error_codes']))}. Expected predictions assume the declared score behavior and on-time proposals. The diagnostics below disclose late frames, errors and deviations without excluding them.</p><details><summary>Every batch diagnostic</summary><div class="scroll"><table><thead><tr><th>Arm</th><th>Filing</th><th>Frames before cutoff</th><th>Worker errors</th><th>Outcome deviations</th><th>Max publication jitter</th></tr></thead><tbody>{diagnostic_rows}</tbody></table></div><p>These are private research diagnostics published in this deliberately non-private experiment. They are excluded from the defined attacker interface.</p></details><details><summary>Inspect all release and comparison ledgers</summary><p>{links}</p></details><p><a href="summary.json">Counts and diagnostics</a> · <a href="protocol.json">Committed protocol</a> · <a href="passport.json">Combined noisy-channel passport</a> · <a href="artifact-checks.json">Artifact verification</a> · <a href="README-numbers.md">Generated result text</a></p><p><a href="retained/report.html">Earlier complete report, unchanged</a>. All earlier evidence remains byte-for-byte intact.</p></section>
<footer>Protocol: {e(s['protocol_id'])}<br>Commit: {e(s['protocol_commit'])}<br>Protocol SHA-256: {e(s['protocol_sha256'])}<br>Software sandbox; trusted custodian; no external checkpoint witness. Execution time: {s['wall_seconds']:.1f} seconds.</footer></main></body></html>'''


def generate(directory, prior, patch_source, first, utility, retained_report, output):
    directory, prior, patch_source, first, utility, retained_report, output = map(Path, (directory, prior, patch_source, first, utility, retained_report, output))
    if output.exists():
        raise ValueError("new report directory required")
    originals = {str(p.resolve()): evidence_hashes(p) for p in (directory, prior, patch_source, first, utility, retained_report)}
    summary, protocol, ledgers = validate(directory)
    if sha((prior / "summary.json").read_bytes()) != protocol["prior_summary_sha256"] or sha((patch_source / "summary.json").read_bytes()) != protocol["patch_source_summary_sha256"]:
        raise ValueError("prior evidence commitment mismatch")
    cohorts, combined = [], []
    for label, path in (("first", first), ("utility", utility), ("qwen", patch_source), ("filings", prior), ("useful-crash", directory)):
        cohort_summary, cohort_ledgers = load_evidence(path)
        cohorts.append((label, cohort_summary, (path / "protocol.json").read_bytes(), cohort_ledgers))
        combined.extend((label+"/"+name, rows) for name, rows in cohort_ledgers)
    passport = export(combined, json.loads((first / "summary.json").read_text())["axis_meaning"],
        {summary["model_hash"]: ["software sandbox", "trusted custodian", "live and fixed public Qwen patch replay",
            "synthetic private test property", "public normal-score side information", "timing noninterference unproved"]})
    total = passport["privacy_scope_totals"][summary["budget"]["scope"]]
    if total["admitted_records"] != summary["budget"]["used"] or total["epsilon_scope_total"] != summary["budget"]["epsilon_composed"]:
        raise ValueError("combined passport accounting mismatch")
    events = policy_history(cohorts)
    names = {row["model_hash"]: "Fixture " + agent for filename, rows in cohorts[0][3] for agent in ("A", "B") if f"honest-{agent}" in filename for row in rows}
    names[summary["model_hash"]] = "Qwen3-0.6B (live and fixed-patch replay)"
    scopes = model_scopes(combined, names)
    output.mkdir(parents=True)
    (output / "policy-sources").mkdir()
    for label, _, raw, _ in cohorts:
        (output / "policy-sources" / (label+".json")).write_bytes(raw)
    (output / "policy-changes.jsonl").write_text("".join(json.dumps(event, sort_keys=True, separators=(",", ":"))+"\n" for event in events), encoding="utf-8")
    write_json(output / "policy-changes-checkpoint.json", {"entries": len(events), "last_entry_hash": events[-1]["entry_hash"]})
    verify_history(output)
    write_json(output / "model-scope-accounting.json", {"model_accounting_scopes": scopes, "shared_asset_composition": total})
    write_json(output / "passport.json", passport)
    for name in ("summary.json", "protocol.json", "completion-receipt.json", "replay-provenance.json"):
        shutil.copyfile(directory / name, output / name)
    shutil.copytree(directory, output / "evidence", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(retained_report, output / "retained")
    plots(summary, output)
    panel = budget_panel(scopes, events).replace("all three cap raises", "all four cap raises")
    panel = panel.replace("Unsafe comparison arms have no finite guarantee and are excluded from these totals.", "Both new noisy arms are included in these totals. Unnoised and status-visible comparators have no finite guarantee and are excluded.")
    (output / "report.html").write_text(render(summary, protocol, panel), encoding="utf-8")
    (output / "README-numbers.md").write_text(numbers(summary), encoding="utf-8")
    if {str(p.resolve()): evidence_hashes(p) for p in (directory, prior, patch_source, first, utility, retained_report)} != originals:
        raise RuntimeError("original evidence changed")
    write_json(output / "artifact-checks.json", {"status": "passed", "original_evidence_preserved_byte_for_byte": True,
        "all_ledgers_and_checkpoints_verified": True, "all_prefixes_and_intervals_checked": True,
        "combined_noisy_channel_accounting_verified": True, "backend_accesses": 0,
        "recovery_counts": "trusted custodian aggregates; private labels discarded"})
    print(str((output / "report.html").resolve()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--prior-run", default="scratch/coding-demo-filings")
    parser.add_argument("--patch-source", default="scratch/coding-demo-qwen-02")
    parser.add_argument("--first-run", default="scratch/coding-demo")
    parser.add_argument("--utility-run", default="scratch/coding-demo-utility")
    parser.add_argument("--retained-report", default="scratch/coding-demo-review-final-01")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    generate(args.input, args.prior_run, args.patch_source, args.first_run, args.utility_run, args.retained_report, args.output)


if __name__ == "__main__":
    main()
