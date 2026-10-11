"""Add honest score baselines and filing curves without replacing old evidence."""
import argparse
import html
import json
from pathlib import Path
import shutil
import sqlite3
from rt.bundle import sha
from rt.experiment import interval
from rt.log import read as read_naive
from .filings_run import prediction
from .passport import export
from .report import metric
from .review_report import load_evidence
from .run import checkpoint, write_json
from .utility_run import evidence_hashes


def validate(directory, prior):
    summary, ledgers = load_evidence(directory)
    protocol = json.loads((directory / "protocol.json").read_text())
    inference = json.loads((directory / "inference-receipt.json").read_text())
    patches = [json.loads(line) for line in (directory / "public-patches.jsonl").read_text().splitlines()]
    if (inference["model_inferences"] != protocol["expected_live_inferences"] or len(patches) != inference["model_inferences"]
            or sha((directory / "public-patches.jsonl").read_bytes()) != inference["public_patches_sha256"]
            or {(row["arm"], row["index"]) for row in patches} != {("exact_score_attack", i) for i in range(protocol["attack_trials"])}
            or any(sha(row["patch"].encode()) != row["patch_sha256"] for row in patches)):
        raise ValueError("fresh baseline patch receipt mismatch")
    if sha((prior / "summary.json").read_bytes()) != protocol["prior_summary_sha256"] or sha((prior / "public-patches.jsonl").read_bytes()) != protocol["public_patches_sha256"]:
        raise ValueError("retained Qwen evidence mismatch")
    for filename in summary["unsafe_ledger_files"]:
        unsafe_rows = read_naive(directory / filename)
        if filename == "naive-exact-score-attack.jsonl" and any("release_policy" in row for row in unsafe_rows):
            raise ValueError("exact baseline has noise policy")
        if checkpoint(directory / filename) != summary["checkpoints"][filename]:
            raise ValueError("unsafe checkpoint mismatch")
    for checks in [*(directory / "naive-source-records").glob("*/checkpoints.json"), *(directory / "uncapped-source-records").glob("*/checkpoints.json")]:
        for filename, saved in json.loads(checks.read_text()).items():
            read_naive(checks.parent / filename)
            if checkpoint(checks.parent / filename) != saved:
                raise ValueError("source checkpoint mismatch")
    for arm, points in summary["curve"].items():
        if [point["filing"] for point in points] != list(range(protocol["filings"]+1)):
            raise ValueError("missing curve prefix")
        for point in points:
            n, k = point["n"], point["filing"]
            admitted = k if arm == "uncapped" else min(k, protocol["cap_per_secret"])
            refused = 0 if arm == "uncapped" else max(0, k-protocol["cap_per_secret"])
            if (n != protocol["repeated_trials"] or point["rate"] != point["correct"]/n or point["wilson_95"] != interval(point["correct"], n)
                    or point["admitted_per_trial"] != admitted or point["refused_per_trial"] != refused or point["predicted"] != prediction(admitted)):
                raise ValueError("curve count, interval or prediction mismatch")
    cap = protocol["cap_per_secret"]
    for index, (_, rows) in enumerate(ledgers):
        if len(rows) != protocol["repeated_trials"] or any(row["kind"] != ("released" if index < cap else "refused") for row in rows):
            raise ValueError("cap ledger mismatch")
    if any(point["correct"] != summary["curve"]["artt"][cap]["correct"] for point in summary["curve"]["artt"][cap+1:]):
        raise ValueError("post-cap decoder changed")
    budget = summary["budget"]
    with sqlite3.connect((directory / "budget.sqlite").resolve().as_uri()+"?mode=ro", uri=True) as connection:
        if connection.execute("SELECT scope,cap,used FROM budgets").fetchall() != [(budget["scope"], budget["cap"], budget["used"])]:
            raise ValueError("budget state mismatch")
    if not (budget["protected_replay_calls_at_cap"] == budget["protected_replay_calls_after_refusals"] == protocol["additional_admissions"]
            and budget["refused"] == (protocol["filings"]-cap)*protocol["repeated_trials"]
            and all(value == cap for value in budget["item_consumption"])):
        raise ValueError("cap call receipt mismatch")
    if any(result["exit_code"] != 0 for result in summary["verification"].values()):
        raise ValueError("chain verification failed")
    return summary, protocol, ledgers


def plots(summary, retained, output):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter, MaxNLocator
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "svg.fonttype": "none"})
    orange, teal = "#d97860", "#278982"
    baseline, protected = summary["exact_baseline"]["score"], retained["recovery"]["artt_score_attack"]["score"]
    fig, ax = plt.subplots(figsize=(10, 2.7), layout="constrained")
    for y, point, color in ((1, baseline, orange), (0, protected, teal)):
        low, high = point["wilson_95"]
        ax.barh(y, point["rate"], height=0.38, color=color)
        ax.errorbar(point["rate"], y, xerr=[[point["rate"]-low], [high-point["rate"]]], color="#243b48", capsize=4)
        ax.text(1.025, y, f"{point['correct']}/{point['n']}", va="center")
    ax.set_yticks([1, 0], ["New exact-score baseline\n128 fresh Qwen generations", "ARTT noisy score release\nretained first live cohort"])
    ax.set_xlim(0, 1.14)
    ax.set_ylim(-0.55, 1.55)
    ax.set_xticks([0, .25, .5, .75, 1])
    ax.xaxis.set_major_formatter(PercentFormatter(1))
    ax.axvline(.5, color="#809299", linestyle="--", linewidth=1)
    ax.set_xlabel("Private-bit recovery (Wilson 95% intervals)")
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    fig.savefig(output / "exact-baseline.svg")
    fig.savefig(output / "exact-baseline.png", dpi=180)
    plt.close(fig)
    cap = summary["budget"]["cap_per_secret"]
    fig, (ax, lower) = plt.subplots(2, 1, figsize=(10, 7), sharex=True, height_ratios=[3, 1.25], layout="constrained")
    for arm, color, label in (("uncapped", orange, "Uncapped noisy releases"), ("artt", teal, f"ARTT: cap {cap}")):
        points = summary["curve"][arm]
        shown = points if arm == "uncapped" else points[:cap+1]
        xs, ys = [p["filing"] for p in shown], [p["rate"] for p in shown]
        ax.plot(xs, ys, "o-", color=color, linewidth=2.4, label=label)
        ax.fill_between(xs, [p["wilson_95"][0] for p in shown], [p["wilson_95"][1] for p in shown], color=color, alpha=.12)
        ax.plot(xs, [p["predicted"] for p in shown], "--", color=color, alpha=.7, linewidth=1, label=f"{arm.upper()} prediction")
    plateau = summary["curve"]["artt"][cap]["rate"]
    ax.plot([cap, summary["curve"]["artt"][-1]["filing"]], [plateau, plateau], ":", color="#6b7d85", linewidth=1.5)
    ax.annotate("No further scores; last estimate retained", (cap+0.4, plateau), xytext=(0, -24), textcoords="offset points", color="#53666f")
    ax.axhline(.5, color="#b4bfc3", linestyle=":", linewidth=1)
    ax.set_ylim(.4, 1.03)
    ax.yaxis.set_major_formatter(PercentFormatter(1))
    ax.set_ylabel("Private-bit recovery")
    ax.legend(loc="lower right", fontsize=9)
    ax.set_title("Fresh noisy scores accumulate information; the cap stops new scores", loc="left", pad=14)
    points = summary["curve"]["artt"]
    xs = [p["filing"] for p in points]
    lower.bar(xs, [p["refused_per_trial"] for p in points], color="#dfa98e", alpha=.8, label="Cumulative refusals per secret")
    lower.plot(xs, [p["admitted_per_trial"] for p in points], color=teal, marker=".", linewidth=2, label="Protected backend accesses per secret")
    lower.set_ylabel("Filings per secret")
    lower.set_xlabel("Number of attempted filings of the same secret")
    lower.yaxis.set_major_locator(MaxNLocator(integer=True))
    lower.legend(loc="upper left", fontsize=9)
    lower.set_xticks(range(0, len(points), 2))
    for panel in (ax, lower):
        panel.axvline(cap, color="#53666f", linestyle="--", linewidth=1)
        panel.spines[["top", "right"]].set_visible(False)
        panel.grid(axis="y", alpha=.15)
    fig.savefig(output / "repeated-filings.svg")
    fig.savefig(output / "repeated-filings.png", dpi=180)
    plt.close(fig)


def generate(directory, prior, retained_report, first, utility, output):
    directory, prior, retained_report, first, utility, output = map(Path, (directory, prior, retained_report, first, utility, output))
    if output.exists():
        raise ValueError("new report directory required")
    originals = {str(path): evidence_hashes(path) for path in (directory, prior, retained_report, first, utility)}
    summary, protocol, ledgers = validate(directory, prior)
    retained, prior_ledgers = load_evidence(prior)
    original, first_ledgers = load_evidence(first)
    _, utility_ledgers = load_evidence(utility)
    combined = [(prefix+"/"+name, rows) for prefix, cohort in (("first", first_ledgers), ("utility", utility_ledgers), ("real", prior_ledgers), ("filings", ledgers)) for name, rows in cohort]
    passport = export(combined, original["axis_meaning"], {summary["model_hash"]: ["software sandbox", "trusted custodian", "live Qwen baseline", "fixed public Qwen patch replay for repeated releases", "synthetic judge-side canary"]})
    total = passport["privacy_scope_totals"][summary["budget"]["scope"]]
    if total["admitted_records"] != summary["budget"]["used"] or total["epsilon_scope_total"] != summary["budget"]["epsilon_composed"]:
        raise ValueError("full composed passport mismatch")
    output.mkdir(parents=True)
    plots(summary, retained, output)
    document = (retained_report / "report.html").read_text(encoding="utf-8")
    for path in retained_report.iterdir():
        if path.is_file():
            document = document.replace('href="'+path.name+'"', 'href="retained/'+path.name+'"')
    document = document.replace('<nav>', '<p>This supplement adds a fresh exact-score baseline and a separate fixed-patch replay experiment for repeated filings. All first-run rows and evidence are retained.</p><nav>', 1)
    # Keep the old eight rows and measurements, clearly label their noisy control.
    document = document.replace('<section id="recovery"><h2>Before and after: canary recovery</h2>', '<section id="retained-recovery"><h2>Retained first live comparison: both score arms noisy</h2><p><b>These eight original rows are unchanged.</b> The old “naive” score control already used p=0.5 noise. Its 98/128 versus ARTT 96/128 does not measure the effect of adding noise. The status attack compares exposed versus suppressed success/failure.</p>', 1)
    document = document.replace('<a href="#recovery">Recovery</a>', '<a href="#recovery">Exact baseline</a><a href="#filings">Repeated filings</a><a href="#retained-recovery">Retained rows</a>', 1)
    exact, previous = summary["exact_baseline"]["score"], retained["recovery"]["artt_score_attack"]["score"]
    final_uncapped, at_cap = summary["curve"]["uncapped"][-1], summary["curve"]["artt"][protocol["cap_per_secret"]]
    baseline_panel = f'''<section id="recovery"><h2>Exact scores before; noisy scores after</h2><p>The new baseline publishes the judge's exact score with <b>no noise</b>. The same judge writes the private bit into both score fields. ARTT applies fresh noise to those fields.</p><img style="width:100%" src="exact-baseline.svg" alt="Exact-score baseline {exact['correct']}/{exact['n']}; retained live ARTT {previous['correct']}/{previous['n']}"><p><b>New exact baseline:</b> {metric(exact)}.<br><b>Retained live-model ARTT:</b> {metric(previous)}.</p><p>This is a separately predeclared new baseline arm with 128 fresh Qwen generations, compared descriptively with the retained ARTT cohort. They use independent balanced canary assignments, not paired observations. The first fixture result remains 88/128; the live-model result remains 96/128. Neither has been rerun or replaced.</p><p><a href="protocol.json">New predeclared protocol</a> · <a href="public-patches.jsonl">128 new public Qwen patches</a> · <a href="retained/report.html#recovery">Unchanged first live report</a> · <a href="exact-baseline.png">Export chart</a></p></section>'''
    rows = ""
    for un, ar in zip(summary["curve"]["uncapped"], summary["curve"]["artt"]):
        rows += f'<tr><td>{un["filing"]}</td><td>{metric(un)}</td><td>{metric(ar)}</td><td>{ar["admitted_per_trial"]}</td><td>{ar["refused_per_trial"]}</td></tr>'
    ledger_links = " · ".join(f'<a href="{name}">filing {i+1}</a>' for i, (name, _) in enumerate(ledgers))
    budget = summary["budget"]
    filings_panel = f'''<section id="filings"><h2>What the admission budget buys</h2><p>Each trial repeatedly files the <b>same private bit and same frozen Qwen patch</b>. Both paths add the same fresh p=0.5 noise. The uncapped path keeps releasing scores; ARTT permits four filings per secret, then refuses further access.</p><img style="width:100%" src="repeated-filings.svg" alt="Recovery over 16 filings; ARTT scores stop after four and later filings are refused"><p>At filing 16, uncapped recovery is <b>{final_uncapped['correct']}/{final_uncapped['n']}</b>. At its cap, ARTT recovery is <b>{at_cap['correct']}/{at_cap['n']}</b>; later requests reveal no new scores. Across 128 trials, <b>{budget['refused']} additional filings were refused</b>. Protected replay-backend accesses stayed <b>{budget['protected_replay_calls_at_cap']} → {budget['protected_replay_calls_after_refusals']}</b>.</p><p>Solid lines are observed recovery; shaded areas are pointwise Wilson 95% intervals; dashed colored lines are the predeclared mechanism prediction. The gray extension retains the last available estimate after the cap and is not a new release. Prefix measurements share the same secrets and are correlated.</p><p class="note">This experiment isolates repeated releases by replaying public patches from the retained Qwen run. It makes zero new GPU generations for the filing curve; each admitted filing invokes the protected replay backend once. The new exact baseline above makes 128 fresh GPU generations. The uncapped curve is already noisy: an exact-score uncapped attacker would recover the bit on its first filing.</p><p>The four-per-secret cap is enforced by durable item budgets plus a shared allowance of 512 for this new cohort. Earlier {budget['used_before']} corpus charges are carried forward; total used is {budget['used']}/{budget['cap']}. This demonstrates a chosen cap, not a claim that the demo's large cumulative epsilon offers strong privacy. New release epsilon: {budget['epsilon_new']:.4f}; composed ARTT scope: {budget['epsilon_composed']:.4f}. Unsafe controls are outside that finite guarantee.</p><details><summary>All 17 observed prefixes, intervals and refusals</summary><div class="scroll"><table><thead><tr><th>Attempted filings</th><th>Uncapped</th><th>ARTT / last available estimate</th><th>ARTT accesses per secret</th><th>Refusals per secret</th></tr></thead><tbody>{rows}</tbody></table></div></details><p><a href="repeated-filings.png">Export chart</a> · <a href="summary.json">Counts and diagnostics</a> · <a href="replay-provenance.json">Frozen patch provenance</a> · <a href="supplement-passport.json">Combined passport through this cohort</a></p><details><summary>Inspect all 16 ARTT filing ledgers</summary><p>{ledger_links}</p></details></section>'''
    document = document.replace('<main>', '<main>'+baseline_panel+filings_panel, 1)
    document = document.replace('<section id="budget"><h2>The cap is charged before access</h2>', '<section id="budget"><h2>Retained first live-cohort budget</h2><p>The numbers below are from the unchanged first live cohort. The new filing cohort and combined totals appear above.</p>', 1)
    document = document.replace('<section id="passport"><h2>A proposed passport mapping</h2>', '<section id="passport"><h2>Retained passport through the first live cohort</h2><p><a href="supplement-passport.json">The combined passport including the new filing cohort</a> carries the updated cumulative total.</p>', 1)
    document = document.replace('</main>', f'<footer>New protocol commit: {summary["protocol_commit"]}<br>New executed commit: {summary["git_commit"]}<br>New protocol SHA256: {summary["protocol_sha256"]}<br>Recovery truth remains a custodian aggregate; private schedules were not saved.</footer></main>', 1)
    (output / "report.html").write_text(document, encoding="utf-8")
    write_json(output / "supplement-passport.json", passport)
    for name in ("summary.json", "protocol.json", "start.json", "backend-receipt.json", "inference-receipt.json", "public-patches.jsonl", "replay-provenance.json"):
        shutil.copyfile(directory / name, output / name)
    for name in [*summary["ledger_files"], *summary["unsafe_ledger_files"]]:
        shutil.copyfile(directory / name, output / name)
    # Keep the old report's relative assets separate from the new cohort's.
    shutil.copytree(retained_report, output / "retained")
    if {str(path): evidence_hashes(path) for path in (directory, prior, retained_report, first, utility)} != originals:
        raise ValueError("retained evidence changed while reporting")
    write_json(output / "artifact-checks.json", {"status": "passed", "original_evidence_preserved_byte_for_byte": True,
        "all_merged_and_source_ledgers_verified": True, "fresh_baseline_receipt_verified": True,
        "all_prefixes_and_intervals_checked": True, "combined_passport_accounting_verified": True,
        "post_cap_replay_access_count_unchanged": True})
    (output / "completion.md").write_text(f"# Exact baseline and repeated filings\n\nNew exact score recovery: {metric(exact)}. Retained live ARTT: {metric(previous)}.\n\nUncapped at 16: {metric(final_uncapped)}. ARTT at cap four: {metric(at_cap)}. Extra refused filings: {budget['refused']}; protected replay accesses {budget['protected_replay_calls_at_cap']} before and {budget['protected_replay_calls_after_refusals']} after.\n\nThe curve uses frozen public Qwen patch replay, not fresh GPU generations. The separate exact baseline generated 128 new Qwen patches. All existing evidence remains byte-for-byte unchanged.\n\nProtocol commit: {summary['protocol_commit']}. Executed commit: {summary['git_commit']}. Protocol SHA256: {summary['protocol_sha256']}.\n", encoding="utf-8")
    print(str((output / "report.html").resolve()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--prior-run", default="scratch/coding-demo-qwen-02")
    parser.add_argument("--retained-report", default="scratch/coding-demo-qwen-report")
    parser.add_argument("--first-run", default="scratch/coding-demo")
    parser.add_argument("--utility-run", default="scratch/coding-demo-utility")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    generate(args.input, args.prior_run, args.retained_report, args.first_run, args.utility_run, args.output)


if __name__ == "__main__":
    main()
