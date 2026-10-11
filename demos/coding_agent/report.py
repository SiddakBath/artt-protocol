"""Build an offline HTML report exclusively from preserved run outputs."""
import argparse
import html
import json
from pathlib import Path
from rt.bundle import sha
from rt.scheduled_log import read
from .passport import STATUS, export, legacy_export


def number(value):
    return f"{value:.4f}"


def metric(value, interval_key="wilson_95"):
    low, high = value[interval_key]
    if "correct" in value:
        return f"{value['correct']}/{value['n']} ({number(value['rate'])}; 95% interval {number(low)} to {number(high)})"
    return f"{number(value['estimate'])}, 95% interval {number(low)} to {number(high)}"


def readme_numbers(summary):
    if summary.get("backend") == "local-qwen":
        from .real_report import readme_numbers as real_numbers
        return real_numbers(summary)
    recovery = summary["recovery"]
    lines = ["## ARTT on a coding-agent evaluation", "",
        "Coding agents are judged on hidden tests. This demo runs 48 small Python tasks through two release paths with deterministic fixture agents, not learned models.", "",
        "On a naive design that publishes status, the constant-score abort attack recovered its planted canary in " + metric(recovery["naive_status_attack"]["status"]) + ".",
        "Under ARTT the same attack recovered it from status in " + metric(recovery["artt_status_attack"]["status"]) + " and from scores in " + metric(recovery["artt_status_attack"]["score"]) + ".",
        "The deliberate score encoder recovered it in " + metric(recovery["artt_score_attack"]["score"]) + "; its predicted optimal recovery is " + number(recovery["artt_score_attack"]["score"]["predicted"]) + ". The score channel is bounded and logged, not closed.", "",
        "Honest fixture A estimate: " + metric(summary["honest"]["A"]["deception"], "hoeffding_95") + ".",
        "Honest fixture B estimate: " + metric(summary["honest"]["B"]["deception"], "hoeffding_95") + ".",
        "A minus B: " + metric(summary["honest"]["difference"], "hoeffding_95") + ". " + ("The conservative interval excludes zero." if summary["honest"]["difference"]["interval_excludes_zero"] else "The conservative interval includes zero; this run does not establish separation."), "",
        "Each batch is a separate hash-chained ledger. Edited and middle-deleted copies are checked by `python -m rt.verify`; tail deletion needs a retained checkpoint. CT-style witnessing is future work.", "",
        f"Budget: {summary['budget']['admitted']} admitted, {summary['budget']['refused']} refused; epsilon per record {number(summary['budget']['epsilon_per_record'])}, total {number(summary['budget']['epsilon_total'])}. The post-cap call count is unchanged: {summary['budget']['calls_before_refusals']} before, {summary['budget']['calls_after_refusals']} after.", "",
        "Run it on Linux or Windows via WSL:", "", "    .venv/bin/python -m rt.build_sandbox", "    make demo", "", "On Windows use `scripts/demo.ps1`. Every run needs a fresh output directory. Open `scratch/coding-demo/report.html`.", "",
        "Scope: deterministic fixture agent; single model call per admission; trusted custodian; software sandbox, not hardware. Timing noninterference is not proven. The passport export is a proposed mapping, not an official AIUC or Lucid format.", "",
        f"Observed runtime: {number(summary['wall_seconds'])} seconds. Commit: `{summary['git_commit']}`. Protocol SHA256: `{summary['protocol_sha256']}`.", "", "Decoder results from summary.json:", ""]
    for arm, decoders in recovery.items():
        for decoder, value in decoders.items():
            lines.append(f"- {arm} / {decoder}: {metric(value)}")
    lines.extend(["", "Observed tamper checks:", ""])
    for label, result in summary["tamper"]["variants"].items():
        lines.append(f"- {label}: {result['output']}; checkpoint matches: {result['checkpoint_matches']}")
    if "utility_followup" in summary:
        followup = summary["utility_followup"]
        lines.extend(["", "Separately predeclared utility-only follow-up (the first run above remains unchanged):", "",
            f"{followup['honest']['A']['deception']['n']} admissions per fixture agent, repeating the same fixed 48-task corpus. No pooling with the first utility sample.",
            "Follow-up A: " + metric(followup["honest"]["A"]["deception"], "hoeffding_95") + ".",
            "Follow-up B: " + metric(followup["honest"]["B"]["deception"], "hoeffding_95") + ".",
            "Follow-up A minus B: " + metric(followup["honest"]["difference"], "hoeffding_95") + ". " + ("The conservative interval excludes zero." if followup["honest"]["difference"]["interval_excludes_zero"] else "The conservative interval includes zero."),
            f"Additional admissions: {followup['budget']['admitted_this_cohort']}. The public budget extension carries forward the first {followup['budget']['used_before']} charges; total used is {followup['budget']['used_after']} against an extended cap of {followup['budget']['extended_cap']}. Additional epsilon: {number(followup['budget']['epsilon_this_cohort'])}; combined scope total: {number(followup['budget']['epsilon_total_including_first_run'])}.",
            f"Utility protocol SHA256: `{followup['protocol_sha256']}`; predeclared in `{followup['protocol_commit']}`. Observed utility runtime: {number(followup['wall_seconds'])} seconds."])
    return "\n".join(lines) + "\n"


def chart(summary):
    rows = [(arm, decoder, value) for arm, decoders in summary["recovery"].items() for decoder, value in decoders.items()]
    height = len(rows) * 44 + 65
    parts = [f'<svg viewBox="0 0 960 {height}" role="img" aria-label="Canary recovery with Wilson intervals and chance line">',
             f'<line x1="530" x2="530" y1="20" y2="{height-35}" stroke="#64748b" stroke-dasharray="5 5"/>',
             '<text x="535" y="16" font-size="13">chance</text>']
    for index, (arm, decoder, value) in enumerate(rows):
        y = 38 + index * 44
        low, high = value["wilson_95"]
        color = "#ef765b" if arm.startswith("naive") else "#148b87"
        label = arm.replace("_", " ") + " / " + decoder
        parts += [f'<text x="0" y="{y+17}" font-size="14">{html.escape(label)}</text>',
                  f'<rect x="320" y="{y}" width="{420*value["rate"]}" height="24" rx="4" fill="{color}"/>',
                  f'<path d="M {320+420*low} {y+7} v10 M {320+420*low} {y+12} H {320+420*high} M {320+420*high} {y+7} v10" stroke="#122838" stroke-width="2"/>',
                  f'<text x="765" y="{y+17}" font-size="14">{value["correct"]}/{value["n"]} ({number(value["rate"])})</text>']
    parts.append(f'<text x="320" y="{height-8}" font-size="13">0</text><text x="733" y="{height-8}" font-size="13">1</text></svg>')
    return "".join(parts)


def render_html(summary, ledgers, passport):
    real = summary.get("backend") == "local-qwen"
    rows = [{"ledger_file": filename, "display_index": index, **row} for index, (filename, row) in enumerate((filename, row) for filename, entries in ledgers for row in entries)]
    preview_entries = [entry for entry in passport["entries"] if not real or entry["subject"]["model_commitment"] == summary["model_hash"]]
    passport_preview = {"status": passport["status"], "privacy_scope_totals": passport["privacy_scope_totals"], "entries": preview_entries[:1]}
    data = json.dumps({"summary": summary, "rows": rows, "passport": passport_preview}, ensure_ascii=True, sort_keys=True).replace("<", "\\u003c")
    recovery = "".join(f'<tr><td>{html.escape(arm.replace("_", " "))}</td><td>{decoder}</td><td>{metric(value)}</td><td>{number(value["predicted"]) if value["predicted"] is not None else "not predeclared"}</td></tr>' for arm, decoders in summary["recovery"].items() for decoder, value in decoders.items())
    followup = summary.get("utility_followup")
    measurements = followup["honest"] if followup else summary["honest"]
    if real:
        baseline, model = measurements["naive"], measurements["model"]["deception"]
        honest_panel = f'<article class="stat"><span>Qwen · unnoised honest control</span><strong>{baseline["passes"]}/{baseline["n"]}</strong><p>Observed hidden-test pass fraction: {number(baseline["pass_rate"])}</p><small>Worker errors: {baseline["worker_errors"]}</small></article><article class="stat"><span>Qwen · ARTT honest estimate</span><strong>{number(model["estimate"])}</strong><p>{metric(model, "hoeffding_95")}</p><small>{model["n"]} fresh model-generated patches</small></article><article class="stat"><span>Live model inferences</span><strong>{summary["budget"]["calls_before_refusals"]}</strong><p>No patch cache or fixture fallback</p><small>Public patches and checkpoint hashes retained</small></article>'
        utility_note = "One learned model on 48 tiny tasks. The conservative utility interval remains wide; this run makes no A/B separation claim."
    else:
        honest = "".join(f'<article class="stat"><span>Fixture {agent}</span><strong>{number(measurements[agent]["deception"]["estimate"])}</strong><p>{metric(measurements[agent]["deception"], "hoeffding_95")}</p><small>Raw fixture pass rate: {number(summary["raw_fixture_pass_rates"][agent]["pass_rate"])} (custodian ground truth)</small></article>' for agent in ("A", "B"))
        difference = measurements["difference"]
        honest_panel = honest + f'<article class="stat"><span>A minus B</span><strong>{number(difference["estimate"])}</strong><p>{metric(difference, "hoeffding_95")}</p></article>'
        utility_note = "The conservative interval excludes zero." if difference["interval_excludes_zero"] else "The conservative interval includes zero. This sample does not establish separation."
    budget = summary["budget"]
    utility_context = ""
    budget_extension = ""
    followup_provenance = ""
    intro_kind = "fixture coding task"
    backend_badge = "Fixture agent, not a real model"
    private_description = "The public task corpus has 48 tiny Python functions. A custodian-private test context carries a balanced, privately shuffled canary comment, echoed by a deterministic fixture backend. Trial ground truth is never saved in public ledgers. Source code is published for reproducibility."
    utility_intro = "These are fixture results."
    budget_label, cap_display = "First protocol", budget["cap"]
    scope_total_label = "First protocol scope total"
    if real:
        intro_kind = "Qwen3-0.6B coding model"
        backend_badge = "Live local Qwen3-0.6B · CUDA"
        private_description = "Qwen generates every patch from a public task description, signature and example. After inference, the custodian appends hidden tests and a balanced private canary for the judge. The model never receives those tests or the canary. This measures a planted judge-side leak, not extraction from model training data. Public generated patches are retained; private trial labels are discarded."
        utility_intro = "These patches come from live model inference."
        budget_label, cap_display = "This model protocol", budget["admitted"]
        scope_total_label = "This cohort release epsilon"
        diag = summary["private_diagnostics_aggregate"]
        utility_context = f'<p class="note">The fixture first run and larger fixture utility cohort remain separate and unchanged. This real-model run uses fresh inference in both arms and is not pooled with either earlier result.</p><p>Scheduled proposals before cutoff: {diag["proposals_before_cutoff"]}/{diag["scheduled_slots"]}. Private worker errors: {diag["private_worker_errors"]}; timeouts: {diag["private_timeouts"]}. Status-attack aborts are deliberate.</p>'
        budget_extension = f'<p class="note">The predeclared extension carries forward {budget["used_before"]} ARTT charges. Combined ARTT admissions: {budget["used"]}/{budget["cap"]}; composed ARTT scope epsilon: {number(budget["epsilon_composed_artt_scope"])}. The separately charged, deliberately unsafe comparator has no finite privacy guarantee for its status channel.</p>'
        inference = summary.get("inference_receipt", {})
        followup_provenance = f'<br>Qwen weights SHA256: {summary["backend_receipt"]["model_files_sha256"]["model.safetensors"]}<br>Model commitment: {summary["model_hash"]}<br>Observed runtime including model load: {number(inference.get("wall_seconds_including_model_load", summary["wall_seconds"]))} seconds.'
    if followup:
        utility_context = f'<p>Separately predeclared utility-only cohort: {measurements["A"]["deception"]["n"]} admissions per fixture agent, repeating the same fixed 48 tasks. Independent release noise is sampled each admission. The first utility sample is not pooled into these estimates; this comparison concerns the fixed corpus, not unseen coding tasks.</p>'
        utility_context += f'<p class="note">First cohort retained: A minus B {metric(summary["honest"]["difference"], "hoeffding_95")}. That interval includes zero. The attack and refusal results still come from that original run.</p>'
        extension = followup["budget"]
        budget_extension = f'<p class="note">Before the utility-only cohort, a new committed protocol explicitly extended the allowance, carrying forward {extension["used_before"]} charges. The first SQLite ledger remains unchanged. This is additional authorized access, with additional privacy cost.</p><div class="grid"><article class="stat"><span>Utility-only admissions</span><strong>{extension["admitted_this_cohort"]}</strong><p>Additional allowance: {extension["additional_allowance"]}</p></article><article class="stat"><span>Combined admissions / extended cap</span><strong>{extension["used_after"]} / {extension["extended_cap"]}</strong></article><article class="stat"><span>Combined scope epsilon</span><strong>{number(extension["epsilon_total_including_first_run"])}</strong><p>First cohort {number(budget["epsilon_total"])} plus utility cohort {number(extension["epsilon_this_cohort"])}</p></article></div>'
        followup_provenance = f'<br>Utility executed commit: {followup["git_commit"]}<br>Utility protocol SHA256: {followup["protocol_sha256"]}<br>Utility protocol introduced in: {followup["protocol_commit"]}<br>Observed utility-only runtime: {number(followup["wall_seconds"])} seconds.'
    title = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>ARTT · Coding-agent evaluation</title>'
    css = '''<style>
    *{box-sizing:border-box}body{margin:0;background:#f3f5f5;color:#183342;font:16px/1.55 system-ui,sans-serif}header{background:#112d3b;color:#f6fbfb;padding:52px max(24px,calc((100vw - 1160px)/2))}header p{max-width:830px;color:#c6dce1}h1{font-size:44px;line-height:1.12;margin:16px 0}h2{font-size:27px;margin:0 0 16px}h3{margin:0}main{max-width:1208px;padding:30px 24px;margin:auto}section{background:white;border:1px solid #dce5e6;border-radius:12px;padding:28px;margin:0 0 24px;scroll-margin-top:12px}.eyebrow{font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:#69c9be}.badge{display:inline-block;padding:5px 10px;border:1px solid #52707c;border-radius:25px;margin:4px 6px 4px 0;font-size:12px}nav a{color:#b8efe7;margin-right:20px;text-decoration:none}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.stat{background:#f0f7f6;padding:20px;border-radius:8px}.stat span{display:block;font-size:14px}.stat strong{display:block;font-size:33px;color:#14766d}.stat p{font-size:14px}.note{background:#fff4e6;border-left:4px solid #e4ac52;padding:12px 16px}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:10px 12px;text-align:left;border-bottom:1px solid #e1e8e9;vertical-align:top}th{background:#f3f7f7}tr[data-row]{cursor:pointer}tr[data-row]:hover{background:#edf7f5}input{padding:12px;border:1px solid #9ab2bb;border-radius:6px;width:min(100%,420px)}button{background:#136f69;color:white;border:0;border-radius:6px;padding:11px 17px;cursor:pointer}button:focus,input:focus,a:focus{outline:3px solid #efb861;outline-offset:3px}pre{background:#102c3a;color:#dbf4ef;padding:18px;border-radius:8px;overflow:auto;max-height:420px;font:12px/1.5 ui-monospace,monospace}svg{width:100%;height:auto}footer{font-size:12px;word-break:break-all;color:#48636f;padding:10px 0 35px}small{color:#48636f}.ok{color:#08695c}.bad{color:#b23525}@media(max-width:760px){.grid{grid-template-columns:1fr}h1{font-size:34px}section{padding:18px}header{padding:30px 24px}}@media print{button,input,nav{display:none}section{break-inside:avoid}}
    </style>'''
    body = f'''<header><div class="eyebrow">A Right to Test · Executed evidence</div><h1>What leaves a hidden coding evaluation?</h1><p>The same {intro_kind} and the same attacker, through a naive status-publishing design and ARTT's scheduled release. Status is suppressed for this attack. Score leakage remains noisy, bounded, logged and capped.</p><div><span class="badge">{backend_badge}</span><span class="badge">Single call per admission</span><span class="badge">Trusted custodian</span><span class="badge">Software sandbox, not hardware</span></div><p>{private_description}</p><nav><a href="#recovery">Recovery</a><a href="#utility">Honest utility</a><a href="#ledger">Ledger</a><a href="#verification">Verification</a><a href="#passport">Passport sketch</a></nav></header><main>
    <section id="recovery"><h2>Before and after: canary recovery</h2><p>Bars show observed recovery. Whiskers show Wilson 95% intervals. The dashed line is chance for a balanced bit. The deliberate encoder uses both axes; its predicted optimal recovery is {number(summary['recovery']['artt_score_attack']['score']['predicted'])}.</p>{chart(summary)}<div class="scroll"><table><thead><tr><th>Arm / judge</th><th>Decoder</th><th>Observed count and interval</th><th>Prediction</th></tr></thead><tbody>{recovery}</tbody></table></div></section>
    <section id="utility"><h2>Honest utility, with its uncertainty</h2><p>The first axis estimates hidden-test pass rate as mean(released bucket) minus 1. The second checks the declared signature. Noise remains in both. {utility_intro}</p>{utility_context}<div class="grid">{honest_panel}</div><p class="note">{utility_note} Hoeffding intervals are conservative and shown without truncation to the parameter range.</p></section>
    <section id="ledger"><h2>Inspect a released record</h2><p>Inherited schema names: <b>deception</b> means hidden-test pass bucket; <b>sycophancy</b> means signature check. Attack judges encode a canary instead of evaluating correctness. Each batch has its own chain; seq and slot restart within each ledger file. Select a row to inspect all its public fields.</p><input id="search" aria-label="Search ledger" placeholder="Search task, hash, kind, or ledger file"><p id="row-count"></p><div class="scroll"><table><thead><tr><th>Ledger / seq</th><th>Slot</th><th>Kind</th><th>Item</th><th>Verdict</th><th>Entry hash</th><th>Previous</th></tr></thead><tbody id="ledger-rows"></tbody></table></div><p><button id="more">Show more rows</button></p><pre id="detail">Select a ledger row.</pre></section>
    <section id="budget"><h2>The cap is charged before access</h2><div class="grid"><article class="stat"><span>{budget_label} admissions / allowance</span><strong>{budget['admitted']} / {cap_display}</strong><p>Durable budget used: {budget['used']}</p></article><article class="stat"><span>{budget_label} post-cap refusals</span><strong>{budget['refused']}</strong><p>Model calls before / after: {budget['calls_before_refusals']} / {budget['calls_after_refusals']}</p></article><article class="stat"><span>Epsilon per release</span><strong>{number(budget['epsilon_per_record'])}</strong><p>{scope_total_label}: {number(budget['epsilon_total'])}</p></article></div>{budget_extension}<svg id="budget-chart" viewBox="0 0 960 220" role="img" aria-label="Cumulative admissions and refused slots"></svg><p>Timeline uses display order across batch files. Refusals are public pre-access decisions. Failed admitted executions still consume their admission.</p></section>
    <section id="verification"><h2>What the hash chain catches</h2><p><button id="tamper-toggle" aria-pressed="true">Show original ledgers</button></p><div id="verify-panel"></div><p class="note">{html.escape(summary['tamper']['caveat'])}</p><p>The saved checkpoint commits to the original batch head and row count. Validate the chain as well as the checkpoint: an edited middle row can leave the saved head unchanged. A holder must keep the checkpoint independently; it is not a hardware quote or an external witness.</p></section>
    <section id="passport"><h2>A proposed passport mapping</h2><p class="note">{STATUS}</p><p>One entry per scheduled record carries model and evaluation commitments, the released verdict, privacy charge and ledger provenance. Refusals have no released verdict and cost no additional release epsilon. The running charge through this record and the full scope total in this export are separately labelled.</p><pre id="passport-preview"></pre></section>
    <footer>First executed commit: {summary['git_commit']}<br>Runner version: {summary['runner_version']}<br>First protocol SHA256: {summary['protocol_sha256']}<br>First protocol introduced in: {summary['protocol_commit']}<br>Observed first evaluation runtime: {number(summary['wall_seconds'])} seconds.{followup_provenance}<br>Timing noninterference is not proven. CT-style witnessing is future work. Recovery counts are trusted custodian aggregates; private schedules were discarded.</footer></main>'''
    js = '''<script id="run-data" type="application/json">''' + data + '''</script><script>
    const data=JSON.parse(document.getElementById('run-data').textContent), rows=data.rows;
    const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    let limit=15;
    function showRows(){const query=document.getElementById('search').value.toLowerCase();const selected=rows.filter(r=>JSON.stringify(r).toLowerCase().includes(query));document.getElementById('row-count').textContent=`Showing ${Math.min(limit,selected.length)} of ${selected.length} matching records.`;document.getElementById('ledger-rows').innerHTML=selected.slice(0,limit).map(r=>`<tr data-row="${r.display_index}" tabindex="0" role="button" aria-label="Inspect record ${r.display_index}"><td>${esc(r.ledger_file)} / ${r.seq}</td><td>${r.slot}</td><td>${r.kind}</td><td>${esc(r.item_id)}</td><td>${esc(r.verdict?JSON.stringify(r.verdict.axes):r.reason_code)}</td><td>${r.entry_hash.slice(0,12)}</td><td>${(r.prev||'genesis').slice(0,12)}</td></tr>`).join('');document.getElementById('more').hidden=limit>=selected.length;}
    document.getElementById('search').addEventListener('input',()=>{limit=15;showRows()});document.getElementById('more').addEventListener('click',()=>{limit+=30;showRows()});
    function inspect(event){const tr=event.target.closest('tr[data-row]');if(tr)document.getElementById('detail').textContent=JSON.stringify(rows[Number(tr.dataset.row)],null,2)}
    document.getElementById('ledger-rows').addEventListener('click',inspect);document.getElementById('ledger-rows').addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();inspect(event)}});showRows();
    let tampered=true;function verification(){const outcomes=tampered?data.summary.tamper.variants:data.summary.original_verification;document.getElementById('verify-panel').innerHTML=`<table><thead><tr><th>Copy / ledger</th><th>Observed CLI result</th><th>Saved checkpoint</th></tr></thead><tbody>${Object.entries(outcomes).map(([name,result])=>`<tr><td>${esc(name)}</td><td class="${result.exit_code===0?'ok':'bad'}">${esc(result.output)}</td><td>${tampered?(result.checkpoint_matches?'MATCH':'MISMATCH'):'retained'}</td></tr>`).join('')}</tbody></table>`;const button=document.getElementById('tamper-toggle');button.textContent=tampered?'Show original ledgers':'Show tampered copies';button.setAttribute('aria-pressed',String(tampered));}document.getElementById('tamper-toggle').addEventListener('click',()=>{tampered=!tampered;verification()});verification();
    document.getElementById('passport-preview').textContent=JSON.stringify({status:data.passport.status,privacy_scope_totals:data.passport.privacy_scope_totals,entry:data.passport.entries[0]},null,2);
    let used=data.summary.backend==='local-qwen'?data.summary.budget.used_before:0;const cap=data.summary.utility_followup?data.summary.utility_followup.budget.extended_cap:data.summary.budget.cap;const points=rows.map((r,i)=>{if(r.kind==='released')used++;return [35+890*i/(rows.length-1),180-145*used/cap,r.kind]});document.getElementById('budget-chart').innerHTML=`<path d="M35 25 V180 H935" fill="none" stroke="#9bb1b7"/><polyline points="${points.map(p=>p.slice(0,2).join(',')).join(' ')}" fill="none" stroke="#148b87" stroke-width="3"/>${points.filter(p=>p[2]==='refused').map(p=>`<circle cx="${p[0]}" cy="${p[1]}" r="4" fill="#ef765b"/>`).join('')}<text x="40" y="20" font-size="13">${cap} admissions (declared cap)</text><text x="40" y="210" font-size="13">Display order across batch ledgers; orange dots are refusals</text>`;
    </script></html>'''
    return title + css + body + js


def generate(input_dir, html_path):
    directory = Path(input_dir)
    summary = json.loads((directory / "summary.json").read_text())
    if sha((directory / "protocol.json").read_bytes()) != summary["protocol_sha256"]:
        raise ValueError("protocol hash mismatch")
    ledgers = [(filename, read(directory / filename)) for filename in summary["ledger_files"]]
    for filename, entries in ledgers:
        if len(entries) != summary["checkpoints"][filename]["entries"] or (entries[-1]["entry_hash"] if entries else None) != summary["checkpoints"][filename]["last_entry_hash"]:
            raise ValueError("retained ledger checkpoint mismatch")
    retained_passport = json.loads((directory / "passport.json").read_text())
    meanings = summary.get("axis_meaning", json.loads((directory / "protocol.json").read_text())["axis_meaning"])
    passport = export(ledgers, meanings)
    if retained_passport != passport and retained_passport != legacy_export(ledgers, meanings):
        raise ValueError("passport does not match retained ledgers")
    html_path = Path(html_path)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(render_html(summary, ledgers, passport), encoding="utf-8")
    (html_path.parent / "README-numbers.md").write_text(readme_numbers(summary), encoding="utf-8")
    (html_path.parent / "passport.json").write_text(json.dumps(passport, indent=2)+"\n", encoding="utf-8")
    print(str(html_path.resolve()))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--html", required=True)
    args = parser.parse_args(argv)
    generate(args.input, args.html)


if __name__ == "__main__":
    main()
