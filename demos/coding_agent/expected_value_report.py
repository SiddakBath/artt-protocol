"""Verify published expected-value evidence and render a portable offline report."""
import argparse
import html
import json
import math
from pathlib import Path
import sqlite3
from rt.bundle import sha
from rt.experiment import interval
from rt.log import read as read_exact
from rt.scheduled_log import read as read_noisy
from .design import STYLES
from .run import checkpoint, utility, write_json
from .useful_crash import predicted_recovery


CONTRIBUTIONS = '''<section id="contributions"><h2>What ARTT contributes</h2>
<p><b>ARTT aims to make independent AI scrutiny compatible with confidentiality, and make the testing process publicly accountable.</b> An outsider could file an inspectable evaluation; a custodian could execute it against a committed model configuration under declared access rules; the public could receive a bounded result and a record of the outcome.</p>
<h3>1. A public testing contract</h3><p>A filing identifies the method, intended target, resource limits and result schema. The protocol specifies admissions, releases and refusal records. This supplies a concrete process for organizing access; it does not determine which tests are scientifically valid or which models custodians must offer.</p>
<h3>2. A security analysis of the public exit</h3><p>A score, crash or timeout can disclose private information even when computation is sealed. Our studies demonstrate these channels with a language model in the loop, including a hidden assertion choice that changes correctness. The submitted evaluator itself is part of the threat model.</p>
<h3>3. A controlled release mechanism</h3><p>The trusted publisher owns the output format and noise. Access is charged before execution; successes and failures pass through the same scheduled, protected record interface. Shared caps limit repeated access across filers and program aliases. The latest experiment reserves experiment and per-secret allowances atomically.</p>
<h3>4. Evidence readers can check</h3><p>Committed protocols, source snapshots, preserved ledgers, checkpoints and durable counters connect reported results to retained artifacts. Checkpoints expose changes to their committed prefix. Hashes establish integrity; truthful custody, external witnessing and omission detection require additional guarantees.</p>
<h3>5. Measured protection and honest utility</h3><p>The ideal status-only case remains visible alongside useful-score and expected-value attacks, repeated filings and honest scoring. These measurements show both the repaired status channel and the remaining score signal, rather than treating a constant public status as proof that useful results are private.</p>
<p class="note">The contribution builds on established confidential execution, differential privacy and <a href="https://www.usenix.org/conference/usenix-security-11/differential-privacy-under-fire">covert-channel defenses for private queries</a>. Our claim is the specified public AI evaluation interface, its analysis of the declared release, and the end-to-end implementation and measurements. The guarantee depends on trusted custody, accounting, publication and delivery; physical timing and generic shared-queue noninterference remain outside the established scope.</p></section>
<section id="impact"><h2>The change this could enable</h2>
<p>Independent researchers could investigate failures that standard benchmarks miss. Regulators and evaluators could examine confidential systems and protect unreleased test material. Custodians could permit broader scrutiny while retaining sensitive assets. Inspectable methods and recorded refusals could make the testing process easier for the public to question.</p>
<p><b>The proposed change is broader participation in challenging AI claims, with access and disclosure governed together.</b> Suitable custody, practical privacy settings, external witnessing and institutional adoption would be needed to turn this prototype into public infrastructure.</p>
<p class="note">These are deployment goals, not measured societal outcomes. Today the evidence covers a specified protocol, a working prototype and controlled experiments with one small model. At the current noise setting, ARTT meters the channel rather than making a bit private; the reported findings and honest-utility intervals state that boundary explicitly.</p></section>'''


def verify(directory):
    directory=Path(directory)
    s=json.loads((directory/'summary.json').read_text(encoding='utf-8'))
    p=json.loads((directory/'protocol.json').read_text(encoding='utf-8'))
    start=json.loads((directory/'start.json').read_text(encoding='utf-8'))
    receipt=json.loads((directory/'completion-receipt.json').read_text(encoding='utf-8'))
    if sha((directory/'protocol.json').read_bytes())!=s['protocol_sha256'] or not s['invariants_passed'] or receipt['status']!='completed':
        raise ValueError('protocol_or_completion_failure')
    if start['git_commit']!=s['protocol_commit'] or start['protocol_sha256']!=s['protocol_sha256'] or any(v['exit_code'] for v in s['verification'].values()):
        raise ValueError('commit_or_verification_mismatch')
    for name,digest in start['source_sha256'].items():
        if sha((directory/'source-snapshot'/name).read_bytes())!=digest:
            raise ValueError('archived_source_mismatch: '+name)
    noisy={name:read_noisy(directory/name) for name in s['ledger_files']}
    exact={name:read_exact(directory/name) for name in s['unsafe_ledger_files']}
    for name in [*noisy,*exact]:
        if checkpoint(directory/name)!=s['checkpoints'][name]:
            raise ValueError('checkpoint_mismatch')
    for path in (directory/'naive-source-records').glob('*/checkpoints.json'):
        for name,saved in json.loads(path.read_text(encoding='utf-8')).items():
            read_exact(path.parent/name)
            if checkpoint(path.parent/name)!=saved:raise ValueError('source_chain_checkpoint_mismatch')
    admitted=sum(row['kind']=='released' for rows in noisy.values() for row in rows)
    refused=sum(row['kind']=='refused' for rows in noisy.values() for row in rows)
    if admitted!=p['admission_cap'] or refused!=p['attack_refusals'] or sum(map(len,exact.values()))!=p['unsafe_cap']:
        raise ValueError('cohort_or_accounting_mismatch')
    expected=[(p['budget_scope'],704,704)]
    expected.extend((f'expected-value-6-{label}-{i}',4,4) for label,n in (('attack',128),('utility',48)) for i in range(n))
    for name,rows in (('budget.sqlite',expected),('unsafe-budget.sqlite',[('expected-value-unsafe-6',432,432)])):
        with sqlite3.connect((directory/name).resolve().as_uri()+'?mode=ro',uri=True) as conn:
            if sorted(conn.execute('SELECT scope,cap,used FROM budgets').fetchall())!=sorted(rows):
                raise ValueError('durable_budget_mismatch')
    controls=[exact[f'naive-public-candidate-{bit}.jsonl'] for bit in (0,1)]
    axes=[r.get('verdict',{}).get('axes',{'deception':0,'sycophancy':0}) for r in controls[0]]
    if s['normal']['candidate_passes']!=[sum(r.get('verdict',{}).get('axes',{}).get('deception')==3 for r in rows) for rows in controls]:
        raise ValueError('ordinary_score_counts_mismatch')
    if [point['filing'] for point in s['curve']]!=list(range(9)):
        raise ValueError('missing_prefix')
    for point in s['curve']:
        k=min(point['filing'],4)
        predicted=sum(predicted_recovery(k,sum(v!=0 for v in a.values())) for a in axes)/128
        if point['rate']!=point['correct']/128 or point['wilson_95']!=interval(point['correct'],128) or abs(point['predicted']-predicted)>1e-12:
            raise ValueError('prefix_arithmetic_mismatch')
        if point['filing']>4 and point['correct']!=s['curve'][4]['correct']:
            raise ValueError('refusal_changed_guess')
    utility_rows=[r for name,rows in noisy.items() if name.startswith('utility-') for r in rows]
    estimates=utility(utility_rows)
    truth_rows=exact['naive-exact-honest.jsonl']
    for axis,estimate in estimates.items():
        truth=sum(r.get('verdict',{}).get('axes',{}).get(axis)==3 for r in truth_rows)/48
        saved=s['honest'][axis]
        if any(saved[k]!=v for k,v in estimate.items()) or saved['exact_truth']!=truth or saved['error']!=saved['estimate']-truth:
            raise ValueError('honest_utility_mismatch')
    b=s['budget']
    if not math.isclose(b['epsilon_per_secret_at_cap'],8*math.log(3)) or not math.isclose(b['epsilon_experiment_sum'],704*2*math.log(3)):
        raise ValueError('epsilon_mismatch')
    if receipt['backend_calls']!=1136 or b['all_backend_calls']!=1136 or b['attack_calls_after_refusals']!=512:
        raise ValueError('backend_count_mismatch')
    return s,p


def historical(history):
    history=Path(history)
    manifest=json.loads((history/'publication-manifest.json').read_text(encoding='utf-8'))
    for name,digest in manifest['published_sha256'].items():
        if sha((history/name).read_bytes())!=digest:raise ValueError('historical_publication_mismatch')
    return {label:json.loads((history/label/'summary.json').read_text(encoding='utf-8')) for label in ('qwen','useful-crash')}


def plots(s,old,output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter
    ideal=old['qwen']['recovery']
    useful=old['useful-crash']['primary']
    rows=[('Equal scores · exposed status',ideal['naive_status_attack']['status']),('Equal scores · ARTT status',ideal['artt_status_attack']['status']),
          ('Useful scores · exact joint',useful['before_joint']),('Useful scores · ARTT joint',useful['after_joint']),
          ('Expected value · exact joint',s['primary']['before']),('Expected value · ARTT joint',s['primary']['after'])]
    plt.rcParams.update({'font.family':'DejaVu Sans','svg.fonttype':'none','font.size':10})
    fig,ax=plt.subplots(figsize=(10,4.8),layout='constrained')
    for index,(label,p) in enumerate(rows):
        y=len(rows)-index-1
        ax.barh(y,p['rate'],height=.5,color='#9ca7a1' if index%2==0 else '#177b63')
        lo,hi=p['wilson_95']
        ax.errorbar(p['rate'],y,xerr=[[max(0,p['rate']-lo)],[max(0,hi-p['rate'])]],color='#243b48',capsize=3)
        ax.text(1.015,y,f"{p['correct']}/{p['n']}",va='center')
    ax.set_yticks(list(reversed(range(6))),[label for label,_ in rows]);ax.set_xlim(0,1.14)
    ax.set_xticks([0,.25,.5,.75,1]);ax.xaxis.set_major_formatter(PercentFormatter(1))
    ax.axvline(.5,color='#809299',linestyle='--',linewidth=1)
    ax.set_xlabel('Recovery · separate experiments and decoders · Wilson 95% intervals')
    ax.spines[['top','right','left']].set_visible(False)
    fig.savefig(output/'scenarios.svg');fig.savefig(output/'scenarios.png',dpi=160);plt.close(fig)
    fig,ax=plt.subplots(figsize=(9,3.6),layout='constrained')
    ps=s['curve'];xs=[p['filing'] for p in ps]
    ax.plot(xs,[p['rate'] for p in ps],'o-',color='#177b63',label='Observed expected-value recovery')
    ax.fill_between(xs,[p['wilson_95'][0] for p in ps],[p['wilson_95'][1] for p in ps],color='#177b63',alpha=.12)
    ax.plot(xs,[p['predicted'] for p in ps],'--',color='#83958b',label='Declared on-time prediction')
    ax.axvspan(4.1,8.1,color='#f0f3f1',zorder=0);ax.set_xlim(0,8.1);ax.set_ylim(.35,1.02)
    ax.set_xlabel('Attempts per secret · at most four admitted');ax.set_ylabel('Recovery')
    ax.yaxis.set_major_formatter(PercentFormatter(1));ax.legend(fontsize=9,loc='lower right')
    fig.savefig(output/'filings.svg');fig.savefig(output/'filings.png',dpi=160);plt.close(fig)
    for path in output.glob('*.svg'):
        path.write_text('\n'.join(line.rstrip() for line in path.read_text(encoding='utf-8').splitlines())+'\n',encoding='utf-8',newline='\n')


def render(s,p,old,history_href):
    e=html.escape
    after=s['primary']['after'];before=s['primary']['before'];b=s['budget'];first=s['diagnostics']['attack-filing-01.jsonl']
    ideal=old['qwen']['recovery'];previous=old['useful-crash']['primary']
    scenarios=[('Equal-score crash','Planted canary; status decoder',ideal['naive_status_attack']['status'],ideal['artt_status_attack']['status']),
               ('Useful-score crash','Assertion order; status + scores',previous['before_joint'],previous['after_joint']),
               ('Expected-value crash','Which valid assertion is checked; status + scores',before,after)]
    scenario_rows=''.join(f'<tr><td>{e(label)}</td><td>{e(method)}</td><td>{a["correct"]}/{a["n"]}</td><td>{z["correct"]}/{z["n"]} ({z["rate"]:.1%})</td></tr>' for label,method,a,z in scenarios)
    utility_rows=''.join(f'<tr><td>{label}</td><td>{v["exact_truth"]:.1%}</td><td>{v["estimate"]:.3f}</td><td>{v["hoeffding_95"][0]:.3f}–{v["hoeffding_95"][1]:.3f}</td><td>{v["error"]:+.3f}</td></tr>' for axis,label in (('deception','Hidden-suite pass fraction'),('sycophancy','Signature-match fraction')) for v in [s['honest'][axis]])
    curve_rows=''.join(f'<tr><td>{v["filing"]}</td><td>{v["correct"]}/{v["n"]} ({v["rate"]:.1%})</td><td>{v["wilson_95"][0]:.1%}–{v["wilson_95"][1]:.1%}</td><td>{v["admitted_per_trial"]} / {v["refused_per_trial"]}</td><td>{v["admitted_per_trial"]*b["epsilon_per_release"]:.4f}</td></tr>' for v in s['curve'])
    diagnostics=''.join(f'<tr><td>{e(name)}</td><td>{d["frames_before_cutoff"]}</td><td>{e(str(d["worker_errors"]))}</td><td>{d["backend_calls"]}</td><td>{d["max_publication_jitter_seconds"]:.4f}s</td></tr>' for name,d in s['diagnostics'].items())
    links=' · '.join(f'<a href="../{e(name)}">{e(name)}</a>' for name in s['ledger_files']+s['unsafe_ledger_files'])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hidden expected-value evaluation</title>{STYLES}<style id="contributions-layout">nav{{flex-wrap:wrap;overflow:visible;white-space:normal;gap:10px 22px}}#secret code{{white-space:pre-wrap}}</style></head><body><header><div class="masthead"><span class="wordmark">A Right to Test</span><span class="report-label">Committed experiment · published evidence</span></div><h1>Useful scores can reveal a hidden expected value</h1><p class="lede">The secret changes which valid assertion the evaluator checks. ARTT suppresses error status and meters noisy score releases; it does not make a bit private at this noise level.</p><p class="context">Qwen3-0.6B only · 128 attack patches + 48 honest patches · 48 tiny tasks · fixed public patch replay · zero new GPU generations</p><nav><a href="#result">Results</a><a href="#contributions">Contributions</a><a href="#impact">Impact</a><a href="#secret">Hidden expected value</a><a href="#privacy">Privacy cost</a><a href="#utility">Honest utility</a><a href="#filings">Repeated filings</a><a href="#evidence">Evidence</a></nav></header><main>
<section id="result"><h2>Measure released status and scores together</h2><p>The new expected-value attack recovers <b>{before['correct']}/{before['n']}</b> from exposed exact outcomes and <b>{after['correct']}/{after['n']} ({after['rate']:.1%})</b> from its first noisy release. First-release Wilson 95% interval: {after['wilson_95'][0]:.1%}–{after['wilson_95'][1]:.1%}; declared on-time prediction: {after['predicted']:.1%}.</p><div class="scroll"><table><thead><tr><th>Experiment</th><th>Private fact / decoder</th><th>Exposed exact outcome</th><th>First ARTT release</th></tr></thead><tbody>{scenario_rows}</tbody></table></div><figure><img src="scenarios.svg" alt="Three retained crash scenarios, each with its own cohort and decoder"><figcaption>Before/after comparisons are paired within each experiment. Experiments are separate; counts and intervals are not pooled. The equal-score result remains a useful isolation of status suppression.</figcaption></figure><p>Expected-value choices were sampled independently, without forcing balance. Always-zero accuracy in this cohort is {s['primary']['always_zero_baseline']:.1%}; the empirical majority baseline is {s['primary']['empirical_majority_baseline']:.1%}. These are descriptive baselines, not decoder inputs. Accuracy is not a measurement of Shannon information leaked.</p><p>The first attack batch received {first['frames_before_cutoff']}/{after['n']} proposals before cutoff; maximum publication jitter was {first['max_publication_jitter_seconds']:.4f}s. Late proposals and all errors remain included. Timing leakage is not measured.</p></section>
{CONTRIBUTIONS}
<section id="secret"><h2>The expected value affects correctness</h2><p>For each existing task, the protocol selects two valid assertions with different expected values. A private bit selects which assertion is included; the three other checks stay common. For example, the slugify suite includes either <code>assert slugify('') == ''</code> or <code>assert slugify('  A  B ') == 'a-b'</code>. These are actual correctness checks with different inputs and expected outputs. The private fact is which case the hidden suite tests.</p><p>The judge executes the honest pass/signature rubric, reads the expected-value literal from the selected executable assertion, and aborts for candidate one. Candidate zero retains the genuine scores; an abort uses the normal zero fallback. No canary comment is used. Both candidate suites are public possibilities; the trial's choice remains private during evaluation. The model receives neither suite.</p><p>Public fixed-candidate controls pass {s['normal']['candidate_passes'][0]}/128 and {s['normal']['candidate_passes'][1]}/128 suites. Their score disagreements are {s['normal']['candidate_score_disagreements']}; control errors are {e(str(s['normal']['control_errors']))}. The decoder knows each patch's candidate-zero ordinary score. This is strong explicit side information. All retained patches count, including incorrect code.</p><p class="note">This protects a meaningful hidden-suite choice, but still uses synthetic sampling and a hand-written malicious judge. It is not evidence of a production breach, autonomous discovery or whole-suite theft. There is one 0.6B model, fixed replay and 48 tiny tasks; the study does not establish generalization to larger models or unseen tasks.</p></section>
<section id="privacy"><h2>Four releases cost ε = {b['epsilon_per_secret_at_cap']:.2f} per secret</h2><p>Each admitted two-score record costs ε = 2 ln 3 = {b['epsilon_per_release']:.4f}. Four admissions cost <b>ε = {b['epsilon_per_secret_at_cap']:.4f}</b>; refusals add zero epsilon and zero backend calls. <b>At this noise level, ARTT meters the channel rather than making one bit private.</b></p><p>This per-secret bound concerns the defined noisy status/score interface under this replay experiment's isolated per-item contexts and trusted publisher. Each worker receives only one independently sampled private suite; no cross-item private state is available. This is not a locality theorem for arbitrary submitted evaluators, and it excludes timing.</p><p>The new experiment has its own declared 704-admission budget for newly sampled hidden-suite choices, with no cap raises. The conservative sum over its independent items is ε = {b['epsilon_experiment_sum']:.4f}. Historical <code>coding-demo-corpus</code> remains at 5,008/5,008 and ε = {b['historical_epsilon_unchanged']:.4f}. Those costs are retained, not reset or reassigned. Reusing a secret across models, accounts, programs or later experiments requires composition against that same asset.</p><p>Asset and item reservations are atomic in one SQLite database. The attack's item refusals occur while the experiment allowance still has unused utility capacity: shared attack charges stay at 512, and attack backend calls stay at 512. This demonstrates the item cap independently of exhaustion of the shared allowance.</p><p class="note">Exact comparisons, recovery aggregates and research diagnostics make the entire research transcript non-private. The finite epsilon bound describes the noisy release interface, not this published research package.</p></section>
<section id="utility"><h2>Honest scoring utility on the same scenario</h2><p>A separate 48-item honest cohort uses the identical expected-value suite construction and ordinary rubric, with four noisy evaluations of each fixed patch and private suite: 192 observations. Its secrets are independent of the attack cohort and have their own four-release caps. One separately charged exact control per item supplies the measured truth.</p><div class="scroll"><table><thead><tr><th>Rubric</th><th>Exact truth, 48 patches</th><th>Noisy estimate, 192 releases</th><th>Hoeffding 95% interval</th><th>Estimate minus truth</th></tr></thead><tbody>{utility_rows}</tbody></table></div><p>The inverse-noise estimator is mean(released bucket) − 1 at p = 0.5. Intervals remain untruncated and describe release noise on these fixed patches, not uncertainty about unseen tasks. All failures and late defaults remain included; exact honest worker errors: {s['exact_honest_errors']}. This measurement quantifies both remaining leakage and scoring utility at the same noise setting.</p></section>
<section id="filings"><h2>All prefixes through the item cap</h2><figure><img src="filings.svg" alt="Expected-value recovery at every filing and after refusal"><figcaption>Observed recovery need not increase monotonically. Shading shows pointwise Wilson intervals; the dashed prediction assumes the declared attack and on-time proposals. Refusals reuse the last guess.</figcaption></figure><div class="scroll"><table><thead><tr><th>Attempt</th><th>Recovery</th><th>Wilson 95% interval</th><th>Admitted / refused per secret</th><th>ε per secret</th></tr></thead><tbody>{curve_rows}</tbody></table></div></section>
<section id="evidence"><h2>Published, verifiable evidence</h2><p>All {len(s['verification'])} merged ledgers and their checkpoints verify. Original comparator source chains, source snapshot hashes, durable budgets, prefix arithmetic and honest-utility estimates are checked. The run made {b['all_backend_calls']} protected replay calls: 704 noisy admissions plus 432 separately charged exact controls. Report generation makes zero private accesses or model calls. Exact attack outcome deviations: {s['exact_attack_deviations']}.</p><p><a href="../protocol.json">Committed protocol</a> · <a href="../summary.json">Counts and diagnostics</a> · <a href="../start.json">Source hashes and pre-access commitments</a> · <a href="../completion-receipt.json">Completion receipt</a> · <a href="../public-patches.jsonl">Every public patch</a> · <a href="../source-snapshot/">Archived source</a> · <a href="artifact-checks.json">Report checks</a> · <a href="{e(history_href)}/publication-manifest.json">Earlier publication manifest</a></p><p>Historical evidence is published separately, preserving its original bytes and identities. The publication manifest uses portable labels. Old hash-committed metadata and source snapshots retain historical layout strings rather than being silently rewritten. Private choices were discarded; recovery and bootstrap totals remain trusted custodian aggregates, not independently recounted labels.</p><details><summary>Every execution diagnostic</summary><div class="scroll"><table><thead><tr><th>Batch</th><th>Frames before cutoff</th><th>Worker errors</th><th>Backend calls</th><th>Max publication jitter</th></tr></thead><tbody>{diagnostics}</tbody></table></div></details><details><summary>All raw release and comparator ledgers</summary><p>{links}</p></details></section><footer>Protocol {e(s['protocol_id'])}<br>Committed before private assignment: {e(s['protocol_commit'])}<br>Protocol SHA-256: {e(s['protocol_sha256'])}<br>Trusted custodian; Linux software sandbox; timing noninterference unproved. Execution: {s['wall_seconds']:.1f} seconds.</footer></main></body></html>'''


def generate(directory,history,output):
    directory,history,output=map(Path,(directory,history,output))
    if output.exists():raise ValueError('fresh_report_directory_required')
    s,p=verify(directory);old=historical(history)
    output.mkdir(parents=True)
    plots(s,old,output)
    import os
    history_href=Path(os.path.relpath(history,output)).as_posix()
    (output/'report.html').write_text(render(s,p,old,history_href),encoding='utf-8')
    write_json(output/'artifact-checks.json',{'status':'passed','ledger_and_checkpoint_verification':True,'archived_source_hashes':True,
        'durable_budget_accounting':True,'utility_recomputed_from_192_records':True,'historical_publication_hashes':True,
        'private_accesses':0,'model_generations':0,
        'report_html_sha256':sha((output/'report.html').read_bytes()),
        'reporting_source_sha256':sha(Path(__file__).read_bytes()),
        'recovery':'trusted custodian aggregates; private choices discarded'})
    print((output/'report.html').resolve())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True)
    parser.add_argument('--history',default='results/coding-agent-history-2026-10-11')
    parser.add_argument('--output',required=True)
    args=parser.parse_args();generate(args.input,args.history,args.output)


if __name__=='__main__':main()
