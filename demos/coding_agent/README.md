# ARTT on a coding-agent evaluation

[Paper](https://doi.org/10.5281/zenodo.23180546) · [Quick start](../../README.md#quick-start-coding-demo) · [Combined results](../../results/coding-expected-value-2026-10-12/report/report.html)

The protected asset is the **hidden test suite**: which of two valid assertions
with different expected values is included. Recovery is **128/128 → 90/128 (70.3%)**
after one ARTT release and **101/128** after four, with honest utility at the same
noise setting. Optimal equal-score and earlier assertion-order controls remain visible.

## Run the demo

From the repository root on Linux or Windows via WSL, after the top-level setup:

```bash
.venv/bin/python -m rt.build_sandbox
make demo
```

On Windows, use `scripts/demo.ps1`. Open `scratch/coding-demo/report.html`.
The runner refuses existing output directories; for another run use
`make demo OUTPUT=scratch/coding-demo-next`. Reported cohorts are already
published under `results/`; do not rerun them or reuse an older budget snapshot.
A new measured cohort needs a predeclared protocol and current accounting.

### Default fixture demo

The default needs no GPU or download. Agent A and Agent B are deterministic
fixtures that pass 36 and 19 of the 48 tiny Python tasks by construction.
The judge receives a patch, hidden assertions and a private canary comment.
A constant-score judge leaks the canary through accepted/error status;
scheduled release gives both branches the same fallback and noise distribution.
A deliberate score encoder still receives a noisy signal, bounded and logged.

The offline report shows recovery, Wilson and Hoeffding intervals, searchable
records, honest estimates, budgets and tamper checks.

## Expected-value secret and honest utility

[Predeclared protocol](expected-value-protocol.json) · [Offline report](../../results/coding-expected-value-2026-10-12/report/report.html)

The protocol was committed before private sampling. Each independent choice
selects one of two valid assertions with different expected values; three
checks stay common. For slugify, the alternatives test empty input and
whitespace normalization. The judge runs the genuine rubric, parses the
selected expected-value literal and aborts for candidate one.

All 128 attack patches and 48 honest patches are retained Qwen3-0.6B indices,
without repair, filtering or regeneration. Candidate suites and candidate-zero
ordinary scores are public attacker side information. Choices are sampled
once without forced balance; the decoder reads released status and scores.

Recovery is **128/128 exact**, **90/128 after one release** (Wilson 95%:
61.9%–77.5%; declared prediction: 70.1%) and **101/128 after four**. The retained
prefixes are `59, 90, 96, 98, 101, 101, 101, 101, 101` out of 128. Always-zero
and empirical majority baselines are 46.1% and 53.9%. Public candidate controls
pass 78/128 and 80/128 suites, with two genuine score disagreements.

At four admissions the declared prediction is 85.4%; observed recovery is 78.9% (Wilson 95%: 71.0%–85.1%), so the prediction lies just above the interval. The assertion-order cohort was also below prediction at its cap (102/128 against 85.4%). We report this as observed and have not adjusted the decoder or prediction.

The fixed allowance is **704 noisy admissions**: 512 attack and 192 honest.
Experiment and four-release item reservations are atomic in one SQLite
database. The 512 later attack refusals add no charge or backend call while
honest capacity remains. Another 432 exact/control accesses are separately
charged; the run makes 1,136 protected replay calls and zero new GPU generations.

At p = 0.5, each two-score release costs ε = 2 ln 3; four cost
**ε = 8.7889 per secret**. The conservative experiment sum is ε = 1,546.8461.
**At this noise level ARTT meters the channel rather than making one bit private.**
The conditional bound and transcript limitations are stated in [Scope](#scope).

Honest utility uses 48 independently assigned suites, one exact control and four
noisy evaluations per patch. The estimator is mean(released bucket) − 1, with untruncated Hoeffding intervals.

| Honest rubric | Exact fraction, 48 patches | Noisy estimate, 192 releases | Hoeffding 95% interval | Error |
| --- | ---: | ---: | ---: | ---: |
| Hidden-suite pass | 0.604 (29/48) | 0.510 | 0.216–0.804 | -0.094 |
| Signature match | 1.000 (48/48) | 1.010 | 0.716–1.304 | +0.010 |

Both exact truths lie inside their intervals. Regenerate the report without protected access:

```bash
python -m demos.coding_agent.expected_value_report --input results/coding-expected-value-2026-10-12 --output scratch/expected-value-report-next
```

Opening published HTML needs no packages. Before regenerating figures, install
the optional dependencies with `python -m pip install -r requirements-report.txt`.

## Equal-score and useful-score crash results

| Scenario | Successful / crashed raw scores | Decoder | Exact outcome | First ARTT release |
| --- | --- | --- | ---: | ---: |
| Equal scores, live Qwen cohort | (0, 0) / (0, 0) | Status | 128/128 | 64/128 (50.0%) |
| Useful scores, Qwen patch replay | Honest scores / (0, 0) | Status and scores | 128/128 | 98/128 (76.6%) |

The equal-score control isolates status suppression. Its status decoder guesses
zero on a balanced cohort; its score decoder observes 67/128 against a declared
50% prediction because both noisy-score distributions are identical.

The useful-score secret is assertion order. Ordinary controls pass 78/128
suites and match all signatures; swapping order changes no ordinary score.
The attacker knows these public scores. First-release recovery is 98/128
(Wilson 95%: 68.5%–83.1%); the four-release arm reaches 102/128, then refuses
512 attempts without increasing its 512 replay calls. The eight-release
control reaches 120/128. All prefixes are retained, including decreases and
one late proposal in the first capped batch. Item and shared allowances expire
together here; their effects are not separately identified. Both noisy arms
contribute 1,536 admissions to the historical budget, and all 19 chains verify.

[Crash comparison](assets/useful-crash-comparison.svg) · [Every filing prefix](assets/useful-crash-filings.svg)

## Separately predeclared utility follow-up

The initial fixture difference interval includes zero. A utility-only study
uses 1,152 admissions per fixture on the same 48 tasks and measures A minus B
as 0.3524, with a conservative 95% interval of 0.1827–0.5222. Its 2,304 releases
carry forward the first 352 charges and extend the shared cap to 2,656.
Regenerate the review from published inputs:

```bash
python -m demos.coding_agent.review_report --first-run results/coding-agent-history-2026-10-11/first --utility-run results/coding-agent-history-2026-10-11/utility --output scratch/coding-demo-review-next
```

## Optional live local model

`--backend local-qwen` uses an offline Qwen3-0.6B checkpoint to generate a fresh
patch after admission. The model sees only the public task, signature and
example; hidden checks and the canary are appended afterward for the judge.
Incorrect patches count; generations are not repaired, cached or retried.

On Windows, set `$ModelPath` and `$ModelPython` to your installed checkpoint
and CUDA Python runtime, or use `ARTT_MODEL_PATH` and `ARTT_MODEL_PYTHON`:

```powershell
./scripts/demo.ps1 -Backend local-qwen -ModelPath $ModelPath -ModelPython $ModelPython -Output scratch/coding-demo-qwen-next
```

A Linux CUDA host can use the same backend flag:

```bash
python -m demos.coding_agent.run --backend local-qwen --model-path /path/to/Qwen3-0.6B --output scratch/coding-demo-qwen-next
```

Runtime dependencies are in `requirements-runtime.txt`; the demo downloads nothing.
The published live cohort uses 608 inferences and 304 new scheduled admissions;
its honest comparison is one model against its unnoised control.

## Exact-score baseline and repeated filings

The separately predeclared exact-score baseline uses 128 fresh Qwen generations
and recovers 128/128, versus 96/128 in the retained live noisy-score cohort.
Repeated filings fix 128 public patches and private bits across 16 attempts,
using fresh p = 0.5 noise and protected replay rather than GPU generation.
Uncapped recovery reaches 128/128; ARTT reaches 109/128 at four admissions,
then refuses 1,536 attempts while replay calls stay at 512.

[Repeated-filings figure](assets/repeated-filings.svg)

To regenerate the combined report, first build its retained live report from
published evidence. Both commands use fresh output directories and make no
model calls or private admissions:

```bash
HISTORY=results/coding-agent-history-2026-10-11
python -m demos.coding_agent.real_report --input "$HISTORY/qwen" --first-run "$HISTORY/first" --prior-run "$HISTORY/utility" --output scratch/coding-demo-qwen-report-next
python -m demos.coding_agent.filings_report --input "$HISTORY/filings" --prior-run "$HISTORY/qwen" --first-run "$HISTORY/first" --utility-run "$HISTORY/utility" --retained-report scratch/coding-demo-qwen-report-next --output scratch/coding-demo-filings-report-next
```

## Privacy accounting and policy history

The historical `coding-demo-corpus` counter ends at **5,008/5,008** with
conservative ε = **11,003.7007**. It is retained, not reset by the fresh-secret
expected-value experiment. Refusals add zero release epsilon; admitted errors
still count. Model attribution does not create independent asset allowances.

| Noisy-release attribution | Admissions | Cumulative ε |
| --- | ---: | ---: |
| Fixture A | 1,456 | 3,199.1590 |
| Fixture B | 1,200 | 2,636.6695 |
| Qwen3-0.6B, including replay | 2,352 | 5,167.8722 |
| Protected asset total | 5,008 | 11,003.7007 |

| Predeclared policy | Shared cap | Charges carried forward | New allowance |
| --- | ---: | ---: | ---: |
| [Initial fixtures](protocol.json) | 352 | 0 | 352 |
| [Fixture utility](utility-protocol.json) | 2,656 | 352 | 2,304 |
| [Live Qwen](real-model-protocol.json) | 2,960 | 2,656 | 304 |
| [Repeated filings](filings-protocol.json) | 3,472 | 2,960 | 512 |
| [Useful-score crash](useful-crash-protocol.json) | 5,008 | 3,472 | 1,536 |

Policy changes are reconstructed from retained protocols, not a contemporaneous event log.
Shared secrets across accounts, models or programs require composition against that asset.

## Scope

These are controlled, hand-written attacks with one 0.6B model, 48 tiny tasks, synthetic
suite choices, a trusted custodian and publisher, a software sandbox and declared side
information. They do not establish production exploitation, autonomous discovery,
training data extraction or larger-model generalization. Discarded private labels leave
recovery totals as custodian aggregates. Cohorts are not pooled: crash comparisons are
paired within experiments; the exact-score baseline and retained noisy cohort are descriptive.

The per-secret bound relies on isolated private contexts and the noisy status/score
interface. Generic per-item locality, timing and shared-queue noninterference are
unproved. Exact comparators and diagnostics make the full transcript non-private.
Intervals concern release noise on fixed patches, not unseen tasks; prefix intervals are pointwise.

Hash chains detect edits and middle deletions; retained checkpoints detect prefix
truncation. Hashes establish integrity, not execution truth or omission detection;
external witnessing remains future work. The passport implies no AIUC or Lucid endorsement.
