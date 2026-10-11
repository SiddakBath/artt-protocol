# A Right to Test: Public Evaluation Under Output Confidentiality

[Paper](https://doi.org/10.5281/zenodo.23180546) · [Paper source](paper/draft.tex) · [Coding demo and recorded results](demos/coding_agent/README.md) · [Evidence index](results/README.md)

Let outsiders run evaluations while protecting what the evaluator can read. This coding demo protects the **hidden test suite**: a malicious judge tries to publish a private bit through a crash or a score. ARTT hides admitted error status, adds noise to scores, and charges each admitted release against a declared budget. We report both equal-score and useful-score crash scenarios.

![Separate crash cohorts: equal-score status recovery falls from 128/128 to 64/128; useful-score joint recovery falls from 128/128 to 98/128](demos/coding_agent/assets/useful-crash-comparison.svg)

The equal-score scenario isolates status leakage in the retained live Qwen3-0.6B cohort: **128/128 → 64/128** with a status-only decoder. The useful-score scenario retains genuine test and signature scores on success and uses zero fallback on a crash: **128/128 → 98/128 (76.6%)** using status and scores together, with public normal-score controls. Its first-release Wilson 95% interval is 68.5%–83.1%. Comparisons are paired within each scenario; the two cohorts are separate and are not pooled. Whiskers are descriptive Wilson intervals. Earlier evidence is retained.

The useful-score run replays all 128 pinned public Qwen patches across 48 tiny tasks, including the 50 incorrect patches, with zero fresh GPU generations. Its private bit selects the order of executable hidden assertions. It remains a controlled, hand-written attack rather than a production incident or autonomous test theft. See [both scenarios and the committed protocol](demos/coding_agent/README.md#equal-score-and-useful-score-crash-results).

## Quick start: coding demo

On Linux or Windows through WSL, with Python 3.11+, GCC, `unshare` and `libseccomp.so.2`:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python -m rt.build_sandbox
make demo
```

Open `scratch/coding-demo/report.html`. The default uses deterministic fixture agents and needs no GPU or model download. Every run needs a fresh directory; use `make demo OUTPUT=scratch/coding-demo-next` for another run. Windows also has `scripts/demo.ps1`.

The [live model option](demos/coding_agent/README.md#optional-live-local-model) uses local Qwen3-0.6B to produce patches. The custodian appends hidden tests after generation; the malicious judge sees them. The [repeated-filings experiment](demos/coding_agent/README.md#exact-score-baseline-and-repeated-filings) replays frozen public Qwen patches to isolate repeated releases: uncapped recovery reaches 128/128 at 16 filings; ARTT stops releasing scores after four per secret, with 109/128 recovery and 1,536 later refusals. Protected replay calls stay at 512. This curve makes no new GPU generations; its separate exact baseline generated 128 fresh patches.

## What the result means

In the equal-score scenario, the judge crashes for bit 1 and succeeds for bit 0. Public error status reveals the bit. ARTT publishes the same admitted record shape in both cases. The status decoder always guesses 0, and the balanced sample has 64 zeros: **64/128 is exactly half by construction**. Both branches have identical raw scores and therefore identical noisy-score distributions. This assumption isolates the benefit of suppressing status; it does not establish chance-level recovery for arbitrary evaluators.

In the useful-score scenario, status suppression still works, but scores retain a signal. The capped arm recovers 98/128 after one admission and 102/128 after four, then refuses 512 later attempts without increasing its 512 protected replay calls. The eight-admission control recovers 120/128. All prefixes, including decreases in recovery, are retained. One late proposal in the first capped batch is included; maximum publication jitter was 0.474 seconds. Timing leakage is not measured.

The deliberate score attack still leaks. At the demo's noise setting, each admitted two-score record costs **ε = 2 ln 3 ≈ 2.1972**. Refusals cost zero additional release epsilon. The budget limits the number of releases an attacker can combine; the ledger records the cost and detects editing. A retained checkpoint is needed to detect deletion of a final row. Large experimental caps are not strong privacy settings.

The coding runs used one shared counter, raised from 352 to 2,656, then 2,960, then 3,472, then 5,008 by committed protocols. Both new noisy arms contribute all 1,536 admissions to that total. The [accounting note](demos/coding_agent/README.md#privacy-accounting-and-policy-history) shows model attribution and all four cap raises. Exact/status-visible comparators make the combined experimental transcript non-private; finite epsilon accounting applies only to the noisy channels. Separate model attribution does not create independent allowances for the same protected test suite.

The first fixture utility interval includes zero. A separately predeclared utility-only follow-up used 1,152 admissions per fixture and measured A minus B as 0.3524, with a conservative 95% interval of 0.1827 to 0.5222. It concerns the fixed 48-task corpus and repeated release noise. The learned-model run has only one model and makes no A/B utility claim.

## FAQ

**Why not just pre-approve the code?** Approval is useful if the custodian trusts a fixed evaluator. Public testing allows outsiders to submit new evaluations, so approval must account for what arbitrary code does after seeing private information, including secret-dependent crashes and scores. The sandbox restricts execution; the release interface separately restricts what can leave it. This demo shows why a small verdict alone is insufficient.

**Can two accounts split a secret?** They can combine their observations, so the custodian must charge them to the same protected scope. Budgets must be shared across accounts and program aliases, keyed to the protected asset and committed model snapshot. If multiple model paths access the same hidden tests, those paths need shared asset accounting too. Giving each account a fresh cap would break the intended protection.

**Was this a real problem?** The crash and score leaks ran through actual evaluators and a Linux sandbox, with real local Qwen-generated patches in the learned-model experiment. The equal-score scenario uses a planted canary; the useful-score scenario uses a synthetic private assertion order and frozen public patch replay. These demonstrate reproducible leak mechanisms in an evaluation interface; they do not document a production breach or stolen proprietary tests. The custodian, isolation and delivery are trusted, and timing noninterference is not proven.

## Verify and explore

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q -p no:cacheprovider
.venv/bin/python -m tools.research_audit --output scratch/recheck.json
```

The [evidence index](results/README.md) also covers the earlier learned-model study, multi-bit score study, privacy and utility calculations, and integrity audits. Its [interrupted-run limitation](results/multibit-rerun-2026-10-07/EVIDENCE-LIMITATIONS.md) remains part of the record. Counts and intervals belong to their declared cohorts; they are not pooled across experiments.

- `demos/coding_agent/`: coding tasks, fixture and local-model runners, protocols and report generation.
- `rt/`: isolation, release, logging and budget code.
- `judges/`, `examples/`, `fixtures/`: executable study inputs.
- `tests/`, `tools/`: regression checks and evidence audits.
- `paper/`, `results/`: paper, proofs, figures and retained research evidence.

Cite using [CITATION.cff](CITATION.cff). Code is [Apache 2.0](LICENSE); the paper is [CC BY 4.0](paper/LICENSE). Release source archives follow `.gitattributes`; generated PDFs, environments and scratch outputs are excluded. The compiled paper is distributed separately.
