# A Right to Test: Public Evaluation Under Output Confidentiality

[Paper](https://doi.org/10.5281/zenodo.23180546) · [Paper source](paper/draft.tex) · [Coding demo and recorded results](demos/coding_agent/README.md) · [Evidence index](results/README.md)

Let outsiders run evaluations while protecting what the evaluator can read. This coding demo protects the **hidden test suite**: a malicious judge publishes a private suite choice through a crash or a score. ARTT suppresses admitted error status, adds score noise and charges each release against a declared budget.

![Separate equal-score, useful-score and expected-value crash experiments](results/coding-expected-value-2026-10-12/report/scenarios.svg)

The new, predeclared experiment protects **which valid expected value a hidden assertion checks**, using a private choice between two different correctness checks. Recovery is **128/128 → 90/128 (70.3%)** after one ARTT release, and **101/128 (78.9%)** after four. Its first-release Wilson 95% interval is 61.9%–77.5%. Useful scores still leak after error status is hidden.

The optimal equal-score case remains visible: status-only recovery falls from **128/128 to 64/128**, with identical successful and fallback score distributions by construction. The earlier assertion-order case falls from **128/128 to 98/128** with a joint status/score decoder. Comparisons are paired within each experiment; the three cohorts and decoders are separate and their counts are not pooled.

The new run uses every pinned attack patch and 48 honest patches from **Qwen3-0.6B only**, across 48 tiny public tasks, with zero new GPU generations. Candidate suites and ordinary candidate-zero scores are known to the attacker. This remains a controlled, hand-written attack on synthetic private suite choices, with a trusted custodian and software sandbox; it does not demonstrate a production breach or larger-model generalization.

[Open the combined offline report](results/coding-expected-value-2026-10-12/report/report.html) · [Protocol and detailed results](demos/coding_agent/README.md#expected-value-secret-and-honest-utility) · [Published historical evidence](results/coding-agent-history-2026-10-11/README.md)

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

The expected-value experiment has its own fixed **704-admission budget** for fresh, independent suite choices: 512 attack and 192 honest releases. Every secret has a cap of four. Its 512 later attack refusals add no charge or backend call while honest capacity remains. At p = 0.5, four releases cost **ε = 8.7889 per secret**, conditional on this experiment's isolated private contexts and defined noisy score/status interface; timing is excluded. The conservative experiment-wide sum is ε = 1,546.8461. **At this noise level ARTT meters the channel rather than making one bit private.** Shared secrets across accounts, models or later runs would need composition.

Honest utility is measured in the same scenario: **29/48 patches pass**, and all 48 match the declared signature. Across 192 noisy observations, the pass estimate is **0.510** versus exact truth **0.604**, with a conservative untruncated 95% interval of **0.216–0.804**. The signature estimate is 1.010 versus exact truth 1.000. Intervals concern release noise on this fixed corpus, not unseen-task performance or a comparison between models.

In the equal-score scenario, the judge crashes for bit 1 and succeeds for bit 0. Public error status reveals the bit. ARTT publishes the same admitted record shape in both cases. The status decoder always guesses 0, and the balanced sample has 64 zeros: **64/128 is exactly half by construction**. Both branches have identical raw scores and therefore identical noisy-score distributions. This assumption isolates the benefit of suppressing status; it does not establish chance-level recovery for arbitrary evaluators.

In the useful-score scenario, status suppression still works, but scores retain a signal. The capped arm recovers 98/128 after one admission and 102/128 after four, then refuses 512 later attempts without increasing its 512 protected replay calls. The eight-admission control recovers 120/128. All prefixes, including decreases in recovery, are retained. One late proposal in the first capped batch is included; maximum publication jitter was 0.474 seconds. Timing leakage is not measured.

The deliberate score attack still leaks. At the demo's noise setting, each admitted two-score record costs **ε = 2 ln 3 ≈ 2.1972**. Refusals cost zero additional release epsilon. The budget limits the number of releases an attacker can combine; the ledger records the cost and detects editing. A retained checkpoint is needed to detect deletion of a final row. Large experimental caps are not strong privacy settings.

The historical coding runs used one shared counter, raised from 352 to 2,656, then 2,960, then 3,472, then 5,008 by committed protocols. The assertion-order experiment contributed all 1,536 admissions from both noisy arms to that total. The new expected-value scope does not reset those 5,008 charges. The [accounting note](demos/coding_agent/README.md#privacy-accounting-and-policy-history) shows model attribution and all four cap raises. Exact/status-visible comparators make the combined experimental transcript non-private; finite epsilon accounting applies only to the noisy channels. Separate model attribution does not create independent allowances for the same protected test suite.

The first fixture utility interval includes zero. A separately predeclared utility-only follow-up used 1,152 admissions per fixture and measured A minus B as 0.3524, with a conservative 95% interval of 0.1827 to 0.5222. It concerns the fixed 48-task corpus and repeated release noise. The learned-model studies use one model and make no A/B utility claim.

## FAQ

**Why not just pre-approve the code?** Approval is useful if the custodian trusts a fixed evaluator. Public testing allows outsiders to submit new evaluations, so approval must account for what arbitrary code does after seeing private information, including secret-dependent crashes and scores. The sandbox restricts execution; the release interface separately restricts what can leave it. This demo shows why a small verdict alone is insufficient.

**Can two accounts split a secret?** They can combine their observations, so the custodian must charge them to the same protected scope. Budgets must be shared across accounts and program aliases, keyed to the protected asset and committed model snapshot. If multiple model paths access the same hidden tests, those paths need shared asset accounting too. Giving each account a fresh cap would break the intended protection.

**What real confidential information could this expose?** A hidden assertion's expected value or inclusion can reveal which boundary case a benchmark tests and help an outsider target that check. The new protocol tests which of two valid assertions with different expected values is included, and measures genuine correctness scores. The earlier equal-score and assertion-order experiments remain diagnostic controls. This is a controlled evaluation-interface attack using public model-generated patches, not a documented production incident. The custodian and software sandbox are trusted; timing leakage is not measured.

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
