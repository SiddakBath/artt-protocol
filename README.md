# A Right to Test: Public Evaluation Under Output Confidentiality

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23180546.svg)](https://doi.org/10.5281/zenodo.23180546)

## Why this matters

Today, the most powerful AI models are mostly tested by the labs that build them, by partners they choose, or by government institutes under negotiated access. Independent researchers, journalists and the public have to take the results on trust. A right to test would change that. Anyone could submit an evaluation that runs inside a sealed environment next to the model, and only a small public verdict would come out. The model stays private, and the results are public and checkable. That could let outside researchers check safety claims, regulators run their own audits without getting the weights, and the public see which tests a lab refused. It could also let competitors compare models fairly on the same sealed tests. The catch is that the verdict is a way out of the seal. If an evaluator can sneak private model outputs out through it, nobody will agree to host one. This project demonstrates that failure end to end, then builds a release interface that suppresses its status signal and quantifies the score channel that remains.

## What ARTT closes and what it accounts for

ARTT publishes one fixed-shape, noised record per run on a fixed schedule, with the budget charged before the model is touched. It removes status as a separate public channel: on Qwen3-0.6B, the constant-score attack falls from 256/256 recovery to 128/256. For that attack, success and failure have exactly equal public-record distributions, so optimal recovery is 1/2 for any number of filings. Score leakage is an explicit tradeoff: a judge that deliberately writes a secret into the score receives a noisy, logged release that consumes a declared admission budget, while an honest evaluator can still distinguish two literal-format conditions. At p = 1/2, each two-axis record costs ε = 2 ln 3; a total cap B per model snapshot gives 2B ln 3 under the paper's trust and delivery assumptions.

An admission is a charged authorization for one judge execution, permitting at most one private model call in this prototype. Failures and timeouts still count. The custodian declares the cap's scope: an item cap limits repeated admissions of one protected item; a corpus cap limits the total across its items. Counters are shared across filers and program aliases. They count authorized executions, rather than successful calls or questions inside a prompt.

The contribution is an end-to-end demonstration: a malicious evaluation can exploit the public exit even when the proposed score is constant; a protocol can remove that status path; and the remaining score path can be accounted for in public records. The public ledger, fixed-shape fallback release, admission accounting, attack, repair, and measurements are part of one implementation rather than separate assumptions.

ARTT requires every filing, refusal, and released result to appear in a public hash-chained ledger. This makes the process checkable, while the privacy guarantee remains a property of the protected records rather than the ledger itself.

## Quick start

Run these commands from the repository root in WSL or another Linux environment with `unshare`, `libseccomp.so.2`, GCC, and Python 3.11 or later:

```bash
python3 -m venv .venv && .venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python -m rt.build_sandbox
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q -p no:cacheprovider
.venv/bin/python -m tools.research_audit --output results/recheck.json
```

The first three commands install the pinned test dependency, build the Linux sandbox launcher, and run the test suite. The last command verifies the retained public chains, source snapshots, arithmetic, and paper structure without model inference.

The code and retained chains are public. A small live fixture demo runs through
the shipped scheduled publisher without a GPU or downloaded model:

```bash
.venv/bin/python -m tools.multibit_attack --output scratch/fixture-demo --live --trials 2 --admissions 16 --cap 16 --skip-capped --kernel-trials 1000
```

Use a fresh output directory for each demo. This exercises admission charging,
noisy releases and post-cap refusals with planted fixture bits; the learned-model
Qwen experiment is separate.

v0.1.2 passed 71 tests in the WSL environment.

The 8 October preparation passed 84 tests in WSL, including regressions for
interrupted evidence, incompatible resumes, late fallbacks and audit arithmetic.
See [the preparation record](results/readiness-2026-10-08/README.md) for the
retained-chain audit and paper build checks.

## Repository map

- `rt/` contains the filing, isolation, release, logging, and budget code.
- `judges/`, `examples/`, and `fixtures/` hold the executable study inputs.
- `tests/` contains the Linux sandbox and analytical tests.
- `tools/` contains the audit and analysis scripts.
- `paper/` contains the paper, proofs, public note, and figures.
- `results/` contains the retained evidence and its [evidence index](results/README.md).

## Main results

The [evidence index](results/README.md) links the primary Qwen release records, the schema curve, the privacy and utility calculations, and the final integrity audit. The [paper source](paper/draft.tex) gives the protocol, theorem, and full interpretation of the results.

### Learned-model status attack and repair

The Qwen3-0.6B study is the learned-model experiment. A judge whose score never changes recovers a planted secret in 256/256 trials from accepted versus error status. Under ARTT's fixed-slot fallback release, the same status decoder is at chance in every phase, including deliberate timeouts. The same honest records retain a literal-format contrast of 0.742, with a conservative finite-sample interval from 0.233 to 1.252.

### Repeated score-channel study

The sixteen-bit study exercises the shipped scheduled publisher and admission accounting with a fixture completion that carries the planted bit; it adds no Qwen inference. Its caps of 16 and 48 admissions are totals across all sixteen protected items in each trial. The first sixteen admissions visit each item once; further admissions revisit uncertain items. One admission per bit recovers 104/9 correct bits in expectation. At 48 admissions, 64 retained completed trials recovered 14.31 correct bits on average (standard error 0.157), close to the frozen 14.481 decoder expectation. For this one-bit-per-context construction, the same public records carry 0.2314 Shannon bits per two-axis admission, giving ceilings of 3.70 bits at 16 admissions and 11.11 at 48. This is not a protocol-wide cap: the raw two-axis channel has capacity 0.4150 bits per record at the same noise level for richer secrets. One interrupted attempt was replaced and its evidence was lost; read [the evidence limitation](results/multibit-rerun-2026-10-07/EVIDENCE-LIMITATIONS.md).

To regenerate the figure from the retained sample and its locally frozen
Monte Carlo comparator, without rerunning the experiment (requires matplotlib;
the test suite and live fixture demo do not):

```bash
python -m tools.multibit_attack --plot-from results/multibit-rerun-2026-10-07/results.json --comparator results/multibit-rerun-2026-10-07/protocol.json
```

New live experiments use a fresh output directory and record their settings
before execution. `--resume` requires identical settings and intact completed
evidence. Incomplete attempts are preserved and require a new cohort rather
than automatic replacement. Late and failed proposals remain in the sample
through the protocol's noisy fallback.

## ARTT on a coding-agent evaluation

Coding agents are judged on hidden tests. This demo runs 48 small Python tasks through two release paths with deterministic fixture agents, not learned models.

On a naive design that publishes status, the constant-score abort attack recovered its planted canary in 128/128 (1.0000; 95% interval 0.9709 to 1.0000).
Under ARTT the same attack recovered it from status in 64/128 (0.5000; 95% interval 0.4147 to 0.5853) and from scores in 58/128 (0.4531; 95% interval 0.3695 to 0.5395).
The deliberate score encoder recovered it in 88/128 (0.6875; 95% interval 0.6027 to 0.7613); its predicted optimal recovery is 0.7222. The score channel is bounded and logged, not closed.

Honest fixture A estimate: 0.7500, 95% interval 0.1619 to 1.3381.
Honest fixture B estimate: 0.3958, 95% interval -0.1922 to 0.9839.
A minus B: 0.3542, 95% interval -0.4775 to 1.1858. The conservative interval includes zero; this run does not establish separation.

Each batch is a separate hash-chained ledger. Edited and middle-deleted copies are checked by `python -m rt.verify`; tail deletion needs a retained checkpoint. CT-style witnessing is future work.

Budget: 352 admitted, 8 refused; epsilon per record 2.1972, total 773.4231. The post-cap call count is unchanged: 608 before, 608 after.

Run it on Linux or Windows via WSL:

    .venv/bin/python -m rt.build_sandbox
    make demo

On Windows use `scripts/demo.ps1`. Every run needs a fresh output directory. Open `scratch/coding-demo/report.html`.

Scope: deterministic fixture agent; single model call per admission; trusted custodian; software sandbox, not hardware. Timing noninterference is not proven. The passport export is a proposed mapping, not an official AIUC or Lucid format.

Observed runtime: 151.4645 seconds. Commit: `3ed8b0203a3bc65080999ff02a472894c3f59506`. Protocol SHA256: `de79dadef4712648eb8e8f71f04db2e17dee5e2bb70856d1ccee8149efbe73b8`.

Decoder results from summary.json:

- naive_status_attack / status: 128/128 (1.0000; 95% interval 0.9709 to 1.0000)
- naive_status_attack / score: 83/128 (0.6484; 95% interval 0.5625 to 0.7257)
- artt_status_attack / status: 64/128 (0.5000; 95% interval 0.4147 to 0.5853)
- artt_status_attack / score: 58/128 (0.4531; 95% interval 0.3695 to 0.5395)
- naive_score_attack / status: 64/128 (0.5000; 95% interval 0.4147 to 0.5853)
- naive_score_attack / score: 89/128 (0.6953; 95% interval 0.6108 to 0.7684)
- artt_score_attack / status: 64/128 (0.5000; 95% interval 0.4147 to 0.5853)
- artt_score_attack / score: 88/128 (0.6875; 95% interval 0.6027 to 0.7613)

Observed tamper checks:

- edited: INVALID log; checkpoint matches: True
- middle_deleted: INVALID log; checkpoint matches: False
- suffix_deleted: VERIFIED 63 entries (chain integrity only; no hardware attestation); checkpoint matches: False

Separately predeclared utility-only follow-up (the first run above remains unchanged):

1152 admissions per fixture agent, repeating the same fixed 48-task corpus. No pooling with the first utility sample.
Follow-up A: 0.7543, 95% interval 0.6343 to 0.8744.
Follow-up B: 0.4019, 95% interval 0.2819 to 0.5220.
Follow-up A minus B: 0.3524, 95% interval 0.1827 to 0.5222. The conservative interval excludes zero.
Additional admissions: 2304. The public budget extension carries forward the first 352 charges; total used is 2656 against an extended cap of 2656. Additional epsilon: 5062.4054; combined scope total: 5835.8285.
Utility protocol SHA256: `64601a79b768a70ac1ebcdd4776158a9e38507a3e38713358a290bae8aeb0f6c`; predeclared in `6e06fe4c8202a847e4764abfdfb23b572ca93018`. Observed utility runtime: 440.0329 seconds.

## Limitations

- The guarantee assumes trusted isolation, accounting, custody, and fixed-slot delivery.
- Hardware custody, host telemetry, and physical timing noninterference require further work.
- This is a narrow canary and literal-format task. It does not settle semantic alignment evaluation or leakage from model-wide secrets.

## Citation

Please cite the project using [CITATION.cff](CITATION.cff). The project record is
available at [doi:10.5281/zenodo.23180546](https://doi.org/10.5281/zenodo.23180546).

## License

Code is licensed under Apache 2.0 (see LICENSE). The paper in paper/ is licensed under CC BY 4.0 (see paper/LICENSE).

## Source archives

Release source archives use `git archive` and the exclusions in `.gitattributes`.
They include the paper source and required figures, code, tests and retained
evidence. Generated PDFs, local environments, caches, scratch work and build
outputs are excluded. The compiled paper is distributed separately. Each archive
is accompanied by a SHA-256 checksum and must match its declared release version.
An uncommitted candidate package uses the same exclusions and contains the latest
working-file bytes; it is not an archive of the previous release tag.
