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
