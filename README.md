# A Right to Test: Public Evaluation Under Output Confidentiality

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23180547.svg)](https://doi.org/10.5281/zenodo.23180547)

## Why this matters

Today, the most powerful AI models can only be tested by the labs that build them, or by partners they choose. Independent researchers, journalists and the public have to take the results on trust. A right to test would change that. Anyone could submit an evaluation that runs inside a sealed environment next to the model, and only a small public verdict would come out. The model stays private, and the results are public and checkable. That could let outside researchers check safety claims, regulators run their own audits without getting the weights, and the public see which tests a lab refused. It could also let competitors compare models fairly on the same sealed tests. The catch is that the verdict is a way out of the seal. If an evaluator can sneak private model outputs out through it, nobody will agree to host one. This project shows that the leak is real, and that it can be closed.

## Public verdicts can be made leak-resistant

Our release protocol publishes one fixed-shape, noised record per run on a fixed schedule, with the budget charged before the model is touched. On Qwen3-0.6B, it holds a planted secret to chance: 128/256 from run status and 124/256 from scores. An honest evaluator can still tell two model behaviors apart. This matters because without the protocol, the verdict leaks: a judge whose score never changes recovers the secret in 256/256 trials just from whether runs succeed or fail. With the channel deliberately left open, the same decoder gets 202/256, which confirms it works.

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

The frozen release passed 71 tests in the WSL environment.

## Repository map

- `rt/` contains the filing, isolation, release, logging, and budget code.
- `judges/`, `examples/`, and `fixtures/` hold the executable study inputs.
- `tests/` contains the Linux sandbox and analytical tests.
- `tools/` contains the audit and analysis scripts.
- `paper/` contains the paper, proofs, public note, and figures.
- `results/` contains the retained evidence and its [evidence index](results/README.md).

## Main results

The [evidence index](results/README.md) links the primary Qwen release records, the schema curve, the privacy and utility calculations, and the final integrity audit. The same-run honest formatting comparison estimates a difference of 0.742 with an interval from 0.459 to 1.025. The [paper source](paper/draft.tex) gives the protocol, theorem, and full interpretation of the results.

## Limitations

- The guarantee assumes trusted isolation, accounting, custody, and fixed-slot delivery.
- Hardware custody, host telemetry, and physical timing noninterference require further work.
- This is a narrow canary and literal-format task. It does not settle semantic alignment evaluation or leakage from model-wide secrets.

## Citation

Please cite the project using [CITATION.cff](CITATION.cff). The published v0.1.0 record is available at [doi:10.5281/zenodo.23180547](https://doi.org/10.5281/zenodo.23180547).

## License

Code is licensed under Apache 2.0 (see LICENSE). The paper in paper/ is licensed under CC BY 4.0 (see paper/LICENSE).
