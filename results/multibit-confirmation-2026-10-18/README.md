# Preregistered 64-trial multibit confirmation

The protocol, runner and tests were pushed at commit `2c6d05e78860b20387d3737ec62ac01e1bf909b9` before execution. The start receipt confirms that same remote head before any protected access. All 64 initiated trials completed, using 3,072 charged fixture admissions and no learned-model inference. Every trial had a total cap of 48 across its sixteen items; post-cap requests were refused without backend calls or decoder updates.

| Admissions per trial | Mean correct bits | Standard error | Frozen reference | Descriptive z |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 7.8125 | 0.2736 | 8.0000 | -0.69 |
| 16 | 11.8438 | 0.2150 | 11.5556 | +1.34 |
| 48, primary endpoint | 14.6250 | 0.1364 | 14.4811 | +1.06 |

There were zero late proposals and zero worker errors. Of 6,144 released axes, 3,055 differed from the planted bit, against an expected rate of one half (z = -0.43). The roughly three-standard-error excess in the preliminary historical study did not recur here. This does not explain that earlier excess or reconstruct its missing attempt. The new cohort is separate from the historical Appendix E evidence and from the externally reported incomplete run; their counts are not pooled.

The allocation rule, decoder, public tie seed, noise and timing are unchanged. The primary comparator is the historical frozen 100,000-trial Monte Carlo value, not an exact analytic expectation beyond sixteen admissions. All prefix values and pointwise deviations are retained in `results.json`; the 48-admission primary endpoint was fixed before execution. Secondary endpoints are descriptive and have no multiplicity adjustment.

The synthetic label schedule was sampled once and its SHA-256 pushed before execution. `revealed-schedule.json` now permits recovery to be independently reconstructed from the public chains. The schedule includes a random nonce and must match the predeclared digest. All 64 reconstructed curves match the retained recovery counts. The source snapshot, executed judge bundle, private research diagnostics, durable budgets and 839 listed artifacts are retained with their hashes. The research transcript is non-private; this is a fixture channel and cap check, not a model-wide secrecy or timing guarantee.

Use a full Git clone containing registration commit `2c6d05e` to check the evidence without model calls or private access. The audit compares the protocol bytes with that original commit, as well as checking the revealed labels and public records:

```bash
python -c "from pathlib import Path; from tools.research_audit import audit_multibit; print(audit_multibit(Path('results/multibit-confirmation-2026-10-18')))"
```

The completed run must not be executed again or overwritten. Its manifest covers the listed execution artifacts; this explanatory README is a later analysis document.
