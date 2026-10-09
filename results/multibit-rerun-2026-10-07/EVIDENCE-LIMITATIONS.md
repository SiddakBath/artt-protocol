# Retained follow-up evidence

This note was added during preparation on 8 October 2026. It does not amend the
historical protocol, measurements, or comparator.

The local protocol specified 64 trials, a budget of 48, and a primary endpoint
of mean bits correct at 48 admissions. Its 100,000-trial Monte Carlo comparator
is 14.48109. A local file does not establish independent preregistration.

The 64 retained completed trials have mean 14.3125 and standard error
0.1572882174 at 48 admissions. At 16 admissions the mean is 11.421875.
The stored secondary diagnostic records 3,172 mismatches among 6,144 axes.
These summary values reproduce the retained curves; the discarded planted
schedule prevents independent verification of their ground-truth correctness.

One filing missed its cutoff during an additional, unfinished attempt. The old
resume implementation deleted that attempt's partial ledger and admission
database before starting a replacement. Those artifacts are unavailable. The
retained sample therefore describes completed trials, with an excluded attempt,
and cannot establish an all-attempt recovery rate or its uncertainty. There is
no evidence here that exclusion was independent of the private inputs or noise.

The historical `results.json` stores a separate 20,000-trial Monte Carlo curve
under the legacy name `exact_mean_bits`. It is an estimate, not an exact curve.
The paper figure now uses the 100,000-trial curve from `protocol.json`, with a
Monte Carlo label. Historical result files have not been rewritten.

The repaired harness records settings and source identities before execution,
counts late or failed proposals through the noisy fallback, verifies completed
evidence before resuming, and preserves incomplete attempts without automatic
replacement. Historical runs without these settings cannot be resumed by the
repaired harness. A fresh output directory defines a new cohort; it does not
repair the historical excluded attempt. A fresh fully retained cohort would be
required for a stronger empirical claim.
