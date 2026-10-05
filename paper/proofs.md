# Proofs, mechanisms, and source record

Full proofs and the sources behind the related-work section are in this note.
It states the observation models behind the paper's claims and is not a
substitute for the paper.

## Declared fixed-slot record

Fix the public model commitment, filed methods, item identifiers, resource
policy, and observer interface. Neighboring inputs differ in one private canary
context. A filed program has at most one mediated model call and cannot select a
custodian context. The public observer receives ordered records at declared
slots, including preflight refusals and fixed metadata, but no raw proposal,
worker status, call count, cutoff flag, private telemetry, or unscheduled
completion signal.

All validation occurs before access. Corpus and item charges are separate,
durable, non-refundable transactions; both must succeed before a worker starts.
A failed second charge can consume the first and reduce availability. At the
cutoff, a timely valid proposal supplies raw buckets; every other post-access
outcome supplies `(0,0)`. Each raw bucket passes independently through four-way
randomized response: it is retained with probability `1-p` and maps to each
other bucket with probability `p/3`. The same fresh kernel processes successes
and fallbacks.

For any raw buckets `a,a'` and output `z`,

```
K_p(z | a) / K_p(z | a') <= 3(1-p)/p.
```

Thus a two-axis record is `epsilon`-DP for

```
epsilon = 2 ln(3(1-p)/p).
```

Mixtures over transcript-dependent proposals, exceptions and cutoffs preserve
this pointwise bound. Fixed fields, hash chaining and public-history-dependent
filings are postprocessing. Sequential composition applies to `M` potentially
affected records. Replacing `M` by an item cap requires context-local
noninterference, which concurrent shared queues do not establish.

The theorem assumes trusted isolation, custodian, publisher, non-rollback
accounting, availability, and secret-independent delivery of declared records.
That delivery premise covers epoch metadata across batches and excludes a
private API-return signal. It does not certify filesystem-arrival jitter,
network transport, host telemetry, scheduler faults, or a hostile operator.

For the reported status attack, both successful and failing branches map to raw
`(0,0)`. Their entire declared-record distributions are therefore equal for any
number of filings. This exact equality is narrower than the generic privacy
statement: a successful nonzero score remains an allowed noisy channel.

## Utility and the sampled count mechanism

For the registered honest task, an effective bit `B_t` maps to raw score `3B_t`.
With `p=1/2`, `E[V_t | B_t]=1+B_t` and `Var(V_t | B_t)=4/3`. The estimator
`mean(V)-1` targets the effective mean, including defaults. If each effective
bit is chosen before its fresh noise, its error remains a bounded martingale
difference even if earlier releases influence later defaults. For public weights
`w_t`, the pointwise bound is

```
Pr(|sum_t w_t (V_t-1-B_t)| >= h)
  <= 2 exp(-2h^2 / (9 sum_t w_t^2)).
```

The reported finite-sample intervals target the effective predicate mean. They
do not retrospectively condition on the full raw/default trajectory, claim
simultaneous coverage, or debias the raw response mean for failures.

The separate count mechanism has fixed binary scores `x_i`, hidden inclusion
probability `q`, and two-sided geometric noise `G` with parameter `alpha`:

```
Y = sum_i B_i x_i + G.
```

Under replacement of one binary score, its exact cost is
`ln(1 + q(1/alpha - 1))`. For fixed mean `mu` and `r` independent releases, the
unclipped mean estimator has

```
MSE = [(1-q)mu/(qn) + 2alpha/((1-alpha)^2q^2n^2)] / r.
```

The full integer transcript's strongest neighboring-answer decoder reduces to a
binomial likelihood test. Binary subsampling with fair fallback is ordinary
randomized response at the same effective signal. Bounded decoys do not change
the geometric extreme-tail ratio; noiseless finite decoys retain impossible
neighboring outputs. These are scoped mechanism calculations, not universal
optimality claims or protection for a model-wide secret that changes many
responses.

## Sources

- Schnabl, Hugenroth, Marino and Beresford, *Attestable Audits* (2025),
  [arXiv:2506.23706](https://arxiv.org/abs/2506.23706).
- Trask et al., *Double Blind Evals* (2026),
  [technical report](https://storage.googleapis.com/deepmind-media/DeepMind.com/Blog/piloting-the-worlds-first-double-blind-ai-evaluations/double-blind-evaluations-technical-report.pdf);
  [AVERI pilot report](https://www.averi.org/ourwork/averi-pilot-report-the-worlds-first-double-blind-eval).
- South et al., *Verifiable Evaluations Using zkSNARKs* (2024),
  [arXiv:2402.02675](https://arxiv.org/abs/2402.02675); Sun, Li and Zhang,
  *zkLLM* (2024), [arXiv:2404.16109](https://arxiv.org/abs/2404.16109).
- Haeberlen, Pierce and Narayan, *Differential Privacy Under Fire* (2011),
  [USENIX Security](https://www.usenix.org/legacy/events/sec11/tech/full_papers/Haeberlen.pdf);
  Xie and Li, *OCELOT* (2026), [arXiv:2606.12341](https://arxiv.org/abs/2606.12341).
- Balle, Barthe and Gaboardi, *Privacy Amplification by Subsampling* (2018),
  [arXiv:1807.01647](https://arxiv.org/abs/1807.01647); Ghosh, Roughgarden and
  Sundararajan, *Universally Utility-Maximizing Privacy Mechanisms* (2009),
  [arXiv:0811.2841](https://arxiv.org/abs/0811.2841).
- Guntuboyina, *Statistics 210B* lecture notes, Theorem 3.3,
  [conditional Hoeffding inequality](https://www.stat.berkeley.edu/~aditya/resources/FullNotes210BSpring2018.pdf).

None of these mechanisms are new. This repository applies them to public
filing.
