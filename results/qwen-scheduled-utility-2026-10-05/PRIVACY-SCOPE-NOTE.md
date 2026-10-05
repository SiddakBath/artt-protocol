# Privacy accounting correction

The completed frozen report and archived scripts are preserved unchanged. Their
`epsilon_per_status_item_four_filings_upper_bound` field needs an additional
context-local noninterference assumption; it is not an unconditional bound for
this concurrent implementation.

The complete declared slot record has the stated per-release categorical
kernel bound. But shared worker/CPU/model queues can make one context affect
another worker's deadline/default score. A four-admission per-item counter does
not prove that only four records depend on that context. CPU separation of the
publisher does not establish independence between private workers.

For the follow-up's 1,280 admitted v2 records, generic composition over all
potentially affected releases is 2,560*ln(3), approximately 2,812.45. This very
weak bound is reported honestly. A stronger per-item composition needs proved
context-local execution, or a trusted cap covering the full resource-sharing
release domain. Physical delivery independence remains a separate assumption.

The original status attack still has exact identical slot-record distributions:
every abort/timeout branch and every success maps to raw (0,0), irrespective of
other workers' cutoff outcomes. Its controls, recovery counts, same-run utility,
public chains, source freeze and publication timing measurements are unchanged.
This correction is reflected in the paper and whole-release proof; it is not
hidden by rewriting the frozen report or selecting a new run.

## Final delivery and utility qualifications

The complete-view delivery assumption covers declared epoch timestamps across
batches. Choosing an epoch before the current batch's access does not establish
independence from private work in earlier batches. The caller's completion gate
is a minimum delay after worker joins, not a certified exact return time. The
defined observer excludes that signal; an independently scheduled transport
must hide it if a deployed caller could observe it. The frozen report's `claim`
field is not an unconditional privacy certificate for those channels.

Corpus and item counters are individually atomic, separate SQLite charges.
Both precede access. Refusal of the second can consume the first; no joint
all-or-nothing transaction is claimed. This is conservative accounting.

The final utility audit adds pointwise Hoeffding martingale intervals for the
effective predicates including defaults. These allow later default decisions
to depend on earlier release noise, provided the current raw score is chosen
before its fresh noise. They do not condition on a retrospectively selected
entire raw trajectory. The original approximate normal intervals remain
explicit fixed-effective-vector approximations. No original result is replaced.
