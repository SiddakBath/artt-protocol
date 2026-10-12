# Hidden expected-value choice

Protocol `7bffc274cc46043d0fdb6d5cf6bd09e6643bba62` was committed before the one attempted run. Protocol SHA-256: `948ce2a8ebac41b95d7677fcc7234f224c86ff9a72208def0d14a8a6bd092d7a`.

[Offline combined report](report/report.html) · [Summary](summary.json) · [Protocol](protocol.json) · [Start/source manifest](start.json) · [Completion receipt](completion-receipt.json) · [Report checks](report/artifact-checks.json) · [Final audit](audit.json)

The protected fact is which of two genuine hidden assertions with different expected values is included. Three other checks remain common. All 128 pinned Qwen3-0.6B attack patches and 48 honest patches are retained, with no filtering, repairs, regeneration or fresh GPU inference. Candidate suites and candidate-zero ordinary scores are public attacker side information; the inclusion choices were independently sampled once, without forcing balance.

Exact recovery: 128/128. First ARTT release: 90/128 (70.3%; Wilson 95%: 61.9%–77.5%). At four admissions: 101/128 (78.9%). All attempt prefixes are 59, 90, 96, 98, 101, 101, 101, 101, 101. There are 512 later refusals, with attack charges and calls fixed at 512 while honest capacity remains.

At four admissions the declared prediction is 85.4%; observed recovery is 78.9% (Wilson 95%: 71.0%–85.1%), so the prediction lies just above the interval. The assertion-order cohort was also below prediction at its cap (102/128 against 85.4%). We report this as observed and have not adjusted the decoder or prediction.

Honest utility: 29/48 patches pass their hidden suites, and 48/48 match the signature. The 192 noisy observations estimate pass fraction as 0.510 (Hoeffding 95%: 0.216–0.804), versus exact truth 0.604. Signature estimate: 1.010 (0.716–1.304), versus truth 1.000. Estimates and intervals are untruncated and concern noise on this fixed corpus.

The new allowance is 704/704, with four admissions per independently assigned private suite and no cap raises. Four two-score releases at p = 0.5 cost ε = 8.7889 per secret, conditional on isolated per-item contexts, the defined noisy interface and a trusted publisher. The conservative experiment sum is ε = 1,546.8461. Historical charges remain 5,008/5,008, ε = 11,003.7007. At this noise level ARTT meters the channel rather than making one bit private. Shared secrets would require composition. Timing leakage is not measured.

All 16 merged ledgers and original exact-control source chains verify against retained checkpoints. Source snapshot hashes and durable budgets verify. There are 1,136 protected replay calls: 704 noisy admissions plus 432 separately charged exact controls. All admitted proposals arrived before cutoff; exact attack outcome deviations are zero. The completion receipt verifies the source freeze and byte preservation of prior evidence. The earlier optimal equal-score and useful-score assertion-order results are shown as separate cohorts in the report.

Exact comparator outcomes, aggregate recovery and private execution diagnostics make this full research package non-private. Private choice labels were discarded; recovery and bootstrap results remain trusted custodian aggregates. This is a controlled hand-written attack on 48 tiny public tasks with one small model, known candidate checks and a trusted Linux software sandbox. It does not demonstrate a production breach, autonomous attack discovery, larger-model generalization or a generic locality theorem.

Regenerate a report in a fresh directory, with zero protected access or model calls (optional plotting dependencies: `requirements-report.txt`):

```bash
python -m demos.coding_agent.expected_value_report --input results/coding-expected-value-2026-10-12 --output scratch/expected-value-report-next
```

The historical input package is [published separately](../coding-agent-history-2026-10-11/README.md). Its original byte commitments and metadata are preserved. Never overwrite a completed or interrupted run or repeat it to improve observed recovery.
