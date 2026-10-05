# Evidence index

The current paper is `../paper/draft.tex`. Historical studies and failed
development conditions remain intact; subsequent corrections do not overwrite
their reports. Private response transcripts and secret schedules were discarded.
Recovery counts are trusted local aggregate receipts, not independently
authenticated measurements. Hash verification proves integrity, not truth.

| Directory | Evidence and interpretation |
|---|---|
| `run-2026-10-05` | Original fixture schema, byte payload, honest stability and 20-filing completeness study. Its 52-test receipt is historical. |
| `upgrade-analysis-2026-10-05` | Program-hash aliases and historical kernel analysis. |
| `qwen-curve-2026-10-05` | Development learned-model curve; read `SOURCE-INTEGRITY-NOTE.md`. Excluded from the frozen-curve claim. |
| `qwen-curve-frozen-2026-10-05` | Source-frozen Qwen schema curve; 256 inferences over two deterministic prompts. Its exact rational count-kernel follow-up supersedes the finite inverse-CDF development simulation. |
| `abort-channel-2026-10-05` | Constant-verdict accepted/error attack and hidden-inclusion negative result. |
| `budget-controller-2026-10-05` | Shared scope admits 3/32 program aliases; 29 refusals without model access. |
| `privacy-frontier-2026-10-05` | 48 exact binary subsampling/noise/filing settings; decoy and global-secret counterexamples. Analytical, not model trials. |
| `central-frontier-2026-10-05` | 16 sampled geometric-count settings and equal-total-budget comparison. Exact mechanism-specific formulas, not global utility optimality. |
| `qwen-behavior-2026-10-05` | 64 registered arithmetic inferences, 32 primary correct, zero strict-format correct; 4096 kernel replications at each of 16 settings. |
| `qwen-scheduled-release-2026-10-05` | First frozen status repair. Score/status evidence is retained, but filesystem synchronization missed slots; read `TIMING-INTEGRITY-NOTE.md`. |
| `qwen-scheduled-utility-2026-10-05` | Main frozen study: 1536 live inferences, open status 256/256 versus closed status 128/256, score positive control 202/256 versus repeated closed attack 124/256, same-context utility including all five defaults. Read `PRIVACY-SCOPE-NOTE.md` before interpreting the old per-item epsilon field. |
| `research-audit-2026-10-05` | Final read-only integrity/arithmetic audit, test receipt and conservative finite-sample utility intervals computed from the existing honest records. No new inference or result-selected rerun. |

The main study contains seven verified public chains with 1538 entries: 256
open-status entries, 1280 admitted v2 entries, and two pre-access refusals. Its
archived source is matched byte-for-byte to the recorded hashes. The preceding
frozen scheduled study also retains a verified source snapshot.

The status-attack equality concerns releases whose successful and fallback raw
vectors are both zero. It does not assert that every useful score is independent
of the secret. Generic privacy composes over all potentially affected releases;
the concurrent runner has not proved per-item locality. Timing/delivery,
availability and rollback remain explicit boundaries.

All experiment commands require new paths and must not overwrite evidence.
The final audit can be replayed without executing judges or loading the model:

```powershell
$REPO = (Resolve-Path .).Path
python -m tools.research_audit --output "$REPO/results/research-audit-2026-10-05/recheck.json"
```

This rechecks retained model asset hashes on the local machine. A remote reader
without those assets can verify public chains and archived-source hashes, but
cannot independently recover discarded private labels or certify inference.
