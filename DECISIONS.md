# Design decisions

This file records choices that affect how to read or reproduce the release.

1. **Isolation fails closed.** Filed judges run only under Linux namespaces and
   seccomp. A setup failure produces no unisolated fallback. This is software
   isolation, not protection from the machine owner or hardware attestation.
2. **A smaller verdict is not secrecy.** The v1 tag space has 163 subsets.
   v1 and v1b both retain enough freedom to carry a binary secret. v1c is a
   runner-enforced constant control, included to show what removing choice does.
3. **The runner owns randomness.** Categorical randomized response is applied
   after the judge's proposal. Tags and variable call counts are suppressed.
   Repeated releases consume a shared budget because repetition improves both
   estimation and decoding.
4. **Terminal state is part of the release.** The fixed-slot interface charges
   before access, maps every post-access failure to the same raw fallback, adds
   fresh noise, and releases the same record shape. The original constant-raw
   attack then has equal distributions under either secret value.
5. **Composition follows affected records.** Shared workers may couple contexts,
   so an item cap alone does not establish a per-item whole-view privacy bound.
   The generic bound composes over all potentially affected releases. Fixed
   timing/delivery, availability and ledger rollback remain explicit assumptions.
6. **Evidence remains immutable.** Failed timing realization, development runs
   and the older per-item accounting field are retained with correction notes.
   Private schedules and transcripts were deliberately discarded, so reported
   recovery counts are trusted aggregate receipts rather than replayable labels.
