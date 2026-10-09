# Preparation verification, 8 October 2026

This preparation fixes the multibit harness and audit, brings the exact status
result forward, and regenerates the lead figure using the historical local protocol's
100,000-trial Monte Carlo comparator. Historical measurement files and public
chains were preserved. The lost-attempt limitation is documented in
`../multibit-rerun-2026-10-07/EVIDENCE-LIMITATIONS.md`.

- `test-receipt.json`: full Linux suite, 84 passed in 41.82 seconds. Pinned
  test dependencies were installed in the isolated repository environment before
  testing. The receipt retains the actual output and tested source hashes.
- `planting-check.json`: 10,000 offline trials using the live harness's same
  planting and tie-guess code. Zero-admission mean 7.9705, standard error 0.0201,
  z = -1.47 against eight. This does not reconstruct the historical labels.
- `demo-receipt.json`: the documented no-GPU demo completed two fixture trials,
  16 admissions per trial, through the Linux sandbox and scheduled publisher;
  further filings were refused without model access.
- `native-diagnostic.json`: the earlier 16-page native compilation diagnostic.
  It is retained as a historical receipt; its source and PDF hashes do not
  describe the post-revision build below.
- `final-audit.json`: 973 public chains, 12,898 records, historical source
  snapshots, budget counts, mathematical analyses, and independently recomputed
  multibit summary arithmetic. Ground-truth labels were discarded historically,
  so this audit does not authenticate their recovery counts or preregistration.
  Its source manifest describes the earlier preparation snapshot, before the
  later abstract, metadata and source-archive edits. Historical measurement
  files remain unchanged. The current manuscript and PDF hashes are recorded
  in the build receipt below.
- `rebuild-receipt.json`: the current 19-page PDF compilation and layout review,
  after applying the structural feedback on v0.1.2. The introduction is shorter;
  terminology and a worked status attack precede the privacy analysis; the
  experiments have an evidence map; schema history is in Appendix A; and timing
  limitations are collected in one subsection. The theorem and historical
  evidence remain unchanged. The receipt records current
  source, figure, PDF and build-log hashes, separately from the evidence audit.
  The current manuscript distinguishes shared item and corpus caps, scopes
  exact status equality to the constant-score attack, and treats semantic
  admission quotas as future work. Table 5 uses the frozen 100,000-trial
  comparator above the exact first-pass range. The abstract reports the
  conservative utility interval. The current 19-page build has resolved
  references and includes the 9 October 2026 date.

The paper PDF is `dist/a-right-to-test-ready.pdf`. Build it from `paper/` with
the existing LaTeX installation, using shell escape disabled and two passes
when starting without auxiliary files:

```bash
pdflatex -no-shell-escape -interaction=nonstopmode -halt-on-error -output-directory=../dist -jobname=a-right-to-test-ready draft.tex
pdflatex -no-shell-escape -interaction=nonstopmode -halt-on-error -output-directory=../dist -jobname=a-right-to-test-ready draft.tex
```

The preparation does not restore the excluded historical attempt or establish
an all-attempt recovery rate. A fresh fully retained cohort would be needed
for that claim. No ML models were loaded for this preparation.
