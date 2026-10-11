## ARTT on a coding-agent evaluation

Coding agents are judged on hidden tests. This demo runs 48 small Python tasks through two release paths with deterministic fixture agents, not learned models.

On a naive design that publishes status, the constant-score abort attack recovered its planted canary in 128/128 (1.0000; 95% interval 0.9709 to 1.0000).
Under ARTT the same attack recovered it from status in 64/128 (0.5000; 95% interval 0.4147 to 0.5853) and from scores in 58/128 (0.4531; 95% interval 0.3695 to 0.5395).
The deliberate score encoder recovered it in 88/128 (0.6875; 95% interval 0.6027 to 0.7613); its predicted optimal recovery is 0.7222. The score channel is bounded and logged, not closed.

Honest fixture A estimate: 0.7500, 95% interval 0.1619 to 1.3381.
Honest fixture B estimate: 0.3958, 95% interval -0.1922 to 0.9839.
A minus B: 0.3542, 95% interval -0.4775 to 1.1858. The conservative interval includes zero; this run does not establish separation.

Each batch is a separate hash-chained ledger. Edited and middle-deleted copies are checked by `python -m rt.verify`; tail deletion needs a retained checkpoint. CT-style witnessing is future work.

Budget: 352 admitted, 8 refused; epsilon per record 2.1972, total 773.4231. The post-cap call count is unchanged: 608 before, 608 after.

Run it on Linux or Windows via WSL:

    .venv/bin/python -m rt.build_sandbox
    make demo

On Windows use `scripts/demo.ps1`. Every run needs a fresh output directory. Open `scratch/coding-demo/report.html`.

Scope: deterministic fixture agent; single model call per admission; trusted custodian; software sandbox, not hardware. Timing noninterference is not proven. The passport export is a proposed mapping, not an official AIUC or Lucid format.

Observed runtime: 151.4645 seconds. Commit: `3ed8b0203a3bc65080999ff02a472894c3f59506`. Protocol SHA256: `de79dadef4712648eb8e8f71f04db2e17dee5e2bb70856d1ccee8149efbe73b8`.

Decoder results from summary.json:

- naive_status_attack / status: 128/128 (1.0000; 95% interval 0.9709 to 1.0000)
- naive_status_attack / score: 83/128 (0.6484; 95% interval 0.5625 to 0.7257)
- artt_status_attack / status: 64/128 (0.5000; 95% interval 0.4147 to 0.5853)
- artt_status_attack / score: 58/128 (0.4531; 95% interval 0.3695 to 0.5395)
- naive_score_attack / status: 64/128 (0.5000; 95% interval 0.4147 to 0.5853)
- naive_score_attack / score: 89/128 (0.6953; 95% interval 0.6108 to 0.7684)
- artt_score_attack / status: 64/128 (0.5000; 95% interval 0.4147 to 0.5853)
- artt_score_attack / score: 88/128 (0.6875; 95% interval 0.6027 to 0.7613)

Observed tamper checks:

- edited: INVALID log; checkpoint matches: True
- middle_deleted: INVALID log; checkpoint matches: False
- suffix_deleted: VERIFIED 63 entries (chain integrity only; no hardware attestation); checkpoint matches: False
