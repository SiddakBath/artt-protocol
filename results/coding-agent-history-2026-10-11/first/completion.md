# Coding-agent demo completion receipt

Branch: `demo/coding-agent` in `C:/src/experimentation/right-to-test`.

Local commits:

```text
34a29c8 Document observed coding demo results and add Linux and WSL launchers
3ed8b02 Test coding fixtures, release invariants and evidence reports
736dabe Add scheduled coding demo, offline report and passport sketch
fc4e4c1 Add coding tasks, fixture agents and single-call judges
674771a Predeclare coding-agent fixture demo protocol
```

Added files:

- Makefile
- demos/__init__.py
- demos/coding_agent/README.md
- demos/coding_agent/__init__.py
- demos/coding_agent/agents.py
- demos/coding_agent/hidden_tests.py
- demos/coding_agent/judges/honest/judge/__init__.py
- demos/coding_agent/judges/honest/judge/main.py
- demos/coding_agent/judges/honest/method_card.md
- demos/coding_agent/judges/score_attack/judge/__init__.py
- demos/coding_agent/judges/score_attack/judge/main.py
- demos/coding_agent/judges/score_attack/method_card.md
- demos/coding_agent/judges/status_attack/judge/__init__.py
- demos/coding_agent/judges/status_attack/judge/main.py
- demos/coding_agent/judges/status_attack/method_card.md
- demos/coding_agent/passport.py
- demos/coding_agent/protocol.json
- demos/coding_agent/report.py
- demos/coding_agent/run.py
- demos/coding_agent/tasks.py
- scripts/demo.ps1
- tests/test_coding_agent_demo.py

Modified: `README.md`. The existing uncommitted edit to `paper/draft.tex` was left untouched. No push, merge, tag, publication, version change or model download.

Commands run from the repository root in WSL (invoked through `wsl -- bash -lc`):

```bash
.venv/bin/python -m rt.build_sandbox
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_coding_agent_demo.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_coding_agent_demo.py -k 'not live'
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q -p no:cacheprovider | tee scratch/coding-demo-tests.txt
make demo | tee scratch/coding-demo-run-console.txt
.venv/bin/python -m tools.research_audit --output scratch/audit-after-demo.json
.venv/bin/python scratch/coding-demo/check_and_receipt.py
```

`make demo` executes:

```bash
.venv/bin/python -m demos.coding_agent.run --output scratch/coding-demo
.venv/bin/python -m demos.coding_agent.report --input scratch/coding-demo --html scratch/coding-demo/report.html
```

The single reported run took 151.464473214 seconds, measured by the runner from before protocol validation through final verification and passport export. Report rendering and browser QA are additional. No full run was repeated.

Full regression output:

```text
........................................................................ [ 76%]
......................                                                   [100%]
94 passed in 57.98s
```

The unchanged research audit passed with 973 chains and 12898 entries. It validates retained research artifacts, not this demo's discarded private canary schedule. `artifact-checks.json` checks this demo's public artifacts separately.

Observed values copied from summary.json:

```json
{
  "recovery": {
    "naive_status_attack": {
      "status": {
        "correct": 128,
        "n": 128,
        "rate": 1.0,
        "wilson_95": [
          0.9708620041018919,
          0.9999999999999999
        ],
        "predicted": 1.0
      },
      "score": {
        "correct": 83,
        "n": 128,
        "rate": 0.6484375,
        "wilson_95": [
          0.5624962244946202,
          0.725728432973129
        ],
        "predicted": null
      }
    },
    "artt_status_attack": {
      "status": {
        "correct": 64,
        "n": 128,
        "rate": 0.5,
        "wilson_95": [
          0.41465072364379996,
          0.5853492763562
        ],
        "predicted": 0.5
      },
      "score": {
        "correct": 58,
        "n": 128,
        "rate": 0.453125,
        "wilson_95": [
          0.3695064886070455,
          0.5394751985084021
        ],
        "predicted": 0.5
      }
    },
    "naive_score_attack": {
      "status": {
        "correct": 64,
        "n": 128,
        "rate": 0.5,
        "wilson_95": [
          0.41465072364379996,
          0.5853492763562
        ],
        "predicted": 0.5
      },
      "score": {
        "correct": 89,
        "n": 128,
        "rate": 0.6953125,
        "wilson_95": [
          0.6108473759049617,
          0.7683955944473397
        ],
        "predicted": 0.7222222222222222
      }
    },
    "artt_score_attack": {
      "status": {
        "correct": 64,
        "n": 128,
        "rate": 0.5,
        "wilson_95": [
          0.41465072364379996,
          0.5853492763562
        ],
        "predicted": 0.5
      },
      "score": {
        "correct": 88,
        "n": 128,
        "rate": 0.6875,
        "wilson_95": [
          0.602727327674739,
          0.7613459238634704
        ],
        "predicted": 0.7222222222222222
      }
    }
  },
  "honest": {
    "A": {
      "deception": {
        "estimate": 0.75,
        "hoeffding_95": [
          0.161924793225236,
          1.3380752067747639
        ],
        "n": 48
      },
      "sycophancy": {
        "estimate": 1.0208333333333335,
        "hoeffding_95": [
          0.4327581265585695,
          1.6089085401080974
        ],
        "n": 48
      }
    },
    "B": {
      "deception": {
        "estimate": 0.39583333333333326,
        "hoeffding_95": [
          -0.19224187344143073,
          0.9839085401080973
        ],
        "n": 48
      },
      "sycophancy": {
        "estimate": 1.0416666666666665,
        "hoeffding_95": [
          0.4535914598919025,
          1.6297418734414304
        ],
        "n": 48
      }
    },
    "difference": {
      "estimate": 0.35416666666666674,
      "hoeffding_95": [
        -0.4774972664495668,
        1.1858305997829004
      ],
      "interval_excludes_zero": false
    }
  },
  "raw_fixture_pass_rates": {
    "A": {
      "kind": "deterministic fixture",
      "passing_tasks": 36,
      "total_tasks": 48,
      "pass_rate": 0.75,
      "label": "custodian ground truth, fixed by construction"
    },
    "B": {
      "kind": "deterministic fixture",
      "passing_tasks": 19,
      "total_tasks": 48,
      "pass_rate": 0.3958333333333333,
      "label": "custodian ground truth, fixed by construction"
    }
  },
  "budget": {
    "scope": "coding-demo-corpus",
    "cap": 352,
    "admitted": 352,
    "used": 352,
    "refused": 8,
    "epsilon_per_record": 2.1972245773362196,
    "epsilon_total": 773.4230512223493,
    "calls_before_refusals": 608,
    "calls_after_refusals": 608,
    "refusals_never_called_model": true
  },
  "tamper": {
    "source": "artt-status_attack-00.jsonl",
    "saved_checkpoint": {
      "entries": 64,
      "head_line_sha256": "a4de9f9f746805908d4397d6f2170ec096b243587770ca629bf4c39f5c8e48a7",
      "last_entry_hash": "f0e52543ddc5eb99e28fe48a40c4fd68645e8138f06cb0393752f788376c0a2d"
    },
    "variants": {
      "edited": {
        "exit_code": 1,
        "output": "INVALID log",
        "stderr": "",
        "checkpoint_matches": true,
        "file": "tampered/edited.jsonl"
      },
      "middle_deleted": {
        "exit_code": 1,
        "output": "INVALID log",
        "stderr": "",
        "checkpoint_matches": false,
        "file": "tampered/middle_deleted.jsonl"
      },
      "suffix_deleted": {
        "exit_code": 0,
        "output": "VERIFIED 63 entries (chain integrity only; no hardware attestation)",
        "stderr": "",
        "checkpoint_matches": false,
        "file": "tampered/suffix_deleted.jsonl"
      }
    },
    "caveat": "A hash chain alone cannot detect a deleted tail. A retained checkpoint detects this copy's tail deletion. CT-style witnessing is future work."
  },
  "protocol_sha256": "de79dadef4712648eb8e8f71f04db2e17dee5e2bb70856d1ccee8149efbe73b8",
  "protocol_commit": "674771a6af2ddc4fc39bcfb3eaa75a13a71e9fa4",
  "git_commit": "3ed8b0203a3bc65080999ff02a472894c3f59506",
  "runner_version": "d3764e25fe3a9940b36b8f289e4ed2f4f09463b5b1f4e1d66232ee7ed8f1316d",
  "wall_seconds": 151.464473214
}
```

Browser QA: search for refused returned 8 rows; opening record 352 showed its refusal; Show more rows displayed 45 of 360; hash search found one released record; the tamper toggle showed the observed INVALID/INVALID/VERIFIED results and checkpoint states. No browser console warnings or errors were observed.

Screenshots:

- `screens/01-setup.jpg`
- `screens/02-recovery.jpg`
- `screens/03-utility.jpg`
- `screens/04-ledger-refusals.jpg`
- `screens/05-budget.jpg`
- `screens/06-original-verification.jpg`
- `screens/07-tampered-verification.jpg`
- `screens/08-passport.jpg`
- `screens/09-provenance.jpg`

Deviations and limitations:

- User approved a 2.5-second worker window and 2.55-second lead to accommodate the required integer 2-second bundle limit. The protocol predeclared 128 attack trials and a 0.1-second slot period before execution.
- Runtime was 151.464473214 seconds, over the approximately two-minute target. No cohort was reduced or repeated afterwards.
- The honest difference interval includes zero. The recorded point estimates reflect the fixture difference, but this sample does not establish statistical separation.
- The first small test run had two assertion failures: an edited middle row retains the head checkpoint, and JSON key order affected a report equality check. Those were corrected before the full run; the full suite passed.
- Each scheduled batch is its own chain. Chain validation and retained head checkpoints are complementary. A suffix-deleted chain verifies alone and fails its retained checkpoint comparison. No external witness is deployed.
- The offline report is roughly 1 MB and remains ignored under scratch. No showcase copy was committed or published.
- Fixture source and hidden-check design are public for reproducibility. Private trial assignments are generated in memory, then discarded. The recovery totals are trusted custodian aggregates.
- The fixture rates, trusted custody, one-call scope and software sandbox do not demonstrate learned-model performance or hardware attestation. Timing noninterference is not proven.

Final committed-tree audit also passed: scratch/audit-after-demo-final.json. Its README commitment matches the committed file. Both audit receipts were retained. Command: .venv/bin/python -m tools.research_audit --output scratch/audit-after-demo-final.json
