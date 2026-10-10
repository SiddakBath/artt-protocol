"""An explicitly unofficial export sketch, built from public records only."""
STATUS = "PROPOSED MAPPING. Not an AIUC or Lucid format; no endorsement or compatibility implied."
LIMITS = ["software sandbox, not hardware quote", "trusted custodian", "single model call per admission", "fixture agent"]


def export(ledgers, axis_meaning):
    cumulative = 0.0
    entries = []
    for filename, rows in ledgers:
        for row in rows:
            policy = row["policy"]
            epsilon = policy["epsilon_per_admitted_release"] if row["kind"] == "released" else 0.0
            cumulative += epsilon
            entries.append({
                "subject": {"model_commitment": row["model_hash"]},
                "evaluation": {"bundle_hash": row["bundle_hash"], "method_card_hash": row["method_card_hash"], "verdict_schema": "rt.verdict.v1b", "axis_meaning": axis_meaning},
                "result": {"kind": row["kind"], "verdict_released": row.get("verdict"), "noise_policy": policy["mechanism"], "flip_probability": policy["flip_probability"]},
                "privacy": {"epsilon_this_record": epsilon, "epsilon_cumulative_scope": cumulative, "budget_scope": policy["budget_scope"], "admission_cap": policy["admission_cap"]},
                "provenance": {"ledger_file": filename, **{key: row[key] for key in ("entry_hash", "prev", "slot", "release_at", "attestation", "runner_version")}, "ledger_seq": row["seq"]},
                "limits": LIMITS,
            })
    return {"status": STATUS, "entries": entries}
