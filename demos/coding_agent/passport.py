"""An explicitly unofficial export sketch, built from public records only."""
STATUS = "PROPOSED MAPPING. Not an AIUC or Lucid format; no endorsement or compatibility implied."
LIMITS = ["software sandbox, not hardware quote", "trusted custodian", "single model call per admission", "fixture agent"]


def export(ledgers, axis_meaning, model_limits=None):
    totals = {}
    for _, rows in ledgers:
        for row in rows:
            meta = row["policy"]
            scope = meta["budget_scope"]
            total = totals.setdefault(scope, {"admitted_records": 0, "epsilon_per_record": meta["epsilon_per_admitted_release"], "admission_caps_seen": []})
            if total["epsilon_per_record"] != meta["epsilon_per_admitted_release"]:
                raise ValueError("mixed epsilon policies in one scope")
            total["admitted_records"] += row["kind"] == "released"
            if meta["admission_cap"] not in total["admission_caps_seen"]:
                total["admission_caps_seen"].append(meta["admission_cap"])
    for total in totals.values():
        total["epsilon_scope_total"] = total["admitted_records"] * total["epsilon_per_record"]
    admitted = dict.fromkeys(totals, 0)
    entries = []
    for filename, rows in ledgers:
        for row in rows:
            policy = row["policy"]
            epsilon = policy["epsilon_per_admitted_release"] if row["kind"] == "released" else 0.0
            scope = policy["budget_scope"]
            admitted[scope] += row["kind"] == "released"
            cumulative = admitted[scope] * policy["epsilon_per_admitted_release"]
            entries.append({
                "subject": {"model_commitment": row["model_hash"]},
                "evaluation": {"bundle_hash": row["bundle_hash"], "method_card_hash": row["method_card_hash"], "verdict_schema": "rt.verdict.v1b", "axis_meaning": axis_meaning},
                "result": {"kind": row["kind"], "verdict_released": row.get("verdict"), "noise_policy": policy["mechanism"], "flip_probability": policy["flip_probability"]},
                "privacy": {"epsilon_this_record": epsilon, "epsilon_cumulative_scope_through_this_record": cumulative,
                    "epsilon_scope_total_in_this_export": totals[scope]["epsilon_scope_total"], "budget_scope": scope, "admission_cap": policy["admission_cap"]},
                "provenance": {"ledger_file": filename, **{key: row[key] for key in ("entry_hash", "prev", "slot", "release_at", "attestation", "runner_version")}, "ledger_seq": row["seq"]},
                "limits": (model_limits or {}).get(row["model_hash"], LIMITS),
            })
    return {"status": STATUS, "privacy_scope_totals": totals, "entries": entries}


def legacy_export(ledgers, axis_meaning):
    """Validate preserved first-run exports without rewriting their evidence."""
    current = export(ledgers, axis_meaning)
    cumulative = 0.0
    for entry in current["entries"]:
        privacy = entry["privacy"]
        cumulative += privacy["epsilon_this_record"]
        privacy.pop("epsilon_cumulative_scope_through_this_record")
        privacy.pop("epsilon_scope_total_in_this_export")
        privacy["epsilon_cumulative_scope"] = cumulative
    return {"status": current["status"], "entries": current["entries"]}
