"""Model attribution and a sourced history; never rewrite historical scopes."""
import html
import json
from collections import Counter
from rt.bundle import sha


def model_scopes(ledgers, names=None):
    scopes = {}
    for filename, rows in ledgers:
        for row in rows:
            model = row["model_hash"]
            scope = scopes.setdefault(model, {
                "accounting_scope": "coding-model-" + model,
                "model_commitment": model,
                "label": (names or {}).get(model, "Model " + model[:12]),
                "admitted_records": 0, "refused_records": 0,
                "epsilon_per_record": row["policy"]["epsilon_per_admitted_release"],
                "historical_enforcement_scopes": [],
            })
            if scope["epsilon_per_record"] != row["policy"]["epsilon_per_admitted_release"]:
                raise ValueError("mixed epsilon policies for a model")
            scope["admitted_records"] += row["kind"] == "released"
            scope["refused_records"] += row["kind"] == "refused"
            raw_scope = row["policy"]["budget_scope"]
            if raw_scope not in scope["historical_enforcement_scopes"]:
                scope["historical_enforcement_scopes"].append(raw_scope)
    for scope in scopes.values():
        scope["epsilon_model_total"] = scope["admitted_records"] * scope["epsilon_per_record"]
    return list(scopes.values())


def policy_history(cohorts):
    """Reconstruct committed declarations, checking every allowance against rows.

    This is a new reporting log, not a claim that these events were logged in
    this format before access. Original protocol commitments provide that evidence.
    """
    events, used, previous_hash, scope = [], 0, None, None
    for label, summary, protocol_bytes, ledgers in cohorts:
        if sha(protocol_bytes) != summary["protocol_sha256"]:
            raise ValueError("policy source hash mismatch")
        protocol = json.loads(protocol_bytes)
        current_scope = protocol["budget_scope"]
        if scope is not None and scope != current_scope:
            raise ValueError("historical scope changed")
        scope = current_scope
        counts = Counter(row["model_hash"] for _, rows in ledgers for row in rows if row["kind"] == "released")
        cap = protocol.get("extended_admission_cap", summary["budget"]["cap"] if "cap" in summary["budget"] else None)
        before = protocol.get("original_cap_and_used", 0)
        if before != used or cap - before != sum(counts.values()):
            raise ValueError("policy allowance does not match carried charges")
        if any(row["policy"]["budget_scope"] != scope or row["policy"]["admission_cap"] != cap for _, rows in ledgers for row in rows):
            raise ValueError("ledger policy differs from committed allowance")
        event = {
            "seq": len(events), "prev": previous_hash,
            "kind": "initial_policy" if not events else "cap_raise",
            "cohort": label, "historical_enforcement_scope": scope,
            "cap_before": before, "cap_after": cap, "charges_carried_forward": used,
            "additional_allowance_by_model": dict(counts),
            "protocol_commit": summary["protocol_commit"],
            "protocol_sha256": summary["protocol_sha256"],
            "source_file": "policy-sources/" + label + ".json",
            "recording_basis": "reconstructed from retained committed protocols; not a contemporaneous event log",
        }
        event["entry_hash"] = sha(json.dumps(event, sort_keys=True, separators=(",", ":")).encode())
        events.append(event)
        previous_hash, used = event["entry_hash"], cap
    return events


def verify_history(directory):
    """Verify the new reporting chain, saved head, and original policy bytes."""
    from pathlib import Path
    directory = Path(directory)
    events = [json.loads(line) for line in (directory / "policy-changes.jsonl").read_text().splitlines()]
    previous, cap = None, 0
    for seq, saved in enumerate(events):
        event = dict(saved)
        digest = event.pop("entry_hash")
        if (digest != sha(json.dumps(event, sort_keys=True, separators=(",", ":")).encode())
                or event["prev"] != previous or event["seq"] != seq
                or event["cap_before"] != cap or event["charges_carried_forward"] != cap
                or event["cap_after"]-cap != sum(event["additional_allowance_by_model"].values())
                or sha((directory / event["source_file"]).read_bytes()) != event["protocol_sha256"]):
            raise ValueError("policy history or source mismatch")
        previous, cap = digest, event["cap_after"]
    if json.loads((directory / "policy-changes-checkpoint.json").read_text()) != {"entries": len(events), "last_entry_hash": previous}:
        raise ValueError("policy history checkpoint mismatch")
    return events


def budget_panel(scopes, events=()):
    escape = html.escape
    rows = "".join(f'<tr><td>{escape(s["label"])}</td><td><abbr title="{escape(s["accounting_scope"], quote=True)}"><code>coding-model-{s["model_commitment"][:12]}…</code></abbr></td><td>{s["admitted_records"]:,}</td><td>{s["refused_records"]:,}</td><td>{s["epsilon_model_total"]:.4f}</td></tr>' for s in scopes)
    cost = scopes[0]["epsilon_per_record"]
    total = sum(s["epsilon_model_total"] for s in scopes)
    historical = ", ".join(sorted({name for s in scopes for name in s["historical_enforcement_scopes"]}))
    panel = f'''<section id="budget"><h2>Privacy cost, one record at a time</h2><p><b>Each admitted two-score record costs ε = 2 ln 3 = {cost:.4f}.</b> A refusal costs zero additional release epsilon and makes no protected backend call. Failures and timeouts still consume an admission. ε is a worst-case privacy bound, not a percentage of recovered secrets.</p><div class="scroll"><table><thead><tr><th>Model</th><th>Per-model accounting scope</th><th>Admitted records</th><th>Refusals</th><th>Cumulative ε for this model</th></tr></thead><tbody>{rows}</tbody></table></div><p class="note">These are separate accounting scopes derived from the model commitments in the verified records. Historical enforcement scope(s): <code>{escape(historical)}</code>. The coding-demo runs enforced one shared counter, not independent per-model caps. Original records are preserved. Attribution does not reset charges or grant a fresh allowance.</p><p>If multiple models or accounts can read the same hidden test suite, their releases also compose against that protected asset. The conservative total across all admitted ARTT records shown here is <b>ε = {total:.4f}</b>. This large demonstration allowance is not a strong privacy setting. Unsafe comparison arms have no finite guarantee and are excluded from these totals.</p>'''
    if events:
        changes = "".join(f'<tr><td>{escape(e["cohort"])}</td><td>{e["cap_before"]} → {e["cap_after"]}</td><td>{e["charges_carried_forward"]}</td><td>{e["cap_after"]-e["cap_before"]}</td><td><a href="{e["source_file"]}">Committed protocol</a><br><code>{e["protocol_commit"]}</code></td></tr>' for e in events)
        panel += f'''<h3>Initial policy and all three cap raises</h3><p>Each raise authorized more access before its cohort ran. None erased the earlier privacy cost. This reporting log is reconstructed now from the retained protocol commitments; it is not a backdated event log.</p><div class="scroll"><table><thead><tr><th>Cohort</th><th>Shared cap before → after</th><th>Prior charges retained</th><th>New allowance</th><th>Source</th></tr></thead><tbody>{changes}</tbody></table></div><p><a href="policy-changes.jsonl">Hash-chained policy history</a> · <a href="policy-changes-checkpoint.json">History checkpoint</a> · <a href="model-scope-accounting.json">Model accounting receipt</a></p><p>The repeated-filings cohort additionally enforced four admissions per fixed secret. A new protocol would be needed for any further allowance; a model label, account or program alias is not permission to reset a shared secret's budget.</p>'''
    return panel + '</section>'
