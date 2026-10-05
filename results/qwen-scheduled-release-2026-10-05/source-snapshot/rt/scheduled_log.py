"""Strict v2 public records: no post-access status, error, or actual call count."""
from datetime import datetime,timezone
import math
from pathlib import Path
from .bundle import sha
from .log import is_hash,REASONS
from .release import policy as old_policy
from .schema import canonical,strict_json,validate

BASE = {"schema","kind","seq","prev","entry_hash","model_hash","bundle_hash","method_card_hash",
        "runner_version","attestation","slot","release_at","policy","item_id"}


def policy(p,period,window,margin,scope,cap):
    old_policy(p,1)
    if p<=0 or period<=0 or window<=0 or not 0<margin<window or cap<1 or not scope:
        raise ValueError("invalid_scheduled_policy")
    if not all(math.isfinite(x) for x in (period,window,margin)):
        raise ValueError("invalid_scheduled_policy")
    return {"mechanism":"whole-release-categorical-rr-v2","flip_probability":float(p),"axes":2,
        "post_access_status":"suppressed","actual_call_count":"suppressed","tags":"suppressed",
        "error_default_axes":{"deception":0,"sycophancy":0},"slot_period_seconds":float(period),
        "worker_window_seconds":float(window),"proposal_cutoff_margin_seconds":float(margin),
        "budget_scope":scope,"admission_cap":cap,"charge":"before_model_access_no_refunds",
        "epsilon_per_admitted_release":2*math.log(3*(1-p)/p)}


def validate_entry(entry):
    kind = entry.get("kind")
    extra = {"released":{"verdict"},"refused":{"reason_code"}}.get(kind)
    if extra is None or set(entry)!=BASE|extra or entry["schema"]!="rt.release.v2":
        raise ValueError("invalid_scheduled_record")
    if type(entry["seq"]) is not int or entry["seq"]<0 or type(entry["slot"]) is not int or entry["slot"]<0:
        raise ValueError("invalid_slot")
    if type(entry["item_id"]) is not str or not 1<=len(entry["item_id"])<=128:
        raise ValueError("invalid_item_id")
    for key in ("model_hash","bundle_hash","method_card_hash","runner_version","entry_hash"):
        if not is_hash(entry[key]):
            raise ValueError("invalid_scheduled_hash")
    if entry["prev"] is not None and not is_hash(entry["prev"]):
        raise ValueError("invalid_previous_hash")
    if entry["attestation"]!="software-sandbox-v2:"+entry["runner_version"]:
        raise ValueError("invalid_attestation")
    time = datetime.fromisoformat(entry["release_at"])
    if time.tzinfo is None or time.utcoffset().total_seconds()!=0:
        raise ValueError("invalid_scheduled_time")
    meta = entry["policy"]
    if type(meta) is not dict:
        raise ValueError("invalid_policy")
    expected = policy(meta["flip_probability"],meta["slot_period_seconds"],meta["worker_window_seconds"],
                      meta["proposal_cutoff_margin_seconds"],meta["budget_scope"],meta["admission_cap"])
    if meta!=expected:
        raise ValueError("noncanonical_policy")
    if kind=="released":
        verdict = validate(entry["verdict"])
        if verdict["schema"]!="rt.verdict.v1b" or verdict["failure_tags"] or verdict!=entry["verdict"]:
            raise ValueError("invalid_private_verdict")
    elif entry["reason_code"] not in REASONS:
        raise ValueError("invalid_refusal")
    bare = {key:value for key,value in entry.items() if key!="entry_hash"}
    if sha(canonical(bare))!=entry["entry_hash"]:
        raise ValueError("scheduled_entry_hash_mismatch")
    return entry


def read(path):
    data = Path(path).read_bytes()
    if data and not data.endswith(b"\n"):
        raise ValueError("incomplete_scheduled_log")
    entries,prev = [],None
    for seq,raw in enumerate(data.splitlines(keepends=True)):
        entry = validate_entry(strict_json(raw))
        if entry["seq"]!=seq or entry["prev"]!=prev or raw!=canonical(entry)+b"\n":
            raise ValueError("invalid_scheduled_chain")
        if entries:
            prior=entries[-1]
            if entry["release_at"]<=prior["release_at"] or entry["slot"]<=prior["slot"]:
                raise ValueError("nonmonotone_schedule")
            if entry["policy"]!=prior["policy"] or entry["runner_version"]!=prior["runner_version"]:
                raise ValueError("policy_changed_mid_batch")
        entries.append(entry)
        prev=sha(raw)
    return entries
