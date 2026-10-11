"""Single-writer hash chain with exclusive append lock and strict verification."""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
from .bundle import sha
from .schema import canonical, strict_json, validate, integer

REASONS = {"schema_rejected", "resource_rejected", "network_policy_rejected",
           "custodian_declined", "duplicate_bundle", "release_budget_exhausted"}
ERRORS = {"timeout", "oom", "no_emit", "double_emit", "runtime_exception",
          "socket_attempt", "bad_verdict", "complete_limit"}
COMMON = {"kind", "seq", "prev", "model_hash", "bundle_hash", "method_card_hash",
          "custodian_id", "runner", "runner_version", "timestamp", "entry_hash",
          "attestation"}


def is_hash(v):
    return type(v) is str and re.fullmatch("[0-9a-f]{64}", v) is not None


def verify_bytes(data):
    if data and not data.endswith(b"\n"):
        raise ValueError("incomplete_log")
    prev = None
    entries = []
    for seq, raw in enumerate(data.splitlines(keepends=True)):
        entry = strict_json(raw)
        if type(entry) is not dict or type(entry.get("kind")) is not str:
            raise ValueError("invalid_log")
        kind = entry["kind"]
        extra = {"accepted": {"verdict", "n_complete_calls"},
                 "refused": {"reason_code"}, "error": {"error_code"}}.get(kind)
        if extra is None:
            raise ValueError("invalid_kind")
        keys = set(entry)
        if kind == "accepted" and "release_policy" in keys:
            from .release import policy
            extra = extra | {"release_policy"}
            meta = entry["release_policy"]
            if (type(meta) is not dict or set(meta) != {"mechanism", "flip_probability", "fixed_complete_calls", "tags"}
                    or not integer(meta["fixed_complete_calls"], 1, 64)
                    or meta != policy(meta["flip_probability"], meta["fixed_complete_calls"])
                    or entry["n_complete_calls"] != meta["fixed_complete_calls"]
                    or entry["verdict"].get("schema") != "rt.verdict.v1b"
                    or entry["verdict"].get("failure_tags") != []):
                raise ValueError("invalid_release_policy")
        if kind == "refused" and "reason_note" in keys:
            extra = extra | {"reason_note"}
            note = entry["reason_note"]
            if type(note) is not str or len(note) > 120 or "\n" in note or "\r" in note:
                raise ValueError("invalid_note")
        if keys != COMMON | extra or not integer(entry["seq"], seq, seq) or entry["prev"] != prev:
            raise ValueError("invalid_chain")
        for key in ("model_hash", "bundle_hash", "method_card_hash", "entry_hash", "runner_version"):
            if not is_hash(entry[key]):
                raise ValueError("invalid_hash")
        if entry["runner"] != "software-sandbox-v1" or entry["custodian_id"] != "local-dev":
            raise ValueError("invalid_runner")
        if entry["attestation"] != "software-sandbox-v1:" + entry["runner_version"]:
            raise ValueError("invalid_attestation")
        timestamp = datetime.fromisoformat(entry["timestamp"])
        if timestamp.tzinfo is None or timestamp.utcoffset().total_seconds() != 0:
            raise ValueError("invalid_timestamp")
        if kind == "accepted":
            if not integer(entry["n_complete_calls"], 0, 64):
                raise ValueError("invalid_calls")
            verdict = validate(entry["verdict"])
            if verdict != entry["verdict"]:
                raise ValueError("noncanonical_tags")
        elif kind == "refused" and entry["reason_code"] not in REASONS:
            raise ValueError("invalid_reason")
        elif kind == "error" and entry["error_code"] not in ERRORS:
            raise ValueError("invalid_error")
        bare = {k: v for k, v in entry.items() if k != "entry_hash"}
        if entry["entry_hash"] != sha(canonical(bare)) or raw != canonical(entry) + b"\n":
            raise ValueError("entry_hash_mismatch")
        prev = sha(raw)
        entries.append(entry)
    return entries


def read(path):
    return verify_bytes(Path(path).read_bytes())


def append(path, entry):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + ".lock")
    # Fail closed on competing writers. Stale locks require explicit local recovery.
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        data = path.read_bytes() if path.exists() else b""
        entries = verify_bytes(data)
        value = {**entry, "seq": len(entries),
                 "prev": sha(data.splitlines(keepends=True)[-1]) if entries else None,
                 "timestamp": datetime.now(timezone.utc).isoformat()}
        value["entry_hash"] = sha(canonical(value))
        raw = canonical(value) + b"\n"
        verify_bytes(data + raw)
        with path.open("ab") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return value
    finally:
        os.close(fd)
        lock.unlink()
