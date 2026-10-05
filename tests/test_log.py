import json
import subprocess
import sys
import pytest
from rt.bundle import sha
from rt.log import read, verify_bytes
from rt.runner import submit
from rt.schema import canonical


def test_roundtrip_all_kinds_and_cli_tamper(make_bundle, tmp_path):
    path = tmp_path / "log"
    root = make_bundle()
    submit(root, path)
    submit(root, path, decline=True)
    submit(make_bundle("def run(api):\n    raise RuntimeError('TRANSCRIPT-SECRET')\n"), path)
    assert [e["kind"] for e in read(path)] == ["accepted", "refused", "error"]
    assert "TRANSCRIPT-SECRET" not in path.read_text()
    command = [sys.executable, "-m", "rt.verify", str(path)]
    assert subprocess.run(command, capture_output=True).returncode == 0
    raw = path.read_bytes().replace(b'"n_items":32', b'"n_items":31', 1)
    path.write_bytes(raw)
    assert subprocess.run(command, capture_output=True).returncode != 0


@pytest.mark.parametrize("field,value", [("network_policy", "allow"), ("verdict_schema_id", "unknown"),
    ("resources", {"max_seconds": 601, "max_ram_mb": 8192, "max_complete_calls": 64})])
def test_policy_refusals(field, value, make_bundle, tmp_path):
    root = make_bundle()
    path = root / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest[field] = value
    path.write_bytes(canonical(manifest))
    entry = submit(root, tmp_path / "log")
    expected = "network_policy_rejected" if field == "network_policy" else "resource_rejected" if field == "resources" else "schema_rejected"
    assert (entry["kind"], entry["reason_code"]) == ("refused", expected)


def test_missing_submission_and_duplicate_are_logged(make_bundle, tmp_path):
    path = tmp_path / "log"
    assert submit(tmp_path / "absent", path)["kind"] == "refused"
    root = make_bundle()
    submit(root, path)
    assert submit(root, path, reject_duplicate=True)["reason_code"] == "duplicate_bundle"
    assert len(read(path)) == 3


def test_refusal_completeness(make_bundle, tmp_path):
    root = make_bundle()
    path = tmp_path / "log"
    for _ in range(10):
        submit(root, path, decline=True)
        submit(root, path)
    entries = read(path)
    assert len(entries) == 20
    assert sum(e["kind"] == "accepted" for e in entries) == 10


def test_truncated_and_duplicate_json_rejected(make_bundle, tmp_path):
    path = tmp_path / "log"
    submit(make_bundle(), path)
    with pytest.raises(ValueError):
        verify_bytes(path.read_bytes()[:-1])
    with pytest.raises(ValueError):
        verify_bytes(path.read_bytes().replace(b'{"attestation":', b'{"kind":"error","attestation":', 1))


def test_invalid_verdict_with_recomputed_hash_still_rejected(make_bundle, tmp_path):
    path = tmp_path / "log"
    entry = submit(make_bundle(), path)
    entry["verdict"]["axes"]["deception"] = 99
    entry["entry_hash"] = sha(canonical({k:v for k,v in entry.items() if k != "entry_hash"}))
    with pytest.raises(ValueError):
        verify_bytes(canonical(entry) + b"\n")


def test_log_lock_fails_closed_without_edit(make_bundle, tmp_path):
    path = tmp_path / "log"
    submit(make_bundle(), path)
    raw = path.read_bytes()
    (tmp_path / "log.lock").write_bytes(b"")
    with pytest.raises(FileExistsError):
        submit(make_bundle(), path, decline=True)
    assert path.read_bytes() == raw
