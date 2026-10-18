import json
from pathlib import Path
import pytest
from tools import multibit_preregistered as study


def test_registration_rejects_changed_labels_and_frozen_source(tmp_path, monkeypatch):
    protocol, schedule = tmp_path / "protocol.json", tmp_path / "labels.json"
    study.prepare(protocol, schedule)
    registered, labels = study.verify_inputs(protocol, schedule)
    assert len(labels["secrets"]) == registered["trials"] == 64
    assert registered["total_admissions"] == 3072
    raw = schedule.read_bytes()
    schedule.write_bytes(raw + b"\n")
    with pytest.raises(ValueError, match="schedule_commitment_mismatch"):
        study.verify_inputs(protocol, schedule)
    schedule.write_bytes(raw)
    data = json.loads(protocol.read_text())
    data["source_sha256"]["tools/multibit_attack.py"] = "0" * 64
    protocol.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="registered_source_changed"):
        study.verify_inputs(protocol, schedule)


def test_existing_registration_and_labels_cannot_be_replaced(tmp_path):
    protocol, schedule = tmp_path / "protocol.json", tmp_path / "labels.json"
    study.prepare(protocol, schedule)
    before = (protocol.read_bytes(), schedule.read_bytes())
    with pytest.raises(ValueError, match="fresh_protocol_and_schedule_required"):
        study.prepare(protocol, schedule)
    assert before == (protocol.read_bytes(), schedule.read_bytes())
