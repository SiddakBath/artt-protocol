from pathlib import Path
import pytest
from tools.research_audit import audit_multibit


def test_completed_preregistered_cohort_reconstructs_all_64_trials():
    study = Path(__file__).resolve().parents[1] / "results/multibit-confirmation-2026-10-18"
    checked = audit_multibit(study)
    assert checked["independent_recovery_check"]
    assert checked["arms"]["uncapped"]["trials"] == 64
    assert checked["arms"]["uncapped"]["mean_at_end"] == 14.625


def test_audit_rejects_a_protocol_not_bound_to_its_registration_commit(monkeypatch):
    from tools import research_audit
    study = Path(__file__).resolve().parents[1] / "results/multibit-confirmation-2026-10-18"
    monkeypatch.setattr(research_audit.subprocess, "check_output", lambda *args, **kwargs: b"{}")
    with pytest.raises(ValueError, match="registered_protocol_commit_mismatch"):
        audit_multibit(study)
