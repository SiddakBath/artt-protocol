import io
import json
import os
from pathlib import Path
import tarfile
import pytest
from rt.bundle import canonical_archive, identity, check, build, Rejected

VECTORS = Path(__file__).parent / "vectors"


def test_pinned_ustar_vector(tmp_path):
    vector = json.loads((VECTORS / "minimal.json").read_text())
    root = VECTORS / "minimal"
    assert identity(root) == vector["identity"]
    assert canonical_archive(root) == (VECTORS / "minimal.tar").read_bytes()
    with tarfile.open(fileobj=io.BytesIO(canonical_archive(root))) as tar:
        assert tar.getnames() == ["judge", "judge/main.py", "method_card.md"]
        assert all(e.uid == e.gid == e.mtime == 0 and e.uname == e.gname == "" for e in tar)


def test_metadata_independent_and_content_sensitive(make_bundle):
    root = make_bundle()
    before = identity(root)
    os.utime(root / "judge/main.py", (10000, 10000))
    os.chmod(root / "judge/main.py", 0o600)
    assert identity(root) == before
    build(root)
    assert identity(root) == before
    (root / "judge/main.py").write_text("changed")
    with pytest.raises(Rejected):
        check(root)


def test_reject_links_extra_paths_and_incomplete_model(make_bundle):
    root = make_bundle()
    (root / "judge/leak").symlink_to("/etc/passwd")
    with pytest.raises(ValueError):
        identity(root)
    (root / "judge/leak").unlink()
    (root / "uncommitted").write_text("hidden")
    with pytest.raises(Rejected):
        check(root)


def test_method_card_headings_required(make_bundle):
    root = make_bundle()
    (root / "method_card.md").write_text("a model decided")
    build(root)
    with pytest.raises(Rejected):
        check(root)


def test_source_mutation_during_completion_cannot_change_snapshot(make_bundle, tmp_path):
    from rt.model import FixtureModel
    from rt.runner import submit
    root = make_bundle()
    original = identity(root)["bundle_id"]
    class MutatingModel(FixtureModel):
        changed = False
        def complete(self, messages):
            if not self.changed:
                (root / "judge/main.py").write_text("not a runnable judge")
                self.changed = True
            return super().complete(messages)
    entry = submit(root, tmp_path / "log", MutatingModel())
    assert entry["kind"] == "accepted" and entry["bundle_hash"] == original


def test_empty_local_model_changes_identity(make_bundle):
    root = make_bundle()
    before = identity(root)
    (root / "judge_model").mkdir()
    after = identity(root)
    assert before["judge_model_hash"] is None and after["judge_model_hash"] is not None
    assert before["bundle_id"] != after["bundle_id"]
