"""Pinned ustar identity: manifest is excluded to avoid self-reference."""
import hashlib
import io
import os
from pathlib import Path
import tarfile
from .schema import canonical, strict_json, SCHEMAS, integer

PATHS = ("judge", "judge_model", "method_card.md")
CAPS = {"max_seconds": 600, "max_ram_mb": 8192, "max_complete_calls": 64}
HEADINGS = ("Judge family", "What it reads", "Decision rule", "Tag rules",
            "Known blind spots", "What this does not show")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical_archive(root, paths=PATHS):
    root = Path(root)
    entries = []
    for name in paths:
        path = root / name
        if not path.exists():
            if name == "judge_model":
                continue
            raise ValueError("missing_bundle_path")
        entries.append(path)
        if path.is_dir():
            entries.extend(path.rglob("*"))
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for path in sorted(entries, key=lambda p: p.relative_to(root).as_posix()):
            # Windows junctions/reparse points are also forbidden.
            if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                raise ValueError("bundle_link")
            if not path.is_file() and not path.is_dir():
                raise ValueError("bundle_special_file")
            info = tarfile.TarInfo(path.relative_to(root).as_posix())
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if path.is_dir() else 0o644
            if path.is_dir():
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                data = path.read_bytes()
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return output.getvalue()


def identity(root):
    root = Path(root)
    return {"bundle_id": sha(canonical_archive(root)),
            "program_hash": sha(canonical_archive(root, ("judge",))),
            "judge_model_hash": sha(canonical_archive(root, ("judge_model",)))
                if (root / "judge_model").exists() else None,
            "method_card_hash": sha((root / "method_card.md").read_bytes())}


def build(root, schema="rt.verdict.v1", resources=None):
    manifest = {"manifest_version": 1, **identity(root), "verdict_schema_id": schema,
                "resources": resources or dict(CAPS), "network_policy": "deny-all",
                "entrypoint": "judge.main:run"}
    (Path(root) / "manifest.json").write_bytes(canonical(manifest) + b"\n")
    return manifest


class Rejected(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def check(root):
    try:
        manifest = strict_json((Path(root) / "manifest.json").read_bytes())
        ident = identity(root)
        required = {"manifest_version", *ident, "verdict_schema_id", "resources",
                    "network_policy", "entrypoint"}
        if type(manifest) is not dict or set(manifest) != required:
            raise Rejected("schema_rejected")
        if manifest["network_policy"] != "deny-all":
            raise Rejected("network_policy_rejected")
        if (type(manifest["manifest_version"]) is not int or manifest["manifest_version"] != 1
                or manifest["verdict_schema_id"] not in SCHEMAS
                or manifest["entrypoint"] != "judge.main:run"
                or any(manifest[k] != v for k, v in ident.items())):
            raise Rejected("schema_rejected")
        resources = manifest["resources"]
        if (type(resources) is not dict or set(resources) != set(CAPS) or
                any(not integer(resources[k], 1, cap) for k, cap in CAPS.items())):
            raise Rejected("resource_rejected")
        card = (Path(root) / "method_card.md").read_text(encoding="utf-8")
        if any("## " + h not in card.splitlines() for h in HEADINGS):
            raise Rejected("schema_rejected")
        if not (Path(root) / "judge" / "main.py").is_file():
            raise Rejected("schema_rejected")
        # No uncommitted side files become readable in the sandbox snapshot.
        if set(p.name for p in Path(root).iterdir()) - {*PATHS, "manifest.json"}:
            raise Rejected("schema_rejected")
        return manifest
    except Rejected:
        raise
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        raise Rejected("schema_rejected") from None


def snapshot(root, dest):
    """Execute the same copied bytes that were checked, avoiding mutable-source races."""
    import shutil
    for name in (*PATHS, "manifest.json"):
        source = Path(root) / name
        if source.exists():
            if source.is_dir():
                shutil.copytree(source, Path(dest) / name, symlinks=True)
            else:
                shutil.copy2(source, Path(dest) / name, follow_symlinks=False)
    return check(dest)
