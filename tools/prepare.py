"""Prepare committed example manifests and the pinned archive vector, offline."""
import json
from pathlib import Path
import shutil
from rt.bundle import build, CAPS

root = Path(__file__).resolve().parents[1]
for family in ("honest", "adversary"):
    build(root / "judges" / family)
    for suffix in ("v1b", "v1c"):
        dest = root / "judges" / (family + "-" + suffix)
        if dest.exists():
            # Only overwrite generated files, preserving the dedicated directory.
            shutil.copyfile(root / "judges" / family / "judge/main.py", dest / "judge/main.py")
        else:
            shutil.copytree(root / "judges" / family, dest,
                            ignore=shutil.ignore_patterns("__pycache__", "manifest.json"))
        calls = 32 if family == "honest" else 1
        build(dest, "rt.verdict." + suffix, {**CAPS, "max_complete_calls": calls})
print("Prepared example bundles; frozen archive vector left unchanged")
