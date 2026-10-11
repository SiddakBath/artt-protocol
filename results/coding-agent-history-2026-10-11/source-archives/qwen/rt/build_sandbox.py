"""Offline native launcher build. Linux is mandatory; never substitutes a fallback."""
from pathlib import Path
import subprocess
import sys


def main():
    if sys.platform != "linux":
        raise SystemExit("Linux required. Run this command inside WSL.")
    root = Path(__file__).resolve().parent.parent
    (root / ".build").mkdir(exist_ok=True)
    subprocess.run(["gcc", "-Wall", "-Wextra", "-Werror", "-O2", "-fstack-protector-strong",
                    "-D_FORTIFY_SOURCE=2", str(root / "rt/isolate.c"),
                    "-o", str(root / ".build/isolate")], check=True)
    print("Built Linux namespace launcher")


if __name__ == "__main__":
    main()
