import argparse
from .log import read


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify a right-to-test JSONL chain.")
    parser.add_argument("log")
    args = parser.parse_args(argv)
    try:
        from pathlib import Path
        from .schema import strict_json
        raw=Path(args.log).read_bytes()
        first=strict_json(raw.splitlines()[0]) if raw else {}
        if type(first) is dict and first.get("schema")=="rt.release.v2":
            from .scheduled_log import read as scheduled_read
            entries=scheduled_read(args.log)
        else:
            entries = read(args.log)
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        print("INVALID log")
        return 1
    print(f"VERIFIED {len(entries)} entries (chain integrity only; no hardware attestation)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
