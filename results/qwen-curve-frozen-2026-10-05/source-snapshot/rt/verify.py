import argparse
from .log import read


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify a right-to-test JSONL chain.")
    parser.add_argument("log")
    args = parser.parse_args(argv)
    try:
        entries = read(args.log)
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        print("INVALID log")
        return 1
    print(f"VERIFIED {len(entries)} entries (chain integrity only; no hardware attestation)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
