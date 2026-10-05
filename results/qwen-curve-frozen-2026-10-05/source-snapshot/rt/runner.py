"""All public submissions have one logged outcome; model objects stay in the parent."""
import argparse
from pathlib import Path
import tempfile
from . import bundle, log
from .bundle import sha
from .model import FixtureModel
from .sandbox import execute
from .release import release, policy


def version():
    root = Path(__file__).parent
    files = sorted([*root.glob("*.py"), root / "isolate.c"])
    return sha(b"".join(p.name.encode() + p.read_bytes() for p in files))


def submit(source, log_path, model=None, decline=False, reject_duplicate=False, temp_parent=None, noise=None, budget=None):
    model = model or FixtureModel()
    rev = version()
    # Invalid paths still have stable non-transcript placeholder hashes.
    base = {"model_hash": model.model_hash, "bundle_hash": sha(b"unvalidated-bundle"),
            "method_card_hash": sha(b"unvalidated-method-card"), "custodian_id": "local-dev",
            "runner": "software-sandbox-v1", "runner_version": rev,
            "attestation": "software-sandbox-v1:" + rev}
    try:
        with tempfile.TemporaryDirectory(prefix="rt-", dir=temp_parent) as space:
            space = Path(space)
            snap, private = space / "bundle", space / "private"
            snap.mkdir()
            private.mkdir(mode=0o700)
            try:
                bundle.check(source)
                manifest = bundle.snapshot(source, snap)
            except (OSError, ValueError, TypeError):
                # Check original for a specific preflight refusal. Never echo its contents.
                try:
                    bundle.check(source)
                except bundle.Rejected as exc:
                    raise exc
                raise bundle.Rejected("schema_rejected") from None
            base.update(bundle_hash=manifest["bundle_id"], method_card_hash=manifest["method_card_hash"])
            if decline:
                raise bundle.Rejected("custodian_declined")
            if noise is not None:
                try:
                    policy(noise, manifest["resources"]["max_complete_calls"])
                    if manifest["verdict_schema_id"] != "rt.verdict.v1b":
                        raise ValueError("noise_schema")
                except ValueError:
                    raise bundle.Rejected("schema_rejected") from None
            if reject_duplicate and Path(log_path).exists():
                if any(e["bundle_hash"] == base["bundle_hash"] and e["kind"] == "accepted"
                       for e in log.read(log_path)):
                    raise bundle.Rejected("duplicate_bundle")
            # This is after public preflight and before any private model access.
            # Shared scope is custodian-owned; neither program hash nor successful
            # completion resets it. An error/crash after this point is charged.
            if budget is not None and not budget.reserve():
                raise bundle.Rejected("release_budget_exhausted")
            try:
                result = execute(snap, private, manifest, model)
            except (RuntimeError, OSError):
                from .sandbox import Result
                result = Result(error="runtime_exception")
            if result.error:
                entry = {**base, "kind": "error", "error_code": result.error}
            else:
                try:
                    verdict, metadata = release(result.verdict, result.n_calls,
                        manifest["resources"]["max_complete_calls"], noise)
                    entry = {**base, "kind": "accepted", "verdict": verdict, "n_complete_calls": result.n_calls}
                    if metadata is not None:
                        entry["release_policy"] = metadata
                except ValueError:
                    entry = {**base, "kind": "error", "error_code": "bad_verdict"}
    except bundle.Rejected as exc:
        # Recover content identity for valid-shaped but policy-rejected bundles.
        try:
            ident = bundle.identity(source)
            base.update(bundle_hash=ident["bundle_id"], method_card_hash=ident["method_card_hash"])
        except (OSError, ValueError):
            pass
        entry = {**base, "kind": "refused", "reason_code": exc.code}
    return log.append(log_path, entry)


def main(argv=None):
    parser = argparse.ArgumentParser(description="File a judge in the mandatory Linux namespace sandbox.")
    parser.add_argument("bundle")
    parser.add_argument("--log", required=True)
    parser.add_argument("--decline", action="store_true")
    parser.add_argument("--reject-duplicate", action="store_true")
    parser.add_argument("--noise-probability", type=float, help="v1b only: runner bucket flips, 0..0.75; fixed call budget")
    parser.add_argument("--budget-ledger", help="durable shared admission ledger; requires --release-cap and --budget-scope")
    parser.add_argument("--release-cap",type=int)
    parser.add_argument("--budget-scope",help="trusted protected-corpus identity, shared across every program hash")
    args = parser.parse_args(argv)
    configured = (args.budget_ledger is not None,args.release_cap is not None,args.budget_scope is not None)
    if any(configured) and not all(configured):
        parser.error("budget ledger, cap and scope must be configured together")
    budget = None
    if all(configured):
        from .budget import AdmissionBudget
        budget = AdmissionBudget(args.budget_ledger,args.budget_scope,args.release_cap)
    entry = submit(args.bundle, args.log, decline=args.decline,
                   reject_duplicate=args.reject_duplicate, noise=args.noise_probability,budget=budget)
    print(entry["kind"] + " " + entry["entry_hash"])
    return 0 if entry["kind"] == "accepted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
