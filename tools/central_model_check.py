"""Exact rational-coin kernel on the frozen real-model count, up to permutation."""
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import secrets
from tools.central_frontier import release,mse,amplified_epsilon

ROOT = Path(__file__).resolve().parents[1]


def main():
    out = ROOT/"results/qwen-curve-frozen-2026-10-05"
    source = out/"utility-kernel.json"
    frozen = json.loads(source.read_text())
    n = frozen["n"]
    k = round(n*frozen["model_exact_answer_accuracy"])
    assert n==32 and k/n==frozen["model_exact_answer_accuracy"]
    # The sampled count distribution depends only on k; privately reorder the
    # observed correctness bits into canonical positions without changing it.
    bits = [1]*k+[0]*(n-k)
    destination = out/"central-utility-exact.json"
    if destination.exists():
        raise SystemExit("Preserve the exact-kernel result")
    rng = secrets.SystemRandom()
    rows = []
    for q in (Fraction(1,8),Fraction(1,4),Fraction(1,2),Fraction(1)):
        for r in (1,3,9,31):
            errors = []
            for _ in range(4096):
                y = sum(release(bits,q,Fraction(1,3),rng) for _ in range(r))
                estimate = y/(float(q)*n*r)
                errors.append((estimate-k/n)**2)
            observed = sum(errors)/len(errors)
            se = (sum((v-observed)**2 for v in errors)/(len(errors)-1)/len(errors))**0.5
            expected = float(mse(q,Fraction(1,3),n,r,Fraction(k,n)))
            rows.append({"q":float(q),"alpha":1/3,"filings":r,"replications":len(errors),
                "predicted_mse":expected,"observed_mse":observed,"monte_carlo_standard_error":se,
                "difference_in_standard_errors":(observed-expected)/se if se else None,
                "epsilon_total_per_answer":r*amplified_epsilon(q,Fraction(1,3))})
    report = {"scope":"exact rational-coin sampled geometric kernel on frozen real-model correctness count; no additional model inferences or filed executions",
        "permutation_invariance":"sum of independent identically sampled binary scores depends only on their count, not their positions",
        "input_receipt_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),
        "kernel_source_sha256":hashlib.sha256((ROOT/"tools/central_frontier.py").read_bytes()).hexdigest(),
        "n":n,"model_exact_answer_accuracy":k/n,"transcripts_persisted":False,
        "randomness":"OS rational coins, independent replications; no persisted seeds","rows":rows,
        "privacy_scope":"ideal count output and hidden metadata; not v1 terminal/timing privacy",
        "supersedes":"central-utility-kernel.json used finite-precision inverse-CDF noise and is only a development simulation"}
    destination.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"points":len(rows),"replications_per_point":4096,
        "model_exact_answer_accuracy":k/n,"max_abs_standardized_difference":max(abs(r["difference_in_standard_errors"]) for r in rows)},indent=2))


if __name__=="__main__":
    main()
