"""Exact finite-channel research results; not a claim about the v1 public log.

Replacement adjacency: one fixed response bit changes. Secret inclusion is
Bernoulli(q), and a missing response is represented by a fresh fair bit.
This experimental binary mechanism is distinct from v1b categorical noise.
"""
import argparse
from fractions import Fraction
import json
import math
from pathlib import Path


def signal(q, flip):
    q, flip = Fraction(q), Fraction(flip)
    if not 0 <= q <= 1 or not 0 <= flip <= Fraction(1, 2):
        raise ValueError("invalid_channel")
    return q * (1 - 2 * flip)


def epsilon(a):
    a = float(a)
    return math.log1p(a) - math.log1p(-a) if a < 1 else math.inf


def exact_accuracy(a, observations):
    """Rational evaluation of the optimal equal-prior likelihood test."""
    if observations < 0:
        raise ValueError("invalid_observations")
    t = (1 + Fraction(a)) / 2
    return sum((Fraction(math.comb(observations, k)) * t**k * (1-t)**(observations-k)
                * (1 if 2*k > observations else Fraction(1,2) if 2*k == observations else 0)
                for k in range(observations+1)), Fraction(0))


def error_probability(a, observations):
    """Same binomial formula, evaluated in log space to retain tiny errors."""
    if observations == 0 or a == 0:
        return 0.5
    t = (1+float(a))/2
    if t == 1:
        return 0.0
    terms = []
    for k in range(observations//2+1):
        weight = 0.5 if 2*k == observations else 1.0
        terms.append(weight * math.exp(math.lgamma(observations+1)-math.lgamma(k+1)
                     -math.lgamma(observations-k+1) + k*math.log(t) + (observations-k)*math.log1p(-t)))
    return math.fsum(terms)


def exact_mse(a, n, filings):
    """Variance of the unbiased, unclipped mean estimator; fixed true bits."""
    a = Fraction(a)
    if n < 1 or filings < 1:
        raise ValueError("invalid_dimensions")
    return (1-a*a)/(4*n*filings*a*a) if a else None


def mutual_information(a, r):
    """Analytical I(S; r reports) for equiprobable S; no plug-in estimation."""
    t = (1+float(a))/2
    if r == 0 or a == 0:
        return 0.0
    if t == 1:
        return 1.0
    entropy = []
    for k in range(r+1):
        common = math.lgamma(r+1)-math.lgamma(k+1)-math.lgamma(r-k+1)
        p0 = math.exp(common + k*math.log1p(-t)+(r-k)*math.log(t))
        p1 = math.exp(common + k*math.log(t)+(r-k)*math.log1p(-t))
        mass = (p0+p1)/2
        posterior = p1/(p0+p1) if mass else 0.5
        h = -sum(x*math.log2(x) for x in (posterior, 1-posterior) if x)
        entropy.append(mass*h)
    return max(0.0, 1-math.fsum(entropy))


def decoy_accuracy(m):
    """One noiseless count, x plus m independent fair decoys; known m."""
    return Fraction(1,2) + Fraction(math.comb(m,m//2), 2**(m+1))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    output = Path(args.output)
    if output.exists():
        raise SystemExit("Preserve completed research evidence; use a new path")
    rows = []
    for q in (Fraction(1,8), Fraction(1,4), Fraction(1,2), Fraction(1)):
        for flip in (Fraction(1,8), Fraction(1,4), Fraction(3,8)):
            a = signal(q,flip)
            eps = epsilon(a)
            for r in (1,3,9,31):
                n = 32
                rational_accuracy = exact_accuracy(a,r)
                rows.append({"q":float(q), "binary_flip_probability":float(flip), "filings":r, "n":n,
                    "signal":float(a), "epsilon_per_answer_per_filing":eps,
                    "epsilon_per_answer_total":r*eps,
                    "optimal_answer_recovery":float(rational_accuracy),
                    "answer_recovery_exact_fraction":str(rational_accuracy),
                    "answer_mi_bits":mutual_information(a,r),
                    "mean_mse":float(exact_mse(a,n,r)),
                    "expected_real_answer_accesses":float(q*n*r),
                    "global_secret_error":error_probability(a,n*r),
                    "global_secret_epsilon_total":n*r*eps,
                    "globally_shared_epsilon_1_max_filings":math.floor(1/eps)})
    decoys = [{"decoys":m, "optimal_recovery":float(decoy_accuracy(m)),
               "pure_dp_epsilon":"infinite", "distinguishing_endpoint_probability":2.0**(-m)}
              for m in (0,8,32,128)]
    report = {"scope":"exact binary response-local channel, fixed public metadata; not the v1 whole protocol",
        "mechanism":"independent hidden inclusion; fair replacement for excluded items; binary randomized response for included items; public fixed-length report vector",
        "adjacency":"replace one response bit in a fixed, public-size corpus; not secret model weights",
        "utility":"unbiased unclipped estimator of fixed corpus mean; squared error; independent per-item reports",
        "randomness":"analytical enumeration, no Monte Carlo/no model/no private seed",
        "optimality":"one-release binary testing bound is tight; no universal multi-item optimality claim",
        "filing_policy":"epsilon-1 shared cap is a counterfactual calculation; no timing or crash-recovery claim",
        "rows":rows, "decoy_counterexamples":decoys,
        "same_effective_epsilon":"subsampling plus binary RR equals binary RR with the same signal; no statistical-utility gain at fixed effective epsilon and filing count",
        "parity_counterexample":"independent fair bits, n>=2: parity reveals one aggregate bit, marginal I(each bit; parity)=0; knowing other bits removes this independence",
        "precision":"formulas exact; floating reports rounded; small global-secret errors retained instead of calling recovery exactly 1"}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report,indent=2,allow_nan=False)+"\n")
    for row in rows:
        if row["binary_flip_probability"]==0.25 and row["filings"] in (1,31):
            print(json.dumps(row))


if __name__ == "__main__":
    main()
