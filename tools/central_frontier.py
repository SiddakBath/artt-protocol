"""Hidden sampling + geometric count noise: exact response-level channel.

Trusted per-item scores are bits. Arbitrary whole-corpus judge proposals do
not have sensitivity one and cannot inherit this guarantee.
"""
from fractions import Fraction
import argparse
import json
import math
from pathlib import Path
import secrets


def parameters(q, alpha):
    q,alpha = Fraction(q),Fraction(alpha)
    if not 0<q<=1 or not 0<alpha<1:
        raise ValueError("invalid_mechanism")
    return q,alpha


def amplified_epsilon(q,alpha):
    q,alpha = parameters(q,alpha)
    return math.log(float(1+q*(1/alpha-1)))


def mse(q,alpha,n,r,mean):
    q,alpha = parameters(q,alpha)
    if n<1 or r<1 or not 0<=mean<=1:
        raise ValueError("invalid_utility_parameters")
    return ((1-q)*Fraction(mean)/(q*n) + 2*alpha/((1-alpha)**2*q*q*n*n))/r


def likelihood_probabilities(q,alpha):
    """Sufficient observation Z=1[Y>=1], neighbors (0,...,0) vs (1,0,...,0)."""
    q,alpha = parameters(q,alpha)
    return alpha/(1+alpha), (alpha+q*(1-alpha))/(1+alpha)


def exact_accuracy(q,alpha,r):
    p0,p1 = likelihood_probabilities(q,alpha)
    return sum((math.comb(r,k)*max(p0**k*(1-p0)**(r-k),p1**k*(1-p1)**(r-k))/2
                for k in range(r+1)),Fraction(0))


def exact_mi(q,alpha,r):
    p0,p1 = likelihood_probabilities(q,alpha)
    conditional_entropy = 0.0
    for k in range(r+1):
        a,b = [float(math.comb(r,k)*p**k*(1-p)**(r-k)) for p in (p0,p1)]
        mass = (a+b)/2
        if not mass:
            continue
        post = b/(a+b)
        entropy = -sum(p*math.log2(p) for p in (post,1-post) if p)
        conditional_entropy += mass*entropy
    return max(0,1-conditional_entropy)


def geometric_pmf(z,alpha):
    alpha = Fraction(alpha)
    return (1-alpha)/(1+alpha)*alpha**abs(z)


def release(bits,q,alpha,rng=None):
    """Actual trusted kernel. Inclusion, sample size, and raw count stay private."""
    q,alpha = parameters(q,alpha)
    if not bits or any(type(x) is not int or x not in (0,1) for x in bits):
        raise ValueError("bits_required")
    rng = rng or secrets.SystemRandom()
    selected_count = sum(bit for bit in bits if rng.randrange(q.denominator)<q.numerator)
    # Difference of two iid geometric failures has exactly the two-sided PMF.
    def geometric():
        # Rational coins avoid the finite support introduced by float inverse-CDF
        # sampling. No data-dependent cap or truncation is applied to the noise.
        failures = 0
        while rng.randrange(alpha.denominator)<alpha.numerator:
            failures += 1
        return failures
    return selected_count+geometric()-geometric()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output",required=True)
    args = parser.parse_args(argv)
    output = Path(args.output)
    if output.exists():
        raise SystemExit("Preserve completed results")
    rows = []
    for q in (Fraction(1,8),Fraction(1,4),Fraction(1,2),Fraction(1)):
        alpha = Fraction(1,3)
        eps = amplified_epsilon(q,alpha)
        for r in (1,3,9,31):
            acc = exact_accuracy(q,alpha,r)
            rows.append({"q":float(q),"geometric_alpha":float(alpha),"base_epsilon":math.log(3),
                "filings":r,"n":32,"epsilon_per_answer_per_filing":eps,"epsilon_per_answer_total":r*eps,
                "worst_case_answer_recovery":float(acc),"answer_recovery_exact_fraction":str(acc),
                "answer_mi_bits":exact_mi(q,alpha,r),"mean_mse_at_mean_half":float(mse(q,alpha,32,r,Fraction(1,2))),
                "worst_case_mean_mse":float(mse(q,alpha,32,r,1)),
                "expected_model_calls":float(q*32*r),"epsilon_1_shared_max_filings":math.floor(1/eps)})
    fixed_budget = []
    for r in (1,3,9,31):
        for q in (0.125,0.25,0.5,1):
            # Solve epsilon_eff=1/r exactly in real arithmetic; float display only.
            alpha = q/(q+math.expm1(1/r))
            fixed_budget.append({"total_epsilon":1,"q":q,"filings":r,"alpha":alpha,
                "worst_case_mean_mse":float(mse(q,alpha,32,r,1)),
                "expected_model_calls":q*32*r})
    report = {"scope":"exact sampled geometric count mechanism; fixed metadata and trusted per-item scoring; not v1 public log privacy",
        "adjacency":"replace exactly one response score bit in a fixed-size corpus",
        "utility":"unbiased, unclipped mean estimate averaged across independent accepted releases",
        "attacker":"equal priors; all other score bits fixed and known; worst case attained when they are zero",
        "optimality":"tight likelihood-ratio privacy cost and exact strongest attack for this mechanism; no universally optimal utility claim",
        "randomness":"analytical exact rational calculations, not model inference or Monte Carlo",
        "global_budget":"filing ceilings are analytical; persistent admission cap is separately implemented and tested",
        "rows":rows,"fixed_total_epsilon":fixed_budget,
        "decoys":"fixed bounded independent additive decoys leave the extreme-tail privacy ratio unchanged; fresh decoys add variance",
        "global_secret":"when all response bits change, this one-response adjacency guarantee does not imply secrecy of the model-wide bit"}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps([row for row in rows if row["filings"] in (1,31)],indent=2))


if __name__ == "__main__":
    main()
