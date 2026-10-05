from fractions import Fraction
import itertools
import math
import pytest
from tools.privacy_frontier import signal, epsilon, exact_accuracy, error_probability, exact_mse, mutual_information, decoy_accuracy


def test_exact_likelihood_decoder_against_full_transcript_enumeration():
    a = Fraction(1,4)
    t = (1+a)/2
    for r in (1,2,3,4):
        expected = Fraction(0)
        for transcript in itertools.product((0,1), repeat=r):
            k = sum(transcript)
            p1, p0 = t**k*(1-t)**(r-k), t**(r-k)*(1-t)**k
            expected += max(p0,p1)/2
        assert exact_accuracy(a,r) == expected
        assert error_probability(a,r) == pytest.approx(float(1-expected))


def test_privacy_bound_tight_and_effective_channels_identical():
    a = signal(Fraction(1,2), Fraction(1,4))
    assert a == signal(1, Fraction(3,8))
    eps = epsilon(a)
    assert float(exact_accuracy(a,1)) == pytest.approx(1/(1+math.exp(-eps)))
    assert mutual_information(a,1) > 0
    assert mutual_information(0,31) == 0
    assert exact_accuracy(0,31) == Fraction(1,2)


def test_mean_variance_by_full_enumeration():
    a = Fraction(1,2)
    t = (1+a)/2
    for data in itertools.product((0,1), repeat=3):
        truth = Fraction(sum(data),3)
        risk = Fraction(0)
        for out in itertools.product((0,1), repeat=3):
            mass = math.prod(t if x==y else 1-t for x,y in zip(data,out))
            estimate = (Fraction(sum(out),3)-(1-a)/2)/a
            risk += mass*(estimate-truth)**2
        assert risk == exact_mse(a,3,1)


def test_decoy_shift_total_variation_and_endpoint_counterexample():
    for m in (0,8,32):
        probs = [Fraction(math.comb(m,k),2**m) for k in range(m+1)]
        tv = sum(abs((probs[k] if k<=m else 0)-(probs[k-1] if k>=1 else 0)) for k in range(m+2))/2
        assert decoy_accuracy(m) == (1+tv)/2
        assert probs[0] > 0  # endpoint impossible for secret=1, so finite pure DP fails
