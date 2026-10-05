from fractions import Fraction
import itertools
import math
import pytest
from tools.central_frontier import geometric_pmf, amplified_epsilon, likelihood_probabilities, exact_accuracy, mse,release


def test_geometric_mixture_ratio_bound_is_tight_and_constant_in_each_tail():
    alpha,q = Fraction(1,3),Fraction(1,4)
    limit = 1+q*(1/alpha-1)
    for y in range(-10,11):
        p0 = geometric_pmf(y,alpha)
        p1 = (1-q)*p0+q*geometric_pmf(y-1,alpha)
        assert 1/limit <= p1/p0 <= limit
        assert p1/p0 == (1-q+q/alpha if y>=1 else 1-q+q*alpha)
    assert math.exp(amplified_epsilon(q,alpha))==pytest.approx(float(limit))


def test_exact_attack_by_full_sufficient_transcript_enumeration():
    for q in (Fraction(1,8),Fraction(1,4),Fraction(1)):
        p0,p1 = likelihood_probabilities(q,Fraction(1,3))
        for r in (1,2,3,4):
            accuracy = Fraction(0)
            for out in itertools.product((0,1),repeat=r):
                probabilities = [math.prod(p if bit else 1-p for bit in out) for p in (p0,p1)]
                accuracy += max(probabilities)/2
            assert exact_accuracy(q,Fraction(1,3),r)==accuracy


def test_geometric_second_moment_and_sampling_variance():
    alpha = Fraction(1,3)
    approximate_variance = sum(float(geometric_pmf(z,alpha))*z*z for z in range(-60,61))
    assert approximate_variance == pytest.approx(float(2*alpha/(1-alpha)**2))
    assert mse(1,alpha,32,1,1)==Fraction(3,2048)
    assert mse(Fraction(1,4),alpha,32,1,Fraction(1,2))==Fraction(9,128)
    assert mse(1,alpha,32,31,1)==mse(1,alpha,32,1,1)/31


def test_runtime_noise_can_exceed_finite_float_inverse_support():
    class Coins:
        def __init__(self):
            self.coins=iter([0]+[0]*80+[2,2])
        def randrange(self,denominator):
            value=next(self.coins)
            assert value<denominator
            return value
    assert release([0],1,Fraction(1,3),Coins())==80
