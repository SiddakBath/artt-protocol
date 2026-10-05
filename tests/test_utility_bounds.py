from fractions import Fraction
import itertools
import math
import pytest

from tools.utility_bounds import kernel_moments, radius


def test_noise_error_moments_remain_correct_under_feedback():
    # The second effective bit deliberately depends on the first noisy verdict.
    # Enumeration checks the martingale argument without conditioning on a
    # retrospectively selected complete effective-bit trajectory.
    for first_bit in (0, 1):
        expectation = Fraction(0)
        second_moment = Fraction(0)
        for first, second in itertools.product(range(4), repeat=2):
            second_bit = int(first >= 2)
            p = (Fraction(1, 2) if first == 3*first_bit else Fraction(1, 6))
            p *= (Fraction(1, 2) if second == 3*second_bit else Fraction(1, 6))
            error = Fraction(first+second, 2)-1-Fraction(first_bit+second_bit, 2)
            expectation += p*error
            second_moment += p*error*error
        assert expectation == 0
        assert second_moment == Fraction(2, 3)
    for bit in (0, 1):
        assert kernel_moments(bit) == (1+bit, Fraction(4, 3))


def test_weighted_bound_accounts_for_two_public_groups():
    mean_radius = radius([1/256]*256)
    contrast_radius = radius([1/128]*128+[-1/128]*128)
    assert mean_radius == pytest.approx(3*math.sqrt(math.log(40)/(2*256)))
    assert contrast_radius == pytest.approx(2*mean_radius)
    assert 0.7421875-contrast_radius > 0
