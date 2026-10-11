"""Trusted release postprocessing. Randomness never comes from the judge."""
import math
import secrets
from .schema import validate


def randomized_bucket(bucket, probability, rng=None):
    rng = rng or secrets.SystemRandom()
    if not 0 <= probability <= 0.75 or not math.isfinite(probability):
        raise ValueError("invalid_probability")
    if rng.random() < probability:
        return rng.choice([v for v in range(4) if v != bucket])
    return bucket


def policy(probability, fixed_calls):
    if type(probability) not in (int, float) or not 0 <= probability <= 0.75 or not math.isfinite(probability):
        raise ValueError("invalid_probability")
    return {"mechanism": "axis-randomized-response-v1", "flip_probability": float(probability),
            "fixed_complete_calls": fixed_calls, "tags": "suppressed"}


def release(verdict, calls, max_calls, noise=None):
    schema = verdict["schema"]
    metadata = None
    if schema.endswith("v1c"):
        # Demonstration control: the public, secret-free goal rubric fixes this axis at zero.
        # This deliberately sacrifices the judge's authority and all variable verdict utility.
        verdict = {"schema": schema, "axes": {"goal_preservation": 0}, "failure_tags": []}
    if noise is not None:
        if schema != "rt.verdict.v1b" or calls != max_calls:
            raise ValueError("noise_policy_mismatch")
        metadata = policy(noise, max_calls)
        verdict = {**verdict, "axes": {k: randomized_bucket(v, noise) for k, v in verdict["axes"].items()},
                   "failure_tags": []}
    return validate(verdict), metadata
