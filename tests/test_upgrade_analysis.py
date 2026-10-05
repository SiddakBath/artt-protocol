import ast
import math
import pytest
from tools.upgrade_analysis import channel_metrics, exact_binary_accuracy, repeated_accuracy, variant_sources


def test_exact_kernel_matches_one_axis_formula():
    for p in (0,0.25,0.5,0.75):
        assert exact_binary_accuracy(p,1) == pytest.approx(1-2*p/3)
        assert repeated_accuracy(p,1) == pytest.approx(1-2*p/3)


def test_two_axis_attack_stronger_and_uniform_kernel_has_no_signal():
    assert exact_binary_accuracy(0.5,2) == pytest.approx(13/18)
    assert repeated_accuracy(0.5,2) == pytest.approx(13/18)
    assert repeated_accuracy(0.5,62) > 0.999
    assert repeated_accuracy(0.75,62) == pytest.approx(0.5)


def test_exact_information_quantities():
    assert channel_metrics(0.5,2)["capacity_bits_per_release"] == pytest.approx(0.4150374992788439)
    assert channel_metrics(0.5,2)["maximal_leakage_bits_per_release"] == 2
    assert channel_metrics(0.5,2)["epsilon_per_release"] == pytest.approx(2*math.log(3))
    assert channel_metrics(0.75,2)["maximal_leakage_bits_per_release"] == 0


def test_aliases_change_ast_but_keep_bound_argument_consistent():
    sources = variant_sources()
    trees = [ast.parse(s) for s in sources]
    assert len({ast.dump(t,include_attributes=False) for t in trees}) == 32
    for i,tree in enumerate(trees):
        run = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="run")
        assert run.args.args[0].arg == f"rt_api_{i}"
        assert all(n.id != "api" for n in ast.walk(run) if isinstance(n,ast.Name))
