import pytest
from pytest import approx
from p2p.aurora.util import calculate_distance, _distance_expectation_matrix_markov, \
    _distance_transition_matrix_markov, optimum, quantified_mistake

absolute_tolerance = 10e-2



def assert_matrices_equal(expected, result):
    # matrices have to be same size
    assert len(expected) == len(result) and len(expected[0]) == len(result[0])
    for row_index in range(len(result)):
        assert result[row_index] == approx(expected[row_index], abs=absolute_tolerance)


@pytest.mark.parametrize("params, expected", [
    ((5, 2, 3), 4.325),
    ((52, 5, 26), 38.947),
    ((100, 10, 30), 38.535),
    # testing response_size being bigger then network_size
    ((5, 10, 3), 1),
    # test disabled since it is computationally demanding and takes longer time
    # ((1000, 40, 499), 166.9329)
])
def test_aurora_distance(params, expected):
    assert calculate_distance(*params) == approx(expected, abs=absolute_tolerance)


def test_draw_amount_expectation_matrix_markov():
    expected = [[1.111, 0.95238, 2.26190],
                [0, 1.42857, 2.14286],
                [0, 0, 2.5]]
    transition_matrix = _distance_transition_matrix_markov(5, 3, 2)
    result_matrix = _distance_expectation_matrix_markov(transition_matrix)
    assert_matrices_equal(expected, result_matrix)


def test_draw_amount_transition_matrix_markov():
    expected = [[0.10000,   0.60000,   0.30000,   0.00000],
                [0.00000,   0.30000,   0.60000,   0.10000],
                [0.00000,   0.00000,   0.60000,   0.40000],
                [0.00000,   0.00000,   0.00000,   1.00000]]
    result = _distance_transition_matrix_markov(5, 3, 2)
    assert_matrices_equal(expected, result)


@pytest.mark.parametrize("map, expected", [
    ({
        'a': [0.6, 0.51, 0.55],
        'b': [0.91]
    }, ('b', 0.753)),
    ({
        'a': [0.6, 0.51, 0.55],
        'b': [0.4]
    }, ('a', 0.508)),
    ({
        'a': [0.9, 0.9, 0.9],
        'b': [0.91]
    }, ('a', 2.187)),
])
def test_optimum(map, expected):
    result_key, result_value = optimum(map)
    expected_key, expected_value = expected
    assert result_key == expected_key
    assert result_value == approx(expected_value, abs=absolute_tolerance)


@pytest.mark.parametrize("total_size, success_states_in_population, sample_size, observed_successes, expected", [
    (21, 5, 3, 3, 6.823529),
    (10, 5, 3, 3, 1),
    (100, 49, 16, 0, 0),
    (100, 1, 5, 0, 0),
    (100, 50, 16, 3, 0),
    (100, 94, 16, 2, 0),
])
def test_quantified_mistake(total_size, success_states_in_population, sample_size, observed_successes, expected):
    assert quantified_mistake(total_size,
                              success_states_in_population,
                              sample_size,
                              observed_successes) \
           == approx(expected, abs=absolute_tolerance)
