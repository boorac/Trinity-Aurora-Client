from typing import Dict, List, Set, cast, Tuple

import trio
import numpy
import math
import random

from lahja import EndpointAPI
from scipy import stats as st

from p2p.abc import NodeAPI, SessionAPI
from p2p.constants import KADEMLIA_BUCKET_SIZE
from trinity.constants import TO_NETWORKING_BROADCAST_CONFIG
from trinity.protocol.common.events import ConnectToNodeCommand, GetConnectedPeersRequest, PeerJoinedEvent, \
    PeerHeadHashRequest
from trinity.protocol.eth.peer import ETHProxyPeerPool, ETHProxyPeer


def _distance_expectation_matrix_markov(transition_matrix):
    transition_matrix = transition_matrix[:-1, :-1]
    return numpy.linalg.inv(numpy.identity(len(transition_matrix)) - transition_matrix)


def _distance_transition_matrix_markov(network_size, malicious_nodes_number, neighbours_response_size):
    s = (malicious_nodes_number + 1, malicious_nodes_number + 1)
    result_matrix = numpy.zeros(s)
    for row in range(malicious_nodes_number + 1):
        for column in range(malicious_nodes_number + 1):
            if row > column:
                continue
            else:
                result_matrix[row][column] = st.hypergeom(network_size,
                                                          malicious_nodes_number - row,
                                                          neighbours_response_size).pmf(column - row)
    return result_matrix


def calculate_distance(network_size, neighbours_response_size=KADEMLIA_BUCKET_SIZE, malicious_nodes_number=None) -> float:
    """Calculates minimum suggested walk length over the network for Aurora algorithm"""
    if malicious_nodes_number is None:
        malicious_nodes_number = assumed_malicious_node_number(network_size)
    if neighbours_response_size > network_size:
        neighbours_response_size = network_size
    transition_matrix = _distance_transition_matrix_markov(network_size,
                                                           malicious_nodes_number,
                                                           neighbours_response_size)
    network_size = _distance_expectation_matrix_markov(transition_matrix)
    return sum(network_size[0, :])


def assumed_malicious_node_number(network_size: int) -> int:
    """Assumed number of malicious nodes for Aurora algorithm"""
    return math.ceil(network_size / 2) - 1


def quantified_mistake(total_size, success_states_in_population, sample_size, observed_successes):
    """Function measuring suspicious behaviour of the surrounding network using hypergeometric probability
    Returns quantification of the suspicion (mistake)
    """
    if total_size < success_states_in_population:
        raise ValueError("Total size cannot be smaller then success states in population!")
    hypergeom = st.hypergeom(total_size, success_states_in_population, sample_size)
    median = hypergeom.median()
    rounded_median = int(round(median))

    cumulative_prob_good_pick = hypergeom.cdf(rounded_median)
    cumulative_prob_bad_pick = sum([hypergeom.pmf(p) for p in range(rounded_median + 1, sample_size + 1)])
    cumulative_prob_seen = sum([hypergeom.pmf(p) for p in range(rounded_median + 1, observed_successes + 1)])
    ratio_of_likelihood_between_good_bad_choice = \
        0 if cumulative_prob_bad_pick == 0 else cumulative_prob_good_pick / cumulative_prob_bad_pick
    dampening_factor = 0 if cumulative_prob_bad_pick == 0 else cumulative_prob_seen / cumulative_prob_bad_pick

    return ratio_of_likelihood_between_good_bad_choice * dampening_factor


def optimum(m: Dict[any, List[float]]):
    """ Going over dictionary with containing correctness indicators mapped to a key
    and extracting key with an optimum value.
    """
    optimal_key = None
    optimal_correctness = None
    for key, correctness_list in m.items():
        correctness_sum = sum(correctness_list)
        if correctness_sum == 0:
            continue
        average = correctness_sum / len(correctness_list)
        current_key_correctness = len(correctness_list) * (average ** 3)
        if optimal_correctness is None or optimal_correctness < current_key_correctness:
            optimal_correctness = current_key_correctness
            optimal_key = key
    return optimal_key, optimal_correctness


def optimize_distance_with_mistake(distance: float, mistake: float) -> float:
    """ Using mistake to optimize the walk during runtime

    Using mistake to shorten or lengthen the walk, but never more then a single hop
    """
    distance_diff = (min(mistake, 1) - 0.5) / 0.5
    return distance + distance_diff


def calculate_correctness_indicator(accumulated_mistake, standard_mistakes_threshold):
    """Calculate correctness indicator for the walk

    If indicator is closer to zero it is more plausible that that the walk is traversing
    non-malicious nodes, reverse for 1
    """
    return 1 - (accumulated_mistake / standard_mistakes_threshold)


def aurora_put(correctness_dict: Dict[any, List[float]], key, value):
    if key in correctness_dict:
        correctness_dict[key].append(value)
    else:
        correctness_dict[key] = [value]
    return correctness_dict


def aurora_pick(candidates: Set[NodeAPI], exclusion_candidates: Set[NodeAPI] = None) -> NodeAPI:
    if exclusion_candidates is None:
        exclusion_candidates = set()
    if len(candidates) == 0 and len(exclusion_candidates) == 0:
        raise ValueError("No candidates to pick")
    not_excluded_candidates = candidates - exclusion_candidates
    set_to_choose_from = exclusion_candidates if len(not_excluded_candidates) == 0 else not_excluded_candidates
    return random.sample(set_to_choose_from, 1)[0]


async def run_proxy_peer_pool(event_bus: EndpointAPI) -> ETHProxyPeerPool:
    proxy_peer_pool = ETHProxyPeerPool(
        event_bus,
        TO_NETWORKING_BROADCAST_CONFIG,
    )

    # todo this doesn't have to be an asyncio.ensure_future?
    await proxy_peer_pool.run()
    await proxy_peer_pool.events.started.wait()

    try:
        return proxy_peer_pool
    finally:
        await proxy_peer_pool.cancel()
