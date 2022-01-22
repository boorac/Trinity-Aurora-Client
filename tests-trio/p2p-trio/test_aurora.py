import random
from typing import Tuple, Set, List, Dict
import math

import pytest
from unittest.mock import Mock

import trio
from eth_hash.auto import keccak

from eth_keys import keys

from lahja import EndpointAPI

from p2p import constants
from p2p.abc import NodeAPI
from p2p.aurora.aurora_dicovery_protocol import AuroraDiscoveryService, CliqueDetectedError
from p2p.aurora.aurora_parameters import AuroraParameters
from p2p.aurora.util import aurora_pick, calculate_distance
from p2p.kademlia import Address
from p2p.tools.factories import (
    NodeFactory,
)


@pytest.mark.trio
async def test_aurora_tally_clique_detected(manually_driven_discovery):
    async def aurora_walk_mock(*args):
        raise CliqueDetectedError
    manually_driven_discovery.aurora_walk = aurora_walk_mock
    with pytest.raises(CliqueDetectedError):
        await manually_driven_discovery.aurora_tally(NodeFactory(), 10, 50, 16, 3)


@pytest.mark.trio
async def test_aurora_tally(manually_driven_discovery):
    proto = manually_driven_discovery
    m = Mock()

    def make_coroutine(mock):
        async def coroutine(*args, **kwargs):
            return mock(*args, **kwargs)
        return coroutine

    m.side_effect = [
        (0.8, "block_a", set(NodeFactory.create_batch(16))),
        (0.9, "block_b", set(NodeFactory.create_batch(16))),
        (0.7, "block_c", set(NodeFactory.create_batch(16))),
    ]
    proto.aurora_walk = make_coroutine(m)
    result_key, _ = await proto.aurora_tally(NodeFactory(), 10, 50, 16, 3)
    assert result_key == "block_b"
    assert m.call_count == 3


@pytest.mark.trio
async def test_aurora_pick_existing_candidates():
    candidates = NodeFactory.create_batch(4)
    node1, node2, *other_nodes = candidates
    exclusion_candidates = {node1, node2}
    result = aurora_pick(set(candidates), exclusion_candidates)

    assert result in candidates
    assert result not in exclusion_candidates


@pytest.mark.asyncio
async def test_aurora_pick_non_existing_candidates():
    candidates = set(NodeFactory.create_batch(2))
    exclusion_candidates = candidates
    result = aurora_pick(candidates, exclusion_candidates)

    assert result in exclusion_candidates


async def random_socket():
    socket = trio.socket.socket(
        family=trio.socket.AF_INET,
        type=trio.socket.SOCK_DGRAM,
    )
    # specifying 0 as port number results in using random available port
    await socket.bind(("127.0.0.1", 0))
    return socket


@pytest.mark.parametrize("network_size, malpn, malpg, mistake_threshold, should_exit_clique", [
    (100, 0.1, 0.1, 50, False),  # finding honest node to sync
    (100, 0.125, 1, 50, True),  # eclipse attack
    (100, 0.4, 0.9, 50, True),  # almost full eclipse attack
    (100, 0, 0.1, 50, False),  # all honest nodes
])
@pytest.mark.trio
async def test_aurora_walk(network_size, malpn, malpg, mistake_threshold, should_exit_clique):
    # make this test deterministic
    random.seed('seed')

    batch = NodeFactory.create_batch(network_size)
    pubkey_honesty: Dict[any, Tuple[NodeAPI, bool]] = {}
    distance = calculate_distance(network_size)

    # populate honest and malicious nodes
    honest_nodes: Set[NodeAPI] = set()
    malicious_nodes: Set[NodeAPI] = set()
    for index, node in enumerate(batch):
        if index < network_size * malpn:
            pubkey_honesty.update({node.pubkey: False})
            malicious_nodes.add(node)
        else:
            pubkey_honesty.update({node.pubkey: True})
            honest_nodes.add(node)
    socket = await random_socket()
    aurora_parameters = AuroraParameters(network_size, mistake_threshold, 1)
    proto = MockDiscoveryProtocolAurora(batch, honest_nodes, malicious_nodes, malpg, socket, None, aurora_parameters)

    entry_node = random.choice(tuple(malicious_nodes if malpn != 0 else honest_nodes))

    if should_exit_clique:
        with pytest.raises(CliqueDetectedError):
            await proto.aurora_walk(entry_node,
                                    network_size,
                                    mistake_threshold,
                                    distance)
    else:
        _, result_pubkey, _ = await proto.aurora_walk(entry_node,
                                                      network_size,
                                                      mistake_threshold,
                                                      distance)
        assert result_pubkey in pubkey_honesty
        assert pubkey_honesty[result_pubkey]


def link_transport_to_multiple(our_protocol, protocols):
    def _tuple_address_from_protocol(protocol):
        return protocol.address.ip, protocol.address.udp_port

    for protocol in protocols:
        protocol.transport = type(
            "mock-transport",
            (object,),
            {"sendto": lambda msg, addr: our_protocol
                .datagram_received(msg, _tuple_address_from_protocol(protocol))},
        )

    def _send_to_mock(msg, addr):
        ip, udp_port = addr
        # find protocol we want to send to
        # todo change this to filtering
        send_to_protocol = None
        for protocol in protocols:
            if protocol.address.ip == ip and protocol.address.udp_port == udp_port:
                send_to_protocol = protocol
                break
        # mimic sending over wire
        # await asyncio.sleep(1)
        return send_to_protocol.datagram_received(msg, _tuple_address_from_protocol(our_protocol))

    our_protocol.transport = type(
        "mock-transport",
        (object,),
        {"sendto": _send_to_mock},
    )


class MockDiscoveryProtocolAurora(AuroraDiscoveryService):
    def __init__(self,
                 bootstrap_nodes,
                 honest_nodes: Set[NodeAPI],
                 malicious_nodes: Set[NodeAPI],
                 malpg,
                 socket,
                 proxy_peer_pool,
                 aurora_parameters: AuroraParameters):
        privkey = keys.PrivateKey(keccak(b"seed"))
        self.messages = []
        self.honest_nodes = honest_nodes
        self.malicious_nodes = malicious_nodes
        self.malpg = malpg
        super().__init__(privkey,
                         Address(*socket.getsockname()),
                         bootstrap_nodes,
                         bootstrap_nodes,
                         None,
                         socket,
                         aurora_parameters)

    def _send_find_node(self, node: NodeAPI, target_node_id: int) -> None:
        return None

    @staticmethod
    async def aurora_head(node: NodeAPI, event_bus: EndpointAPI):
        return node.pubkey

    async def wait_neighbours(self, remote: NodeAPI) -> Tuple[NodeAPI, ...]:
        response: List[NodeAPI] = list()
        response_size = constants.KADEMLIA_BUCKET_SIZE

        number_of_malicious = min(math.ceil(response_size * self.malpg), len(self.malicious_nodes))
        number_of_honest = min(response_size - number_of_malicious, len(self.honest_nodes))

        if number_of_malicious:
            response.extend(random.sample(self.malicious_nodes, number_of_malicious))
        if number_of_honest:
            response.extend(random.sample(self.honest_nodes, number_of_honest))
        return tuple(response)
