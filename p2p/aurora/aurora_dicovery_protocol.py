import random
from typing import Sequence, Set, Tuple, Dict, List

import trio
from eth_keys import datatypes
from eth_utils import get_extended_debug_logger
from lahja import EndpointAPI
from pympler import asizeof

from p2p import constants
from p2p.abc import AddressAPI, NodeAPI, SessionAPI
from p2p.aurora.aurora_parameters import AuroraParameters
from p2p.aurora.util import calculate_distance, aurora_pick, quantified_mistake, \
    optimize_distance_with_mistake, calculate_correctness_indicator, aurora_put, optimum
from p2p.constants import KADEMLIA_BUCKET_SIZE
from p2p.discovery import PreferredNodeDiscoveryService
from trinity.constants import TO_NETWORKING_BROADCAST_CONFIG
from trinity.events import ShutdownRequest
from trinity.protocol.common.events import ConnectToNodeCommand, GetConnectedPeersRequest, PeerJoinedEvent, \
    PeerHeadHashRequest
from memory_profiler import profile


class CliqueDetectedError(Exception):
    """Possible malicious network"""
    pass


class AuroraDiscoveryService(PreferredNodeDiscoveryService):
    logger = get_extended_debug_logger('p2p.aurora.AuroraDiscoveryService')

    def __init__(self,
                 privkey: datatypes.PrivateKey,
                 address: AddressAPI,
                 bootstrap_nodes: Sequence[NodeAPI],
                 preferred_nodes: Sequence[NodeAPI],
                 event_bus: EndpointAPI,
                 socket: trio.socket.SocketType,
                 aurora_parameters: AuroraParameters,
                 distance: float = None) -> None:
        super().__init__(privkey, address, bootstrap_nodes, preferred_nodes, event_bus, socket)
        self.aurora_parameters: AuroraParameters = aurora_parameters
        self.distance = distance

    async def run(self) -> None:
        self.manager.run_daemon_task(self.handle_get_peer_candidates_requests)
        self.manager.run_daemon_task(self.handle_get_random_bootnode_requests)
        # todo you can make aurora walks periodical
        # self.manager.run_daemon_task(self.periodically_refresh)

        self.manager.run_daemon_task(self.consume_datagrams)
        self.manager.run_task(self.bootstrap)
        await self.manager.wait_finished()

    async def lookup_random(self) -> Tuple[NodeAPI, ...]:
        self.logger.info("Aurora Component lookup started...")
        entry_node: NodeAPI = list(self.routing.get_random_nodes(1))[0]
        try:
            await self.aurora_tally(entry_node,
                                    self.aurora_parameters.threshold,
                                    self.aurora_parameters.network_size,
                                    KADEMLIA_BUCKET_SIZE,
                                    self.aurora_parameters.num_of_walks,
                                    self.distance)
        except CliqueDetectedError:
            self.logger.warning("Clique detected during p2p discovery!")
            await self._event_bus.broadcast(ShutdownRequest("Possible malicious network - exiting!"))

    @profile
    async def aurora_walk(self,
                          entry_node: NodeAPI,
                          network_size: int,
                          standard_mistakes_threshold: int,
                          distance: float) -> Tuple[float, any, Set[NodeAPI]]:
        collected_nodes_set: Set[NodeAPI] = set()
        iteration = 0
        accumulated_mistake = 0
        current_node_in_walk: NodeAPI = entry_node

        self.logger.info(f"Starting Aurora walk - distance: {distance:.2f}, "
                         f"mistake_threshold: {standard_mistakes_threshold}")

        while iteration < distance:
            # https://www.gigacalculator.com/converters/convert-bytes-to-mb.php


            self._send_find_node(current_node_in_walk, self.random_kademlia_node_id())
            candidates = await self.wait_neighbours(current_node_in_walk)

            if len(candidates) == 0:
                self.logger.info(f"Peer {current_node_in_walk.id} timeout, picking another candidate.")
                current_node_in_walk = aurora_pick(collected_nodes_set)
                continue

            last_neighbours_response_size = len(candidates)
            num_of_already_known_peers = len(collected_nodes_set & set(candidates))
            collected_nodes_set.update(candidates)
            num_of_collected_total = len(collected_nodes_set)
            if network_size <= len(collected_nodes_set):
                self.logger.info("Exiting the walk because collected nodes reached the network size. "
                                 "Make sure that a good network size approximation was provided.")
                break
            mistake = quantified_mistake(network_size,
                                         num_of_collected_total,
                                         last_neighbours_response_size,
                                         num_of_already_known_peers)
            accumulated_mistake += mistake
            distance = optimize_distance_with_mistake(distance, mistake)
            current_node_in_walk = aurora_pick(set(candidates), collected_nodes_set)
            iteration += 1
            self.logger.info(f"##Object size: ({asizeof.asizeof(self)} bytes, {asizeof.asizeof(self)/1048576} MB)##")


            self.logger.info(f"iter: {iteration} | distance: {distance:.2f} | "
                             f"{num_of_already_known_peers}/{last_neighbours_response_size} known peers | "
                             f"total_mistake: {accumulated_mistake:.2f} (+{mistake:.2f}) | "
                             f"{num_of_collected_total} collected")

            if accumulated_mistake >= standard_mistakes_threshold:
                self.logger.warning("Aurora is assuming malicious a activity: exiting the network!")
                raise CliqueDetectedError

        correctness_indicator = calculate_correctness_indicator(accumulated_mistake, standard_mistakes_threshold)
        head_hash = await self.aurora_head(current_node_in_walk, self._event_bus)
        self.logger.info(f"Node hash: {head_hash}")
        return correctness_indicator, head_hash, collected_nodes_set

    @profile
    async def aurora_tally(self,
                           entry_node: NodeAPI,
                           standard_mistakes_threshold: int,
                           network_size: int,
                           neighbours_response_size: int,
                           num_of_walks: int,
                           distance: float = None):
        correctness_dict: Dict[any, List[float]] = {}
        iteration = 0
        current_node = entry_node
        self.logger.debug2("Starting the calculation of the distance...")
        if distance is None:
            distance = calculate_distance(network_size, neighbours_response_size)
        while iteration < num_of_walks:
            try:
                correctness_indicator, head_hash, collected_nodes_set = \
                    await self.aurora_walk(
                        current_node,
                        network_size,
                        standard_mistakes_threshold,
                        distance)
            except ConnectionRefusedError:
                self.logger.info(f"Executing additional Aurora walk"
                                 f" - timeout connecting to a proxy peer pool")
                continue
            except CliqueDetectedError:
                # stuck in clique
                raise
            correctness_dict = aurora_put(correctness_dict,
                                          head_hash,
                                          correctness_indicator)
            current_node = aurora_pick(collected_nodes_set)
            iteration += 1
        return optimum(correctness_dict)

    @classmethod
    async def aurora_head(cls, node: NodeAPI, event_bus: EndpointAPI, block_hash=None, tx_hash=None):
        """ Returns the head hash from a remote node """
        cls.logger.debug2("sending ConnectToNodeCommand")
        await event_bus.broadcast(
            ConnectToNodeCommand(node),
            TO_NETWORKING_BROADCAST_CONFIG
        )
        cls.logger.debug2("sending peer GetConnectedPeersRequest")
        response = await event_bus.request(GetConnectedPeersRequest())
        cls.logger.debug2(f"got GetConnectedPeersRequest {response}")
        sessions: Tuple[SessionAPI, ...] = response.sessions
        target_session: SessionAPI = None
        for session in sessions:
            if session.remote.id == node.id:
                target_session = session
                break
        # todo implement a timout here
        if target_session is None:
            cls.logger.debug2("waiting on PeerJoinedEvent")
            async for event in event_bus.stream(PeerJoinedEvent):
                cls.logger.debug2("got PeerJoinedEvent")
                if event.session.remote.id == node.id:
                    target_session = event.session

        if block_hash is not None and tx_hash is not None:
            await cls.aurora_proof(node, block_hash, tx_hash)

        response = await event_bus.request(PeerHeadHashRequest(target_session))
        return response.head_hash

    @staticmethod
    async def aurora_proof(remote_node, block_hash, tx_hash):
        """
        This method is not implemented yet since Trinity lacks API support for fetching Merkle Proof RLPx data from
        a specific peer form the peer pool.
        This method should do the following:
        To get the proof, we need transaction index which we can get through receipt of the transaction.
        So we have to know the transaction block hash, and then ask for the receipt(es), where one of them will
        contain the transaction index.
        This method could also support verifying a given account state.
        """
        raise NotImplementedError

    @staticmethod
    def random_kademlia_node_id() -> int:
        return random.randint(0, constants.KADEMLIA_MAX_NODE_ID)
