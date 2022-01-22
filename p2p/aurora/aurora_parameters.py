from abc import ABC


class AuroraParameters(ABC):

    def __init__(self, network_size, threshold, num_of_walks, block_hash=None, tx_hash=None):
        self.network_size = int(network_size)
        self.threshold = int(threshold)
        self.num_of_walks = int(num_of_walks)
        self.block_hash = block_hash
        self.tx_hash = tx_hash
