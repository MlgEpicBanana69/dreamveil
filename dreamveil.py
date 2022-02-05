import Crypto
import hashlib

class Transaction:
    # Idealy this data form will support currency transaction and amongst other generic
    # item transactions (NFTs)?
    def __init__(self, content):
        # TODO Digital Signatures
        self.content = content

    def __repr__(self):
        return self.content

class Block:
    def __init__(self, previous_sign=None):
        self.signature = None
        self.previous_sign = previous_sign
        self.transactions = []
        self.nonce = 0

    def add_transaction(self, transaction:Transaction):
        self.transactions.append(transaction)

    def remove_transaction(self, transaction:Transaction):
        self.transactions.remove(transaction)

    def read_block(self):
        # TODO: Make a better database method
        return str(self.transactions)

    def sign(self):
        # TODO Make a sign function using hashes
        self.signature = self.read_block()
        return self

    def get_signature(self):
        return self.signature

class Blockchain:
    GENESIS_BLOCK = Block(None).sign()

    @staticmethod
    def verify_blocks(block1:Block, block2:Block):
        """Verfies whether chaining two blocks block1 <U< block2 is valid"""
        # TODO implement hash signatures
        return block2.previous_signature == block1.get_signature()

    @staticmethod
    def verify_signature(block:Block, signature):
        return block.get_signature() == signature

    def __init__(self):
        self.timeline = [Blockchain.GENESIS_BLOCK]

    def chain_block(self, block:Block):
        """Chains a block to the blockchain, only blocks that are considered trusted are to be chained"""
        if Blockchain.verify_blocks(self.timeline[-1], block):
            # The block chains to the blockchain
            self.timeline.append(block)
            return True # Block was chained successfully
        return False # Could not chain block anywhere.



if __name__ == '__main__':
    initial_block = Block(None)
    x = [1, 2, 3, 4, [[[5, 6], [7, [8, [80, 90]]]], [9, 10, 90]], [[11, 12, 13, 14], [15, 16]]]
    x = [1, 2, 3, 4, [[5, 6, [[10, 20, 50], [30, 40]]], [7, 8]]]
    y = Blockchain.split_timelines(x)
    print(sorted(y, key=len))
    print(y)
