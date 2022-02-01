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

class Transactions:
    def __init__(self):
        self.transactions = []

    def add(self, transaction:Transaction):
        self.transactions.append(transaction)

    def remove(self, transaction):
        if transaction in self.transactions:
            del self.transactions[self.transactions.index(transaction)]
            return True
        else:
            return False

class Block:
    def __init__(self, previous_sign):
        self.nonce = None
        self.signature = None
        self.previous_sign = previous_sign
        self.transactions = Transactions()

    def add_transaction(self, transaction:Transaction):
        assert self.signature is None
        self.transactions.add(transaction)

    def remove_transaction(self, transaction:Transaction):
        assert self.signature is None
        self.transactions.remove(transaction)

    def read_block(self):
        # TODO: Make a better database method
        return str(self.transactions)

    def sign(self):
        assert self.signature is None
        # TODO Make a sign function using hashes
        self.signature = self.read_block()

    def get_signature(self):
        return self.signature

class Blockchain:
    @staticmethod
    def verify_blocks(block1:Block, block2:Block):
        """Verfies whether chaining two blocks block1 U block2 is valid"""
        # TODO implement hash signatures
        return block2.previous_signature == block1.get_signature()

    @staticmethod
    def verify_signature(block:Block, signature):
        return block.get_signature() == signature

    def __init__(self, initial_block:Block):
        self.timelines = [[initial_block]]

    def chain_block(self, block:Block):
        for timeline in self.timelines:
            if timeline[-1].get_signature() == block.previous_sign:
                if Blockchain.verify_sign(block.get_signature(), block.read_block()):
                    raise NotImplementedError()

    @staticmethod
    def flatten_timelines(timelines):
        """Flattens the timelines data-structure and returns a list of all complete timeline possibilities to be iterated upon"""
        # Smallest 
        
        if len(timelines) == 0:
            return timelines

        prefix = []
        while len(timelines) > 0 and type(timelines[0]) != list:
            prefix.append(timelines.pop(0))

        if len(timelines) == 0:
            return [prefix]

        output = []
        for timeline in timelines[0]:
            next_recursion = Blockchain.flatten_timelines(timeline)
            for branch in next_recursion:
                output.append(prefix + branch)
        return output

if __name__ == '__main__':
    initial_block = Block(None)
    x = [1, 2, 3, 4, [[[5, 6], [7, [8, [80, 90]]]], [9, 10, 90]], [[11, 12, 13, 14], [15, 16]]]
    x = [1, 2, 3, 4, [[5, 6, [[10, 20, 50], [30, 40]]], [7, 8]]]
    y = Blockchain.flatten_timelines(x)
    print(y)
