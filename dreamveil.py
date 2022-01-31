import Crypto
import hashlib

class Blockchain:
    def __init__(self):
        self.timelines = {}

class Block:
    def __init__(self, previous_sign):
        self.previous_sign = previous_sign
        self.transactions = []
        self.nonce = None
        self.signature = None

    def add_transaction(self, transaction):
        assert self.signature is None
        self.transactions.append(transaction)
    
    def remove_transaction(self, transaction):
        assert self.signature is None
        if transaction in self.transactions:
            del self.transaction[self.transactions.index(transaction)]
            return True
        else:
            return False

    def read_block(self):
        # TODO: Make a better database method
        return str(self.transactions)
    
    def __repr__(self) -> str:
        raise NotImplementedError

    def sign(self):
        assert self.signature is None
        # TODO Make a sign function using hashes
        self.signature = self.read_block()
    


class Transaction:

    # Idealy this data form will support currency transaction and amongst other generic
    # item transactions (NFTs)?
    def __init__(self):
        pass

class Transactions:
    def __init__(self):
        self.transactions = []