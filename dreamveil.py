import Crypto
import random

from AVL import AVL

class Transaction:
    def __init__(self, sender, receiver, type_prefix:str, data:str):
        # TODO Digital Signatures
        self.sender = sender
        self.receiver = receiver
        self.nonce = random.randint(0, 2**64) # Roll a random nonce
        self.signature = None

        # Transaction type must be a three letter string
        # crt - currency transaction, this type is for transactions of cryptocurrency
        # nft - non-fungible token, this type is for media proof of ownership
        # gnd - generic data, this has no special propeties
        # tax - initial block transaction, sender is the miner who mined the block.
        self.type = type_prefix
        self.data = data

    # Create a digital signature for the transaction
    # p_key: the private key that is paired with the sender wallet
    def digital_sign(self, p_key):
        # TODO Implement digital signing
        assert self.data is not None
        self.signature = self.data + str(self.sender)

    def get_value(self):
        if self.type == "tax" or self.type == "crt":
            return int(self.data)
        else:
            return self.data

    def __repr__(self):
        return self.data


class Block:
    def __init__(self, previous_sign):
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

class Blockchain:
    GENESIS_BLOCK = Block(None).sign()

    def __init__(self):
        self.chain = [Blockchain.GENESIS_BLOCK]
        self.transaction_tree = AVL()

    def verify_transaction(self, transaction):
        pass
    
    def chain_block(self, block:Block):
        """Chains a block to the blockchain, only blocks that are considered trusted are to be chained"""
        if self.chain[-1].sign == block.previous_sign:
                # The block chains to the blockchain
                self.chain.append(block)

if __name__ == '__main__':
    t = Transaction("me", "you", "crt")
    t.get_value()