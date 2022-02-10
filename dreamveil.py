import Crypto
import random

from AVL import AVL

class TransactionRecord:
    def __init__(wallet, value):
        raise NotImplementedError()

class Transaction:
    def __init__(self, sender, receiver, value, miner_fee=0):
        # TODO Digital Signatures
        self.sender = sender
        self.receiver = receiver
        self.nonce = random.randint(0, 2**64) # Roll a random nonce
        self.signature = None
        self.value = value
        self.miner_fee = miner_fee
        # TODO: Create a defined data format for transactions (Possibly json?)
        self.data = str(value)

        # type_prefix
        # Transaction type must be a three letter string
        # crt - currency transaction, this type is for transactions of cryptocurrency
        # fee - initial block transaction, reciever is the miner who mined the block.
        #       The validity of this transaction is rooted in the validity of its block
        # nft - non-fungible token, this type is for media proof of ownership
        # gnd - generic data, this has no special propeties
        self.type_prefix = None

    # Create a digital signature for the transaction
    # p_key: the private key that is paired with the sender wallet
    def digital_sign(self, p_key):
        # TODO Implement digital signing
        assert self.data is not None
        # Temporary non-cryptographic signing (To be replaced)
        self.signature = str(self.data) + str(self.sender)

    def __repr__(self):
        return self.data

    def verify_transaction(self):
        # TODO Implement digital signature verifying.
        # Temporary non-cryptographic method (To be replaced)
        return self.signature == str(self.data) + str(self.sender)

class CurrencyTransaction(Transaction):
    def __init__(self, sender, reciever, value:int, miner_fee:int):
        super().__init__(sender, reciever, value, miner_fee)
        self.type_prefix = "crt"

    def verify_transaction(self):
        if not super().verify_transaction():
            return False
        try:
            int(self.value)
        except ValueError:
            return False


    def get_value(self):
        return int(self.data)

class FeeTransaction(Transaction):
    def __init__(self, miner, data:str):
        super().__init__(miner, miner, data)
        self.type_prefix = "fee"

    def verify_transaction(self):
        return super().verify_transaction()

    def get_value(self):
        return int(self.data)

class NftTransaction(Transaction):
    def __init__(self, sender, reciever, value:int, miner_fee=0):
        super().__init__(sender, reciever, value, miner_fee)
        self.type_prefix = "nft"

    def verify_transaction(self):
        if not super().verify_transaction():
            return False
    def get_value(self):
        return self.data

class DataTransaction(Transaction):
    def __init__(self, sender, reciever, data:str):
        super().__init__(sender, reciever, data)

        self.type_prefix = "gnd"

    def verify_transaction(self):
        if not super().verify_transaction():
            return False
        try:
            int(self.data)
        except ValueError:
            return False

    def get_value(self):
        return self.data

class Block:
    def __init__(self, previous_sign, difficulty):
        self.signature = None
        self.previous_sign = previous_sign
        self.transactions = []
        self.nonce = 0
        self.difficulty = None

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

    def verify_block(self):
        for transaction in self.transactions:
            if not transaction.verify_transaction():
                return False

        currency_transactions = [crt for crt in self.transactions if type(crt) == CurrencyTransaction]
        for sender in [crt.sender for crt in currency_transactions]:
            if currency_transactions.count(sender) != 1:
                return False
        fee_transactions = [fee for fee in self.transactions if type(fee) == FeeTransaction]
        if len(fee_transactions) != 1:
            return False

        valid_reward = sum([crt.miner_tax for crt in currency_transactions])
        # TODO: Add changing difficulty block reward
        valid_reward += 50 # Dummy block difficulty reward
        if fee_transactions[0].value != valid_reward:
            return False

class Blockchain:
    GENESIS_BLOCK = Block(None).sign()

    def __init__(self):
        self.chain = [Blockchain.GENESIS_BLOCK]
        self.currency_tree = AVL()
        self.nft_tree = AVL()

    def chain_block(self, block:Block):
        """Chains a block to the blockchain, only blocks that are considered trusted are to be chained"""
        if self.chain[-1].sign == block.previous_sign:
                # The block chains to the blockchain
                self.chain.append(block)
                for transaction in block.transactions:
                    if type(transaction) == "crt" or type(transaction) == "fee":
                        self.currency_tree.insert()