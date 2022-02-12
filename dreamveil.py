import Crypto
import random

from cv2 import add

import data_structures

class WalletRecord:
    WALLET_RECORD_TEMPLATE = {"crt": [], "nft": [], "gnd": []}

    def __init__(self):
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
    MAX_TRANSACTIONS_LENGTH = 727

    def __init__(self, previous_sign, height, difficulty):
        self.signature = None
        self.previous_sign = previous_sign
        self.height = height
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
        if len(currency_transactions) == 0 or len(currency_transactions) > Block.MAX_TRANSACTIONS_LENGTH:
            return False
        currency_transactions_senders = [crt.sender for crt in currency_transactions]
        for sender in currency_transactions_senders:
            if currency_transactions_senders.count(sender) != 1:
                return False

        #miner_reward = sum([crt.miner_fee for crt in currency_transactions])
        # TODO: Add changing difficulty block reward
        #miner_reward += 50 # Dummy block difficulty reward
        return True

    def do_blocks_chain(self, antecedent_block):
        """Checks if antecedent_block << self is a valid chain"""
        if antecedent_block.signature != self.previous_sign:
            return False
        if antecedent_block.height != self.height+1:
            return False
        return True


class Blockchain:
    GENESIS_BLOCK = Block(None).sign()
    TRUST_HEIGHT = 10

    def __init__(self):
        self.chain = [Blockchain.GENESIS_BLOCK]
        self.transaction_tree = data_structures.AVL()
        self.untrusted_timeline = data_structures.multifurcasting_node(self.chain[-1])

    def chain_block(self, block:Block):
        """Tries to chain a block to the blockchain. This function succeeds only if a block is valid.
        Valid blocks first move into the untrusted timeline.
        The block is chained to the blockchain once it reaches TRUST_HEIGHT in the untrusted timeline
        On success returns True. Returns False otherwise"""
        if not self.verify_block(block):
            # Block is invalid
            return False
        if not self.add_block_to_untrusted_timeline(self.untrusted_timeline, block):
            # Block is unrelated to the main chain
            # TODO: Check/show that block(x+1) cannot practically arrive before block(x)
            return False

        if self.untrusted_timeline.calculate_height() == Blockchain.TRUST_HEIGHT+1:
            # Untrusted block has a TRUST_HEIGHT timeline
            # Block is chained into the blockchain since it can now be trusted
            newly_trusted_block_node = self.untrusted_timeline.get_highest_child()
            self.blockchain.append(newly_trusted_block_node.key)
            # Remove the now trusted block from the timeline and advance on its timeline
            self.untrusted_timeline = newly_trusted_block_node

            # Record all of the transactions in the newly added block in the transaction AVL tree
            # TODO: CONTINUE FROM HERE!!!
            #for transaction in self.blockchain[-1].transactions:
            #    wallet_records = self.transaction_tree.find(transaction.sender)
            #    if wallet_records is None:
            #        new_record = Blockchain.WALLET_RECORD_TEMPLATE
            #        new_record[transaction.type_prefix].append((transaction.value, self.blockchain[-1].height))
            #        transaction_record = data_structures.binary_tree_node(transaction.sender, new_record)
            #        self.transaction_tree.insert(transaction_record)
            #    else:
            #        pass
        #if self.chain[-1].sign == block.previous_sign:
        #        # The block chains to the blockchain
        #        self.chain.append(block)
        #        for transaction in block.transactions:
        #            if type(transaction) == "crt" or type(transaction) == "fee":
        #                self.currency_tree.insert()

    def add_block_to_untrusted_timeline(self, root, block):
        if block.do_blocks_chain(root.key):
            next_node = data_structures.multifurcasting_node(block)
            root.children.append(next_node)
            return True
        for child in root.children:
            if self.add_block_to_untrusted_timeline(child, block):
                return True
        return False

    def verify_block(self, block):
        """Checks if a block is entirely authentic, including its contents (transactions) and their complete validity"""
        raise NotImplementedError()


if __name__ == '__main__':
    pass