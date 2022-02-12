from Crypto.PublicKey import RSA
import json
import hashlib
import random

import data_structures

class Transaction:
    # Once a transaction object is initiated it is assumed all of its values are valid
    # except the signature, which needs to be manually verified using verify_signature()
    def __init__(self, sender, receiver, miner_fee, nonce, value, signature):
        # TODO Digital Signatures
        self.sender = sender
        self.receiver = receiver
        self.nonce = nonce
        self.miner_fee = miner_fee
        self.value = value
        self.signature = signature

        # type_prefix
        # Transaction type must be a three letter string
        # crt - currency transaction, this type is for transactions of cryptocurrency
        # fee - initial block transaction, receiver is the miner who mined the block.
        #       The validity of this transaction is rooted in the validity of its block
        # nft - non-fungible token, this type is for media proof of ownership
        # gnd - generic data, this has no special propeties aside from the fact that it is not filtered
        self.type_prefix = None

    # Create a digital signature for the transaction
    # p_key: the private key that is paired with the sender wallet
    def digital_sign(self, p_key):
        # TODO Implement digital signing
        # Temporary non-cryptographic signing (To be replaced)
        self.signature = str(self.data) + str(self.sender)

    def __repr__(self):
        return self.json_dumps_transaction()

    def verify_signature(self):
        # TODO Implement digital signature verifying.
        # Temporary non-cryptographic method (To be replaced)
        return self.signature == hashlib.sha256

    @staticmethod
    def json_loads_transaction(json_str:str):
        try:
            information = json.loads(json_str)
            assert type(information) == list
            assert len(information) == 7
            if information[0] == "crt":
                transaction_object = CurrencyTransaction(*information)
            elif information[0] == "nft":
                transaction_object = NftTransaction(*information)
            elif information[0] == "gnd":
                transaction_object = DataTransaction(*information)
            else:
                raise ValueError("Invalid type prefix in JSON. Possibly corrupt data")
            return transaction_object
        except Exception as err:
            print("Failed to create Transaction object from JSON. (Invalid data")
            raise err

    def json_dumps_transaction(self):
        information = [self.type_prefix, self.sender, self.receiver, self.miner_fee, self.nonce, self.value, self.signature]
        return json.dumps(information)

class CurrencyTransaction(Transaction):
    def __init__(self, sender, receiver, value:int, miner_fee:int):
        super().__init__(sender, receiver, value, miner_fee)
        self.type_prefix = "crt"

    def verify_transaction(self):
        if not super().verify_transaction():
            return False
        try:
            int(self.value)
        except ValueError:
            return False

    def get_value(self):
        return self.value

class NftTransaction(Transaction):
    def __init__(self, sender, receiver, value:int, miner_fee:int):
        super().__init__(sender, receiver, value, miner_fee)
        self.type_prefix = "nft"

    def verify_transaction(self):
        if not super().verify_transaction():
            return False
    def get_value(self):
        return self.value

class DataTransaction(Transaction):
    def __init__(self, sender, receiver, value:str, miner_fee:int):
        super().__init__(sender, receiver, value, miner_fee)

        self.type_prefix = "gnd"

    def verify_transaction(self):
        if not super().verify_transaction():
            return False
        if len(self.data) == 0 or len(self.data) > 140:
            return False
        return True

    def get_value(self):
        return self.value

class Block:
    MAX_TRANSACTIONS_LENGTH = 727

    def __init__(self, previous_sign, height):
        self.signature = None
        self.previous_sign = previous_sign
        self.height = height
        self.transactions = []
        self.nonce = 0
        self.data = bytes()

    def add_transaction(self, transaction:Transaction):
        self.nonce = 0
        self.transactions.append(transaction)

    def remove_transaction(self, transaction:Transaction):
        self.nonce = 0
        self.transactions.remove(transaction)

    def read_block(self):
        # TODO: Make a better database method
        return bytes(self.transactions)

    def sign(self):
        # TODO Make a sign function using hashes
        self.signature = hashlib.sha256(self.read_block())
        return self.signature

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
    GENESIS_BLOCK = Block(None, 0).sign()
    TRUST_HEIGHT = 10
    WALLET_RECORD_TEMPLATE = {"crt": [], "nft": [], "gnd": []}
    AVERAGE_TIME_PER_BLOCK = 300 # in seconds
    BLOCK_REWARD_SEASON = (0.5*365*24*60*60/AVERAGE_TIME_PER_BLOCK) # 52560
    BLOCK_INITIAL_REWARD = 727
    BLOCK_REWARD_SUM = BLOCK_REWARD_SEASON * BLOCK_INITIAL_REWARD * 2 # 76422240

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
            transactions = self.blockchain[-1].transactions
            # miner fees
            transactions.insert(0, CurrencyTransaction(None, self.receiver, self.calculate_block_reward(block)))
            for i, transaction in enumerate(transactions):
                if transaction.sender:
                    wallet_records = self.transaction_tree.find(transaction.sender)
                    if wallet_records is not None:
                        records = wallet_records.value
                    else:
                        records = Blockchain.WALLET_RECORD_TEMPLATE
                    # New record (|value|, polarity, block index, transaction index)
                    # negativity - if a transaction is negative (1) or positive (0).
                    records[transaction.type_prefix].append((transaction.value, 1, block.height, i))
                    wallet_records.value = records
                    self.transaction_tree.insert(self.transaction_tree, wallet_records)

                if transaction.receiver:
                    wallet_records = self.transaction_tree.find(transaction.receiver)
                    if wallet_records is not None:
                        records = wallet_records.value
                    else:
                        records = Blockchain.WALLET_RECORD_TEMPLATE
                    # New record (|value|, polarity, block index, transaction index)
                    # negativity - if a transaction is negative (1) or positive (0).
                    records[transaction.type_prefix].append((transaction.value, 0, block.height, i))
                    wallet_records.value = records
                    self.transaction_tree.insert(self.transaction_tree, wallet_records)

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

    def calculate_block_reward(self, block):
        # We divide block reward in two every 52560 blocks (half a year if 5m per block)
        # a0 = 727 * 52560 = 38211120
        # sum of geometric series = 2 * a0 = 76422240
        # Total currency amount 76 422 240
        r = 0.5
        n = block.height // Blockchain.BLOCK_REWARD_SEASON
        block_reward = Blockchain.BLOCK_INITIAL_REWARD * r**n
        for transaction in block_reward.transactions:
            block_reward += transaction.miner_fee
        return block_reward

# debugging
if __name__ == '__main__':
    # t = CurrencyTransaction("a", "b", 1, 0)
    with open("transaction_dumps_example.json", "r") as amogus:
       t = Transaction.json_loads_transaction(amogus.read())
    print(t)