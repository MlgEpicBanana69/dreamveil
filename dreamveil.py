from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import json
import hashlib
import secrets

import data_structures

class Transaction:
    # Once a transaction object is initiated it is assumed all of its values are valid
    # except the signature, which needs to be manually verified using verify_signature()
    def __init__(self, sender:str, receiver:str, miner_fee:int, nonce:str, value, signature:str):
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
    def sign(self, p_key:RSA.RsaKey):
        """Signs the transaction object after generating a random Nonce for it using RSA"""
        # Generate and set a random Nonce
        self.nonce = secrets.randbits(256)
        # Generate the transaction hash (Including the nonce)
        transaction_hash = SHA256.new(self.json_dumps_transaction().encode()).hexdigest()
        # Encrypt the transaction hash using the RSA private key (Digital signature)
        digital_signature = hex((int(transaction_hash, base=16) ** p_key.e) % p_key.n)[1::]
        # Set and return the generated digital signature
        self.signature = digital_signature
        return digital_signature

    def verify_signature(self):
        """Verifies if the digital signature of the transaction is the same as its true computed digital signature"""
        # TODO DEBUG THIS
        try:
            rsa_public_key = RSA.import_key(self.sender)
            computed_hash = SHA256.new(self.json_dumps_transaction().encode()).hexdigest()
            proposed_hash = hex((self.signature ** rsa_public_key.d) % rsa_public_key.n)[1::],
            if secrets.compare_digest(computed_hash, proposed_hash):
                return True
        except Exception as err:
            print(f"Verify signature raised exception {err}: {err.args}")
        return False

    def __repr__(self):
        return self.json_dumps_transaction()

    @staticmethod
    def json_loads_transaction(json_str:str):
        # TODO: Hard code checks for the data coming in
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
            print("Failed to create Transaction object from JSON. (Invalid data)")
            raise err

    def json_dumps_transaction(self):
        information = [self.type_prefix, self.sender, self.receiver, self.miner_fee, self.nonce, self.value, self.signature]
        return json.dumps(information)

class CurrencyTransaction(Transaction):
    def __init__(self, sender:str, receiver:str, miner_fee:int, nonce:int, value:int, signature:str):
        super().__init__(sender, receiver, value, miner_fee)
        self.type_prefix = "crt"

    def get_value(self):
        return self.value

class NftTransaction(Transaction):
    def __init__(self, sender:str, receiver:str, miner_fee:int, nonce:int, value:str, signature:str):
        super().__init__(sender, receiver, value, miner_fee)
        self.type_prefix = "nft"

    def verify_transaction(self):
        if not super().verify_transaction():
            return False

    def get_value(self):
        return self.value

class DataTransaction(Transaction):
    def __init__(self, sender:str, receiver:str, miner_fee:int, nonce:int, value:str, signature:str):
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

    def __init__(self, previous_block_hash:str, height:int, nonce:int, miner:str, transactions:list, block_hash:str):
        self.previous_block_hash = previous_block_hash
        self.height = height
        self.nonce = nonce
        self.miner = miner
        self.transacions = transactions
        self.block_hash = block_hash

    def add_transaction(self, transaction:Transaction):
        self.nonce = 0
        self.transactions.append(transaction)

    def remove_transaction(self, transaction:Transaction):
        self.nonce = 0
        self.transactions.remove(transaction)


    def __repr__(self):
        return self.dumps_block()

    def json_dumps_block(self):
        information = [self.previous_block_hash, self.height, self.nonce, self.miner, self.transacions, self.block_hash]
        return json.dumps(information)

    @staticmethod
    def json_loads_block(self, json_str):
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
            print("Failed to create Transaction object from JSON. (Invalid data)")
            raise err

    def sign(self):
        # TODO Make a sign function using hashes
        self.signature = SHA256.new(self.json_dumps_block()).hexdigest()
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
        if antecedent_block.signature != self.previous_block_hash:
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