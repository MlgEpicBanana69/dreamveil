from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import json
import secrets

import data_structures

class Transaction:
    MAX_TRANSACTION_SIZE = 1048576 # Max transaction size (1MB)

    # the initializer does not check value validity
    def __init__(self, sender:str, receiver:str, miner_fee:int, nonce:str, value, signature:str):
        assert miner_fee >= 0

        self.sender = sender
        self.receiver = receiver
        self.nonce = nonce
        self.miner_fee = miner_fee
        self.value = value
        self.signature = signature

        # type_prefix
        # Transaction type must be a three letter string
        # crt - currency transaction, this type is for transactions of cryptocurrency
        # nft - non-fungible token, this type is for media proof of ownership
        # gnd - generic data, this has no special propeties aside from the fact that it is not filtered
        self.type_prefix = None

    # Create a digital signature for the transaction
    # p_key: the private key that is paired with the sender wallet
    def sign(self, p_key:RSA.RsaKey):
        """Signs the transaction object after generating a random Nonce for it using RSA"""
        # Generate and set a random Nonce
        self.nonce = hex(secrets.randbits(256))[1::]
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
        # TODO: Hard code information verification for each value
        try:
            information = json.loads(json_str)
            assert len(information.encode()) <= Transaction.MAX_TRANSACTION_SIZE
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
            # TODO: Update once wallet format is decided
            assert transaction_object.sender
            assert transaction_object.receiver is None or transaction_object.receiver
            assert transaction_object.verify_signature()

            return transaction_object
        except Exception as err:
            print("Failed to create Transaction from JSON. (Invalid data)")
            raise err

    def json_dumps_transaction(self):
        information = [self.type_prefix, self.sender, self.receiver, self.miner_fee, self.nonce, self.value, self.signature]
        return json.dumps(information)

class CurrencyTransaction(Transaction):
    def __init__(self, sender:str, receiver:str, miner_fee:int, nonce:int, value:int, signature:str):
        assert value > 0
        super().__init__(sender, receiver, miner_fee, nonce, value, signature)
        self.type_prefix = "crt"

    def get_value(self):
        return self.value

class NftTransaction(Transaction):
    def __init__(self, sender:str, receiver:str, miner_fee:int, nonce:str, value:str, signature:str):
        super().__init__(sender, receiver, miner_fee, nonce, value, signature)
        self.type_prefix = "nft"

    #def verify_transaction(self):
    #    if not super().verify_transaction():
    #        return False

    def get_value(self):
        return self.value

class DataTransaction(Transaction):
    def __init__(self, sender:str, receiver:str, miner_fee:int, nonce:int, value:str, signature:str):
        assert len(value) < 222
        super().__init__(sender, receiver, miner_fee, nonce, value, signature)

        self.type_prefix = "gnd"

    #def verify_transaction(self):
    #    if not super().verify_transaction():
    #        return False
    #    if len(self.data) == 0 or len(self.data) > 140:
    #        return False
    #    return True

    def get_value(self):
        return self.value

class Block:
    MAX_TRANSACTIONS_LENGTH = 727
    MAX_BLOCK_SIZE = 2097152 # Maximum block size in bytes (2MB)

    def __init__(self, previous_block_hash:str, nonce:int, height:int, miner:str, transactions:list, block_hash:str):
        self.previous_block_hash = previous_block_hash
        self.nonce = nonce
        self.height = height
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
        return self.json_dumps_block()

    def json_dumps_block(self):
        information = [self.previous_block_hash, self.height, self.nonce, self.miner, self.transacions, self.block_hash]
        return json.dumps(information)

    @staticmethod
    def json_loads_block(json_str):
        # TODO: DEBUG THIS
        try:
            assert len(json_str.encode()) <= Block.MAX_BLOCK_SIZE
            information = json.loads(json_str)
            assert type(information) == list
            assert len(information) == 6
            assert type(information[0]) == str and len(information[0]) == 64 and int(information[0], base=16)
            assert information[1] >= 0
            assert information[2] >= 0
            # TODO: Update once wallet format is defined
            assert information[3]
            #region verify transactions
            # Read and interpret each transaction object seperately
            assert type(information[4]) == list
            transactions = []
            for transaction in information[4]:
                transaction.append(Transaction.json_loads_transaction(repr(transaction)))
            # Checks that the transaction limit was not reached
            assert len(transactions) <= Block.MAX_TRANSACTIONS_LENGTH

            # Verifies that there are no duplicate transactions
            all_signatures = [t.signature for t in transactions]
            for signature in all_signatures:
                assert all_signatures.count(signature) == 1

            # Verifies that there is one transfer transaction per sender
            transferative_transactions = [transfer for transfer in transactions if type(transaction) != DataTransaction]
            transferative_transactions_senders = [transfer.sender for transfer in transferative_transactions]
            for sender in transferative_transactions_senders:
                assert transferative_transactions_senders.count(sender) == 1
            #endregion
            information[4] = transactions
            assert type(information[5]) == str and len(information[5]) == 64 and int(information[5], base=16)

            return Block(*information)
        except Exception as err:
            print("Failed to create Block from JSON. (Invalid data)")
            raise err

    def sign(self):
        self.signature = SHA256.new(self.json_dumps_block().encode()).hexdigest()
        return self.signature

    def do_blocks_chain(self, antecedent_block):
        """Checks if antecedent_block << self is a valid chain"""
        if antecedent_block.signature != self.previous_block_hash:
            return False
        if antecedent_block.height != self.height+1:
            return False
        return True

class Blockchain:
    TRUST_HEIGHT = 10
    WALLET_RECORD_TEMPLATE = {"crt": [], "nft": [], "gnd": []}
    AVERAGE_TIME_PER_BLOCK = 300 # in seconds
    BLOCK_REWARD_SEASON = (0.5*365*24*60*60/AVERAGE_TIME_PER_BLOCK) # 52560
    BLOCK_INITIAL_REWARD = 727
    BLOCK_REWARD_SUM = BLOCK_REWARD_SEASON * BLOCK_INITIAL_REWARD * 2 # 76422240

    def __init__(self, chain, transaction_tree=None, untrusted_timeline=None):
        self.chain = chain
        self.transaction_tree = transaction_tree if transaction_tree is not None else data_structures.AVL()
        self.untrusted_timeline = untrusted_timeline if untrusted_timeline is not None else data_structures.multifurcasting_node(self.chain[-1])

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
            transactions = self.blockchain[-1].transactions
            # Add the special miner fees transaction
            transactions.append(CurrencyTransaction(None, self.miner, None, None, self.calculate_block_reward(block), None))
            # Go over all of the block's transactions
            for i, transaction in enumerate(transactions):
                if transaction.sender:
                    # See if the sender is already recorded in the AVL tree
                    wallet_records = self.transaction_tree.find(transaction.sender)
                    # Sender is already in the AVL tree
                    if wallet_records is not None:
                        records = wallet_records.value
                    # Sender is not on the tree
                    else:
                        # Generate a new AVL tree node
                        wallet_records = data_structures.binary_tree_node(transaction.sender)
                        # Set records to the records new template
                        records = Blockchain.WALLET_RECORD_TEMPLATE
                    # New record (|value|, polarity, block index, transaction index)
                    # negativity - if a transaction is negative (1) or positive (0).
                    # Append new transaction to the sender wallet records
                    records[transaction.type_prefix].append((transaction.value, 1, block.height, i))
                    # Set tree node value to the updated records
                    wallet_records.value = records
                    # Insert the updated tree node into the transaction AVL tree
                    self.transaction_tree.insert(self.transaction_tree, wallet_records)

                if transaction.receiver:
                    # See if the sender is already recorded in the AVL tree
                    wallet_records = self.transaction_tree.find(transaction.receiver)
                    # Sender is already in the AVL tree
                    if wallet_records is not None:
                        records = wallet_records.value
                    # Sender is not on the tree
                    else:
                        # Generate a new AVL tree node
                        wallet_records = data_structures.binary_tree_node(transaction.sender)
                        # Set records to the records new template
                        records = Blockchain.WALLET_RECORD_TEMPLATE
                    # New record (|value|, polarity, block index, transaction index)
                    # negativity - if a transaction is negative (1) or positive (0).
                    # Append new transaction to the sender wallet records
                    records[transaction.type_prefix].append((transaction.value, 0, block.height, i))
                    # Set tree node value to the updated records
                    wallet_records.value = records
                    # Insert the updated tree node into the transaction AVL tree
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

    def calculate_block_reward(self, block):
        """
        Calculate the reward of the block using a predefined geometric series

        We divide block reward in two every 52560 blocks (half a year if 5m per block)
        a0 = 727 * 52560 = 38211120
        sum of geometric series = 2 * a0 = 76422240
        Total currency amount 76 422 240
        """
        q = 0.5
        n = block.height // Blockchain.BLOCK_REWARD_SEASON
        block_reward = Blockchain.BLOCK_INITIAL_REWARD * q**n
        for transaction in block_reward.transactions:
            block_reward += transaction.miner_fee
        return block_reward

    def verify_block(self, block):
        """Checks if a block is entirely authentic, including its contents (transactions) and their complete validity"""
        raise NotImplementedError()

    def json_dumps_blockchain(self):
        # TODO Make blockchain dumps and loads
        information = [self.chain, self.transaction_tree.to_list(), self.untrusted_timeline.to_list()]
        return json.dumps(information)

    def json_loads_blockchain(self):
        raise NotImplementedError()

# debugging
if __name__ == '__main__':
    # t = CurrencyTransaction("a", "b", 1, 0)
    with open("transaction_dumps_example.json", "r") as amogus:
       t = Transaction.json_loads_transaction(amogus.read())
    print(t)