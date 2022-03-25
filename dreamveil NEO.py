from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import secrets
from decimal import *
import json

import data_structures

class Transaction:
    MAX_TRANSACTION_SIZE = 1048576 # Max transaction size (1MB)

    def __init__(self, sender:str, miner_fee:Decimal):
        self.sender = sender
        self.miner_fee = miner_fee
        self.nonce = None
        self.signature = None

    def __repr__(self):
        return self.dumps()

    def sign(self, p_key:RSA.RsaKey):
        """Signs the transaction object after generating a random Nonce for it using RSA
            :param: p_key: The private key related to the sender's wallet
            :returns: The produced digital signature"""
        # Generate and set a random Nonce
        self.nonce = hex(secrets.randbits(256))[1::]
        # Generate the transaction hash (Including the nonce)
        # TODO: make sure the hash doesn't hash the signature itself ("Bruh")
        transaction_hash = SHA256.new(self.get_contents().encode()).hexdigest()
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
            computed_hash = SHA256.new(self.dumps().encode()).hexdigest()
            proposed_hash = hex((self.signature ** rsa_public_key.d) % rsa_public_key.n)[1::]
            if secrets.compare_digest(computed_hash, proposed_hash):
                return True
        except Exception as err:
            print(f"Verify signature raised exception {err}: {err.args}")
        return False

    @staticmethod
    def loads(json_str:str):
        try:
            assert len(json_str) < Transaction.MAX_TRANSACTION_SIZE
            information = json.loads(json_str)
            assert type(information) == list
            assert len(information) > 1
            type_prefix = information[0]
            information = information[1::]

            if type_prefix == "crt":
                transaction_object = CurrencyTransaction(*information)
            elif type_prefix == "gnd":
                transaction_object = DataTransaction(*information)
            else:
                raise Exception("Unknown transaction type")
            assert transaction_object.verify_signature()
            return transaction_object
        except (Exception) as err:
            # TODO: Debug this
            print("Failed loading transaction from json.")

class CurrencyTransaction(Transaction):
    def __init__(self, sender:str, miner_fee:Decimal, inputs:dict, outputs:dict, nonce:str = "", signature:str = ""):
        assert len(inputs) > 0 and len(outputs) > 0
        super().__init__(sender, miner_fee)
        self.inputs = inputs
        self.outputs = outputs
        assert self.validate_io()

    def validate_io(self):
        """Checks that IO is both in correct format and maintain currency equality"""
        inputs_sum = 0
        for input_key in self.inputs.keys():
            input_value = self.inputs[input_key]
            if type(input_key) != str or type(input_value) != Decimal:
                return False
            if len(input_key) != 64:
                if not (len(self.inputs) == 1 and self.inputs.keys()[0] == "BLOCK"):
                    return False
            if not self.zero_knowledge_range_test(input_value):
                return False
            inputs_sum += input_value

        outputs_sum = 0
        for output_key in self.outputs.keys():
            output_value = self.outputs[output_key]
            if type(output_key) != str or type(output_value) != Decimal:
                return False
            if len(output_key) != 64:
                return False
            if not self.zero_knowledge_range_test(output_value):
                return False
            outputs_sum += output_value

        # Confirm equality.
        return inputs_sum == outputs_sum

    def zero_knowledge_range_test(self, value):
        # TODO: implement a zero-knowledge proof
        return value > 0

    def dumps(self):
        information = ["crt", self.sender, self.miner_fee, self.inputs, self.outputs, self.nonce, self.signature]
        return json.dump(information)

    def get_contents(self):
        information = ["crt", self.sender, self.miner_fee, self.inputs, self.outputs, self.nonce]
        return json.dump(information)

class DataTransaction(Transaction):
    def __init__(self, sender:str, miner_fee:Decimal, recipients:list, message:str, nonce:str = "", signature:str = ""):
        assert len(message) > 0 and len(message) <= 222
        assert len(recipients) > 0
        super().__init__(sender, miner_fee)
        self.recipients = recipients
        self.message = message

    def dumps(self):
        information = ["gnd", self.sender, self.miner_fee, self.recipients, self.message, self.nonce, self.signature]
        return json.dump(information)

    def get_contents(self):
        information = ["gnd", self.sender, self.miner_fee, self.recipients, self.message, self.nonce]
        return json.dump(information)

class Block:
    MAX_TRANSACTIONS_LENGTH = 727
    MAX_BLOCK_SIZE = 2097152 # Maximum block size in bytes (2MB)

    def __init__(self, previous_block_hash:str, height:int, transactions:list, nonce:int = 0, block_hash:str = ""):
        self.previous_block_hash = previous_block_hash
        self.height = height
        self.transacions = transactions
        self.nonce = nonce
        self.block_hash = block_hash

    def __repr__(self):
        return self.dumps()

    def add_transaction(self, transaction:Transaction):
        self.nonce = 0
        self.transactions.append(transaction)

    def remove_transaction(self, transaction:Transaction):
        self.nonce = 0
        self.transactions.remove(transaction)

    def dumps(self):
        information = [self.previous_block_hash, self.height, self.nonce, self.miner, self.transacions, self.block_hash]
        return json.dumps(information)

    @staticmethod
    def loads(json_str):
        # TODO: DEBUG THIS
        try:
            assert len(json_str.encode()) <= Block.MAX_BLOCK_SIZE
            information = json.loads(json_str)
            assert type(information) == list
            assert len(information) == 6
            assert type(information[0]) == str and len(information[0]) == 64 and int(information[0], base=16)
            # Nonce
            assert information[1] >= 0
            # Block height
            assert information[2] >= 0
            # TODO: Update once wallet format is defined
            assert information[3] # Miner wallet
            #region verify transactions
            # Read and interpret each transaction object seperately
            assert type(information[4]) == list
            transactions = []
            for transaction in information[4]:
                transaction.append(Transaction.loads(repr(transaction)))
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

    def hash_block(self):
        self.block_hash = SHA256.new(self.dumps().encode()).hexdigest()
        return self.block_hash

    def do_blocks_chain(self, antecedent_block):
        """Checks if antecedent_block << self is a valid chain"""
        if antecedent_block.signature != self.previous_block_hash:
            return False
        if antecedent_block.height != self.height+1:
            return False
        return True

    def block_has_reward(self):
        """Checks that the block has one miner reward transaction and only one."""


class Blockchain:
    TRUST_HEIGHT = 10
    # WALLET_RECORD_TEMPLATE = {"crt": [], "gnd": []}
    AVERAGE_TIME_PER_BLOCK = 300 # in seconds
    BLOCK_REWARD_SEASON = (0.5*365*24*60*60/AVERAGE_TIME_PER_BLOCK) # 52560
    BLOCK_INITIAL_REWARD = 727
    BLOCK_REWARD_SUM = BLOCK_REWARD_SEASON * BLOCK_INITIAL_REWARD * 2 # 76422240

    # Transaction record tree
    # Transaction signature: (spent, value)
    def __init__(self, chain, untrusted_timeline=None, crt_record_tree=None):
        assert len(chain) > 0
        self.chain = chain
        self.crt_record_tree = crt_record_tree if crt_record_tree is not None else data_structures.AVL()
        if untrusted_timeline is not None:
            self.untrusted_timeline = untrusted_timeline
        else:
            self.untrusted_timeline = data_structures.multifurcasting_tree()
            self.untrusted_timeline.insert(chain[-1], None)

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
            self.blockchain.append(newly_trusted_block_node.value)
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

    def _insert_block_to_multifurcasting_tree(self, block, root):
        if root is None:
            root = self.untrusted_timeline.tree

        # The block was already inserted into the timeline
        if root.value.block_hash == block.block_hash:
            return None

        if root.value.block_hash == block.previous_block_hash:
            root.children.append(block)
            return root

        for child in root.children:
            result = self._insert_block_to_multifurcasting_tree(block, child)
            if result is not None:
                break
        return result

    def add_block_to_untrusted_timeline(self, block):
        return self._insert_block_to_multifurcasting_tree(self, block, self.untrusted_timeline)

    def verify_block(self, block):
        """
        This function verifies that the sender of each transaction in the block has the resources to carry it out.
        Transactions do not recognize other transactions in the same block to prevent order frauding
        """
        untrusted_timeline_block_trace = self.untrusted_timeline.trace(block)
        if untrusted_timeline_block_trace is None:
            return False
        # TODO: DEBUG

        assert len(untrusted_timeline_block_trace) > 0
        for transaction in block.transactions:
            if type(transaction) == CurrencyTransaction:
                wallet_records = self.transaction_tree.find(transaction)
                if wallet_records is None:
                    return False
                wallet_balance = sum(wallet_records["crt"])
                # Add to trusted wallet_balance the untrusted timeline transaction changes
                # this is ment to guarantee timeline transaction consistency used for the verification off the block
                for traced_block in untrusted_timeline_block_trace[0:-1:]:
                    for traced_transaction in traced_block:
                        if type(traced_transaction) == CurrencyTransaction:
                            if traced_transaction.sender == transaction.sender:
                                wallet_balance -= traced_transaction.value
                            elif traced_transaction.reciever == transaction.sender:
                                wallet_balance += traced_transaction.value

                if wallet_balance < transaction.value:
                    return False
        return True

    def dumps(self):
        # TODO Make blockchain dumps and loads
        information = [self.chain, self.untrusted_timeline.json_dumps_tree(), self.transaction_tree.dumps_avl(), ]
        return json.dumps(information)

    @staticmethod
    def loads(json_str):
        json_obj = json.loads(json_str)
        assert type(json_obj) == list
        return Blockchain(*json_obj)

    @staticmethod
    def calculate_block_reward(height):
        """
        Calculate the reward of the block using a predefined geometric series

        We divide block reward in two every 52560 blocks (half a year if 5m per block)
        a0 = 727 * 52560 = 38211120
        sum of geometric series = 2 * a0 = 76422240
        Total currency amount 76422240
        """
        q = Decimal(0.5)
        n = height // Blockchain.BLOCK_REWARD_SEASON
        block_reward = Blockchain.BLOCK_INITIAL_REWARD * q**n
        for transaction in block_reward.transactions:
            block_reward += transaction.miner_fee
        return Decimal(block_reward)

# debugging
if __name__ == '__main__':
    t = CurrencyTransaction("me", 0, {"sex":Decimal(5),}, {"amogus":Decimal(5),})
    t.sign()

    b = Block("L", 0, {"pog": 5})