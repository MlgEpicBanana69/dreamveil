from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import secrets
import decimal
from decimal import Decimal
import json

import data_structures

class Transaction:
    MAX_TRANSACTION_SIZE = 1048576 # Max transaction size (1MB)

    def __init__(self, sender:str, miner_fee:str, nonce:str, signature:str):
        assert type(sender) == str and type(miner_fee) == str and type(nonce) == str and type(signature) == str

        self.sender = sender
        self.miner_fee = Decimal(miner_fee)
        self.nonce = nonce
        self.signature = signature

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
            print("Transaction rejected!")

class CurrencyTransaction(Transaction):
    def __init__(self, sender:str, miner_fee:str, inputs:dict, outputs:dict, nonce:str = "", signature:str = ""):
        assert type(inputs) == dict and type(outputs) == dict
        assert len(inputs) > 0 and len(outputs) > 0
        super().__init__(sender, miner_fee, nonce, signature)
        self.inputs = inputs
        self.outputs = outputs
        assert self.validate_io()

    def validate_io(self):
        """Checks that IO is both in correct format and maintain currency equality"""
        inputs_sum = 0
        for input_key in self.inputs.keys():
            try:
                input_value = Decimal(self.inputs[input_key])
            except decimal.InvalidOperation:
                return False
            if type(input_key) != str:
                return False
            if len(input_key) != 64:
                if not (len(self.inputs) == 1 and list(self.inputs.keys())[0] == "BLOCK"):
                    return False
            if not self.zero_knowledge_range_test(input_value):
                return False
            inputs_sum += input_value

        outputs_sum = self.miner_fee
        for output_key in self.outputs.keys():
            try:
                output_value = Decimal(self.outputs[output_key])
            except decimal.InvalidOperation:
                return False
            if type(output_key) != str:
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
        information = ["crt", self.sender, str(self.miner_fee), self.inputs, self.outputs, self.nonce, self.signature]
        return repr(information)

    def get_contents(self):
        information = ["crt", self.sender, str(self.miner_fee), self.inputs, self.outputs, self.nonce]
        return repr(information)

class DataTransaction(Transaction):
    def __init__(self, sender:str, miner_fee:str, recipients:list, message:str, nonce:str = "", signature:str = ""):
        assert type(recipients) == list and type(message) == str
        assert len(message) > 0 and len(message) <= 222
        assert len(recipients) > 0
        super().__init__(sender, miner_fee, nonce, signature)
        self.recipients = recipients
        self.message = message

    def dumps(self):
        information = ["gnd", self.sender, str(self.miner_fee), self.recipients, self.message, self.nonce, self.signature]
        return repr(information)

    def get_contents(self):
        information = ["gnd", self.sender, str(self.miner_fee), self.recipients, self.message, self.nonce]
        return repr(information)

class Block:
    MAX_BLOCK_SIZE = 2097152 # Maximum block size in bytes (2MB)

    def __init__(self, previous_block_hash:str, height:int, transactions:list, nonce:int = 0, block_hash:str = ""):
        assert type(previous_block_hash) == str and type(height) == int and type(transactions) == list and type(nonce) == int and type(block_hash) == str

        self.previous_block_hash = previous_block_hash
        self.height = height
        self.transactions = transactions
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

    def get_contents(self):
        information = [self.previous_block_hash, self.height, self.transactions, self.nonce]
        return repr(information)

    def hash_block(self):
        self.block_hash = SHA256.new(self.get_contents().encode()).hexdigest()
        return self.block_hash

    @staticmethod
    def loads(json_str):
        # TODO: DEBUG THIS
        try:
            assert len(json_str.encode()) <= Block.MAX_BLOCK_SIZE
            information = json.loads(json_str)
            assert type(information) == list
            assert len(information) == 5
            assert type(information[0]) == str and len(information[0]) == 64 and int(information[0], base=16)
            # Block height
            assert information[1] >= 0

            #      information[2]
            # region verify transactions
            # Read and interpret each transaction object seperately
            assert len(information[2]) > 0 and type(information[2]) == list
            transactions = []
            # TODO: Debug this bs
            for transaction in information[2]:
                transactions.append(Transaction.loads(transaction))

            # Verifies that there are no duplicate transactions
            all_signatures = [t.signature for t in transactions]
            for signature in all_signatures:
                assert all_signatures.count(signature) == 1

            # Verifies that there are no duplicate inputs
            crts = [crt for crt in transactions if type(crt) == CurrencyTransaction]
            all_crt_inputs = [crt.inputs.keys() for crt in crts]
            # TODO debug this shit
            all_crt_input_keys = [input_key for crt_input in all_crt_inputs for input_key in crt_input]
            for input_key in all_crt_input_keys:
                assert all_crt_input_keys.count(input_key) == 1
            information[2] = transactions
            #endregion

            # Nonce
            assert information[3] >= 0

            assert type(information[4]) == str and len(information[4]) == 64 and int(information[4], base=16)
            output = Block(*information)
            assert output.verify_hash()
            assert output.verify_block_has_reward()

            return output
        except Exception as err:
            print("Block rejected!")
            raise err

    def dumps(self):
        information = [self.previous_block_hash, self.height, self.transactions, self.nonce, self.block_hash]
        return repr(information)

    def do_blocks_chain(self, antecedent_block):
        """Checks if antecedent_block << self is a valid chain"""
        if antecedent_block.signature != self.previous_block_hash:
            return False
        if antecedent_block.height != self.height+1:
            return False
        return True

    def verify_block_has_reward(self):
        """Checks that the block has one miner reward transaction and only one.

        Note this does not check whether the block prize value is valid relative to the Blockchain
        as this responsibility falls upon the Blockchain class"""
        reward_transaction_count = 0
        for transaction in self.transactions:
            if type(transaction) == CurrencyTransaction:
                if transaction.inputs[0] == "BLOCK":
                    reward_transaction_count += 1
        return reward_transaction_count == 1

    def verify_hash(self):
        """Verifies that the hash propety matches the actual hash of the block's"""
        proposed_hash = self.block_hash
        computed_hash = self.hash_block()
        output = secrets.compare_digest(proposed_hash, computed_hash)
        self.block_hash = proposed_hash
        return output

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
        return repr(information)

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
    pass