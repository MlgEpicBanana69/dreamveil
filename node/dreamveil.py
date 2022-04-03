from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import secrets
import decimal
from decimal import Decimal
import json
import copy

import data_structures


class Transaction:
    MAX_TRANSACTION_SIZE = 1048576 # Max transaction size (1MB)

    def __init__(self, sender:str, miner_fee:str, inputs:dict, outputs:dict, message:str, nonce:str, signature:str):
        assert type(sender) == str and type(miner_fee) == str
        assert type(inputs) == dict and type(outputs) == dict
        assert type(message) == str
        assert type(nonce) == str and type(signature) == str

        self.sender = sender
        self.miner_fee = Decimal(miner_fee)
        self.inputs = inputs
        self.outputs = outputs
        self.message = message
        self.nonce = nonce
        self.signature = signature
        assert self.verify_io()

    def __repr__(self):
        return self.dumps()

    def sign(self, p_key:RSA.RsaKey):
        """Signs the transaction object after generating a random Nonce for it using RSA
            :param: p_key: The private key related to the sender's wallet
            :returns: The produced digital signature"""
        # Generate and set a random Nonce
        self.nonce = hex(secrets.randbits(256))[2::]
        # Generate the transaction hash (Including the nonce)
        # TODO: make sure the hash doesn't hash the signature itself ("Bruh")
        transaction_hash = SHA256.new(self.get_contents().encode()).hexdigest()
        # Encrypt the transaction hash using the RSA private key (Digital signature)
        digital_signature = hex((int(transaction_hash, base=16) ** p_key.e) % p_key.n)[2::]
        # Set and return the generated digital signature
        self.signature = digital_signature
        return digital_signature

    def verify_signature(self):
        """Verifies if the digital signature of the transaction is the same as its true computed digital signature"""
        # TODO DEBUG THIS
        try:
            rsa_public_key = RSA.import_key(self.sender)
            computed_hash = SHA256.new(self.dumps().encode()).hexdigest()
            proposed_hash = hex((self.signature ** rsa_public_key.d) % rsa_public_key.n)[2::]
            if secrets.compare_digest(computed_hash, proposed_hash):
                return True
        except Exception as err:
            print(f"Verify signature raised exception {err}: {err.args}")
        return False

    def verify_io(self):
        """Checks that IO is both in correct format and maintain currency equality"""

        if len(self.inputs) == 0 or len(self.outputs) == 0:
            return False

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
        return value >= 0

    @staticmethod
    def loads(json_str:str):
        try:
            assert len(json_str) < Transaction.MAX_TRANSACTION_SIZE
            information = json.loads(json_str)
            assert type(information) == list
            assert len(information) == 7

            assert type(information[0]) == str and len(information[0]) == 64 and int(information[0], base=16)
            assert type(information[1]) == str and Decimal(information[1]) >= 0
            assert type(information[2]) == dict
            assert type(information[3]) == dict
            assert type(information[4]) == str and len(information[4]) <= 222
            assert type(information[5]) == str and len(information[5]) == 64
            assert type(information[6]) == str and len(information[0]) == 64 and int(information[0], base=16)

            transaction_object = Transaction(*information)
            assert transaction_object.verify_io()
            assert transaction_object.verify_signature()
            return transaction_object
        except (Exception) as err:
            # TODO: Debug this
            print("Transaction rejected!")

    def dumps(self):
        information = [self.sender, str(self.miner_fee), self.inputs, self.outputs, self.message, self.nonce, self.signature]
        return repr(information)

    def get_contents(self):
        information = [self.sender, str(self.miner_fee), self.inputs, self.outputs, self.message, self.nonce]
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

            # Verifies that there are no duplicate input-sender pairs
            decayed_outputs = []
            for transaction in transactions:
                for transaction_input in transaction.inputs.keys():
                    decayed_output = (transaction_input, transaction.sender)
                    assert decayed_output not in decayed_outputs
                    decayed_outputs.append(decayed_output)

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
            if list(transaction.inputs.keys())[0] == "BLOCK":
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
    def __init__(self, chain=[], untrusted_timeline=None, unspent_transactions_tree=None):
        self.chain = chain
        self.unspent_transactions_tree = unspent_transactions_tree if unspent_transactions_tree is not None else data_structures.AVL()
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


        if len(self.chain) > 0:
            if not self.add_block_to_untrusted_timeline(self.untrusted_timeline, block):
                # Block is unrelated to the main chain
                # TODO: Check/show that block(x+1) cannot practically arrive before block(x)
                return False

        if self.untrusted_timeline.calculate_height() == Blockchain.TRUST_HEIGHT+1 or len(self.chain) == 0:
            if not self.verify_block(block):
                return False

            # Untrusted block has a TRUST_HEIGHT timeline
            # Block is chained into the blockchain since it can now be trusted
            newly_trusted_block_node = self.untrusted_timeline.get_highest_child()
            self.chain.append(newly_trusted_block_node.value)
            # Remove the now trusted block from the timeline and advance on its timeline
            self.untrusted_timeline = newly_trusted_block_node

            # For each now accepted transaction in the newly trusted block
            for transaction in self.chain[-1].transaction:
                # Mark the transaction as unspent
                data_structures.binary_tree_node(transaction.signature, dict(zip(transaction.outputs.keys(), len(transaction.outputs)*[True])))

                # For each input the new transaction referenced
                for heavenly_principle_struck_transaction in transaction.inputs: # All is lost to time (and use) (?)
                    # Find the node that stores the status of the input-referenced transaction
                    intree_node = self.unspent_transactions_tree.find(self.unspent_transactions_tree.tree, heavenly_principle_struck_transaction)
                    try:
                        # TODO: DEBUG
                        # An extra precaution check
                        # This flag should will and must be True and pass.
                        assert intree_node[transaction.sender]
                    except AssertionError:
                        # This error should never trigger as the object checks for the validity of a transaction beforehand.
                        # (should've not passed Blockchain.verify_block())
                        print("Error catching double-spending attempt!!!")
                        raise
                    intree_node[transaction.sender] = False # We set the transaction's output to spent (Transaction output was used)

        # Block was accepted but is not trusted yet (Added to the untrusted timeline)!
        return None

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

        block_fees = Decimal(0)
        miner_reward_transaction = None
        # For each transaction in the block
        for transaction in block.transactions:
            # Go over all of the inputs referenced in the block.
            for transaction_input in transaction.inputs.keys():
                if transaction_input != "BLOCK":
                    transaction_node = self.untrusted_timeline.find(self.untrusted_timeline.tree, transaction_input)
                    if transaction_input is None:
                        print("Block rejected in verify_block (referenced transaction does not exist)")
                        return False
                    if transaction.sender not in transaction_node.value.keys():
                        print("Block rejected in verify_block (referenced transaction exists but the output does not)")
                        return False
                    if transaction_node.value[transaction.sender] != True:
                        print("Block rejected in verify_block (given output was already spent.)")
                        return False
                else:
                    miner_reward_transaction = transaction
            block_fees += Decimal(transaction.miner_fee)

        proposed_block_reward = Decimal(0)
        for output in miner_reward_transaction.outputs.values():
            proposed_block_reward += Decimal(output)
        if proposed_block_reward != Blockchain.calculate_block_reward(block.height) + block_fees:
            print("Block rejected in verify_block (Miner transaction does not evaluate to the correct amount)")
            return False
        return True

    def dumps(self):
        # TODO Make blockchain dumps and loads
        information = [self.chain, self.untrusted_timeline.dumps(), self.unspent_transactions_tree.dumps()]
        return repr(information)

    @staticmethod
    def loads(json_str):
        try:
            json_obj = json.loads(json_str)
            assert type(json_obj) == list
            return Blockchain(*json_obj)
        except Exception as err:
            raise ValueError(f"type(err)" + "err.args")

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

GENESIS_BLOCK = Block("a76b338874117acd5c4151e0f532cb7bd4d84764d818a52d61acdb44aa7a4a16", 0, [Transaction("", 0, {"BLOCK": Blockchain.BLOCK_INITIAL_REWARD}, {"", Blockchain.BLOCK_INITIAL_REWARD}, "", "")], 0, "a76b338874117acd5c4151e0f532cb7bd4d84764d818a52d61acdb44aa7a4a16")

# debugging
if __name__ == '__main__':
    pass