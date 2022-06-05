from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import secrets
import decimal
import json

import data_structures

def to_decimal(number):
    """
    Converts a string represting a number to Decimal.
    This function does not allow otherwise legal special Decimals such as NaN and infinities.
    It also does not allow the use of filler in the number string.
    In case of failure, raises decimal.InvalidOperation error
    :returns: decimal.Decimal number
    """
    if type(number) == str:
        for c in number:
            if not c.isdigit() and c != ".":
                break
    output = decimal.Decimal(number)
    if output.is_finite():
        return output
    raise decimal.InvalidOperation(f"Invalid number given. (char: {c})")

def address_to_key(address:str):
    """
    Converts an address str to RSA key
    :returns: RSA key object
    """
    return RSA.import_key(base64.b64decode(address.encode()))

def key_to_address(rsa_key:RSA.RsaKey):
    """
    Converts an rsa key to address
    :returns: str address
    """
    return base64.b64encode(rsa_key.public_key().export_key()).decode()

class Transaction:
    MAX_TRANSACTION_SIZE = 1048576 # Max transaction size (1MB)

    def __init__(self, sender:str, inputs:dict, outputs:dict, message:str, nonce:str, signature:str):
        assert type(sender) == str
        assert type(inputs) == dict and type(outputs) == dict
        assert type(message) == str
        assert type(nonce) == str and type(signature) == str

        self.sender = sender
        self.inputs = inputs
        self.outputs = outputs
        self.message = message
        self.nonce = nonce
        self.signature = signature

    def __repr__(self):
        return self.dumps()

    def sign(self, private_key:RSA.RsaKey):
        """Signs the transaction object after generating a random Nonce
           :param private_key: The private key related to the sender's wallet
           :returns: self"""
        # Generate and set a random Nonce
        self.nonce = secrets.token_hex(32)
        # Generate the transaction hash (Including the nonce)
        transaction_hash = SHA256.new(self.get_contents().encode())
        # Sign the transaction hash using the RSA private key
        digital_signature = pkcs1_15.new(private_key).sign(transaction_hash).hex()
        # Set and return the generated digital signature
        self.signature = digital_signature
        return self

    def verify_signature(self):
        """Verifies if the digital signature of the transaction is the same as its true computed digital signature"""
        try:
            rsa_public_key = address_to_key(self.sender)
            computed_hash = SHA256.new(self.get_contents().encode())
            pkcs1_15.new(rsa_public_key).verify(computed_hash, bytes.fromhex(self.signature))
            return True
        except ValueError:
            return False

    def verify_io(self):
        """Checks that IO is both in correct format and maintain currency equality"""
        try:
            if len(self.inputs) == 0 and len(self.inputs) == 0:
                return False

            if (len(self.inputs) != 0 and len(self.outputs) == 0) or (len(self.inputs) == 0 and len(self.outputs) != 0):
                return False

            if len(self.inputs) == 1 and len(self.outputs) == 1:
                if self.sender in self.inputs and self.sender in self.outputs:
                    return False

            has_miner_fee = False

            inputs_sum = 0
            for input_key, input_value in self.inputs.items():
                if type(input_key) != str or type(input_value) != str:
                    return False
                input_value = to_decimal(input_value)
                if len(input_key) != 512:
                    if not (len(self.inputs) == 1 and list(self.inputs.keys())[0] == "BLOCK"):
                        return False
                if input_value < 0:
                    return False
                inputs_sum += input_value

            outputs_sum = 0
            for output_key, output_value in self.outputs.items():
                if type(output_key) != str or type(output_value) != str:
                    return False
                output_value = to_decimal(output_value)
                if len(output_key) != 600:
                    if has_miner_fee or output_key != "MINER":
                        return False
                    else:
                        has_miner_fee = True
                if input_value < 0:
                    return False
                outputs_sum += output_value

            # Confirm equality.
            return inputs_sum == outputs_sum
        except (AssertionError, decimal.InvalidOperation):
            return False

    @staticmethod
    def loads(json_str:str):
        try:
            assert len(json_str) < Transaction.MAX_TRANSACTION_SIZE
            information = json.loads(json_str)
            assert type(information) == list
            assert len(information) == 6

            assert type(information[0]) == str and type(address_to_key(information[0])) == RSA.RsaKey
            assert type(information[1]) == dict
            assert type(information[2]) == dict
            assert type(information[3]) == str and len(information[3]) <= 222
            assert type(information[4]) == str and len(information[4]) == 64
            assert type(information[5]) == str and len(information[5]) == 512

            transaction_object = Transaction(*information)
            assert transaction_object.verify_io()
            assert transaction_object.verify_signature()
            return transaction_object
        except Exception as err:
            # print(f"Transaction rejected due to {type(err)}: {err.args}")
            return None

    def dumps(self):
        information = [self.sender, self.inputs, self.outputs, self.message, self.nonce, self.signature]
        if len(self.outputs) == 0:
            print("OSUHOW??")
        output = json.dumps(information)
        if type(Transaction.loads(output)) != type(self):
            print("WARNING dumped transaction is invalid!")
        return output

    def get_contents(self):
        information = [self.sender, self.inputs, self.outputs, self.message, self.nonce]
        return json.dumps(information)

    @staticmethod
    def calculate_efficiency(transaction):
        return transaction.get_miner_fee() / to_decimal(len(transaction.dumps()))

    def get_miner_fee(self):
        """
        Gets the miner fee value.
        :returns: decimal.Decimal miner_fee. If not found, defaults to 0.
        """
        for output_key, output_value in self.outputs.items():
            if output_key == "MINER":
                return to_decimal(output_value)
        return to_decimal(0)

class Block:
    MAX_SIZE = 2097152 # Maximum block size in bytes (2MB)

    def __init__(self, previous_block_hash:str, transactions:list, nonce:str, block_hash:str):
        assert type(previous_block_hash) == str and type(transactions) == list and type(nonce) == str and type(block_hash) == str

        self.previous_block_hash = previous_block_hash
        self.transactions = transactions
        self.nonce = nonce
        self.block_hash = block_hash

    def __repr__(self):
        return self.dumps()

    def hash_block(self):
        """
        Calculates and sets the hash of the block
        :returns: str block_hash
        """
        self.block_hash = SHA256.new(self.get_contents().encode()).hexdigest()
        return self.block_hash

    @staticmethod
    def calculate_block_hash_difficulty(block_hash:str):
        assert len(block_hash) == 64
        binary_block_hash = bin(int(block_hash, base=16))[2::].zfill(256)
        difficulty = 1
        for b in binary_block_hash:
            if b == '0':
                difficulty *= 2
            else:
                break
        return difficulty

    @staticmethod
    def loads(json_str):
        try:
            assert len(json_str.encode()) <= Block.MAX_SIZE
            information = json.loads(json_str)
            assert type(information) == list
            assert len(information) == 4

            assert (type(information[0]) == str and len(information[0]) == 64 and int(information[0], base=16)) or information[0] == ''
            #region information[1]
            # Read and interpret each transaction object seperately
            assert type(information[1]) == list and len(information[1]) > 0
            transactions = []
            for transaction in information[1]:
                transactions.append(Transaction.loads(transaction))
            assert Block.verify_transactions(transactions)
            information[1] = transactions
            #endregion
            assert type(information[2]) == str and len(information[2]) == 64
            assert type(information[3]) == str and len(information[3]) == 64 and int(information[3], base=16)

            output = Block(*information)
            assert output.verify_hash()
            assert output.verify_block_has_reward()
            return output
        except Exception as err:
            print("Block rejected!")

    def dumps(self):
        transactions_json_object = [tx.dumps() for tx in self.transactions]
        information = [self.previous_block_hash, transactions_json_object, self.nonce, self.block_hash]
        output = json.dumps(information)
        if type(Block.loads(output)) != type(self):
            print("WARNING dumped block is invalid!")
        return output

    def get_contents(self):
        transactions_json_object = [tx.dumps() for tx in self.transactions]
        information = [self.previous_block_hash, transactions_json_object, self.nonce]
        return json.dumps(information)

    @staticmethod
    def verify_transactions(block_transactions:list):
        try:
            for transaction in block_transactions:
                if type(transaction) == None:
                    return False
            if len(block_transactions) == 0:
                return False
            # Verifies that there are no duplicate transactions
            all_signatures = [t.signature for t in block_transactions]
            for signature in all_signatures:
                assert all_signatures.count(signature) == 1
            # Verifies that there are no duplicate input-sender pairs
            decayed_outputs = []
            for transaction in block_transactions:
                for transaction_input in transaction.inputs.keys():
                    decayed_output = (transaction_input, transaction.sender)
                    assert decayed_output not in decayed_outputs
                    decayed_outputs.append(decayed_output)
            return True
        except AssertionError:
            return False

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

    def get_header(self):
        """Returns a short str containing the descriptive variables of the block seperated by space. Used for identification."""
        return json.dumps([self.previous_block_hash, self.block_hash])

    def mine(self):
        """
        Guesses a block solution
        :returns: str Block hash
        """
        self.nonce = secrets.token_hex(32)
        return self.hash_block()

class Blockchain:
    AVERAGE_TIME_PER_BLOCK = 300 # in seconds
    BLOCK_REWARD_SEASON = (0.5*365*24*60*60/AVERAGE_TIME_PER_BLOCK) # 52560
    BLOCK_INITIAL_REWARD = 727
    BLOCK_REWARD_SUM = BLOCK_REWARD_SEASON * BLOCK_INITIAL_REWARD * 2 # 76422240

    GENESIS_MESSAGE = r"""Dreamveil - The coolest blockchain, 12th grade cyber project."""

    # unspent_transactions_tree
    # Transaction signature: (spent, value)
    def __init__(self, chain:list=None, mass:int=0, unspent_transactions_tree:data_structures.AVL=None, tracked:dict=None):
        if chain is None:
            chain = []
        if tracked is None:
            tracked = dict()
        self.tracked = tracked
        self.chain = chain
        self.mass = mass
        self.unspent_transactions_tree = unspent_transactions_tree if unspent_transactions_tree is not None else data_structures.AVL()

    def chain_block(self, block:Block):
        """Chains a block to the blockchain. This function succeeds only if a block is valid.
        :returns: Did block chain (boolean)"""

        if len(self.chain) > 0:
            # Block does not continue our chain
            if block.previous_block_hash != self.chain[-1].block_hash:
                return False
        else:
            if block.previous_block_hash != "":
                return False

        if not self.verify_block(block, len(self.chain)):
            return False

        # Add the newly accepted block into the blockchain
        new_block_index = len(self.chain)
        self.chain.append(block)

        # Update the mass of the chain
        self.mass += Block.calculate_block_hash_difficulty(block.block_hash)

        # For each now accepted transaction in the newly chained block
        for transaction in self.chain[-1].transactions:
            # Mark the new transaction as unspent
            self.unspent_transactions_tree.insert(data_structures.binary_tree_node(transaction.signature, transaction.outputs))

            # For each input the new transaction referenced
            for heavenly_principle_struck_transaction in transaction.inputs: # All is lost to time (and use) (?)
                # Find the node that stores the status of the input-referenced transaction
                intree_node = self.unspent_transactions_tree.find(heavenly_principle_struck_transaction)

                if intree_node is not None:
                    # We remove the transaction's output as it was spent
                    del intree_node.value[transaction.sender]

            # Track the transaction for each of the tracked addresss
            for tracked_address in self.tracked.keys():
                if tracked_address in transaction.inputs or tracked_address in transaction.outputs:
                    self.tracked[tracked_address].append((new_block_index, transaction.signature))
        return True

    def verify_block(self, block:Block, block_height:int):
        """
        This function verifies that the sender of each transaction in the block has the resources to carry it out.
        Transactions do not recognize other transactions in the same block to prevent order frauding
        """

        assert block_height >= 0
        block_fees = to_decimal(0)
        miner_reward_transaction = None
        # For each transaction in the block
        for transaction in block.transactions:
            # Go over all of the inputs referenced in the block.
            for input_source, input_amount in transaction.inputs.items():
                if input_source != "BLOCK":
                    transaction_node = self.unspent_transactions_tree.find(input_source)
                    if transaction_node is None:
                        print("Block rejected in verify_block (referenced transaction does not exist)")
                        return False
                    if transaction.sender not in transaction_node.value.keys():
                        print("Block rejected in verify_block (output was already spent or is invalid)")
                        return False
                    if transaction_node.value[transaction.sender] != input_amount:
                        print("Block rejected in verify_block (output amount is not the same as specified in the transaction)")
                        return False
                else:
                    miner_reward_transaction = transaction
            block_fees += transaction.get_miner_fee()

        proposed_block_reward = to_decimal(0)
        for output in miner_reward_transaction.outputs.values():
            proposed_block_reward += to_decimal(output)
        if proposed_block_reward != Blockchain.calculate_block_reward(block_height) + block_fees:
            print("Block rejected in verify_block (Miner transaction does not evaluate to the correct amount)")
            return False
        return True

    def dumps(self):
        information = [[block.dumps() for block in self.chain], self.mass, self.unspent_transactions_tree.dumps(), self.tracked]
        return json.dumps(information)

    @staticmethod
    def loads(json_str):
        try:
            json_obj = json.loads(json_str)
            if json_obj != []:
                assert type(json_obj) == list
                assert len(json_obj) == 4
                assert type(json_obj[0]) == list
                for i in range(len(json_obj[0])):
                    json_obj[0][i] = Block.loads(json_obj[0][i])
                assert type(json_obj[1]) == int
                json_obj[2] = data_structures.AVL.loads(json_obj[2])
                assert type(json_obj[3]) == dict
                assert False not in [type(val) == list for val in json_obj[3].values()]

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

        :param Height: Height of the block
        :returns: decimal.Decimal block_reward
        """
        q = 0.5
        n = height // Blockchain.BLOCK_REWARD_SEASON
        block_reward = Blockchain.BLOCK_INITIAL_REWARD * q**n
        return to_decimal(block_reward)

    def calculate_transaction_value(self, transaction, address):
        """
        Returns the amount of funds a transaction has for a given wallet address.
        :returns: None if the transaction does not exist or is spent;
                  decimal.Decimal Transaction value.
        """
        transaction_node = self.unspent_transactions_tree.find(transaction.signature)
        if transaction_node is not None:
            if address in transaction_node.value:
                return transaction_node.value[address]
        return None