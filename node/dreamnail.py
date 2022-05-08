from itertools import chain
import dreamveil
import dreamshield

import configparser
import ipaddress
import os
import secrets
import json
import random
import math
import atexit
import time
import getpass
from Crypto.PublicKey import RSA

import socket
import threading

# TODO TASKS (AMOGUS):
# Implement transaction pool storing (DONE)
# in setup implement peer and transaction syncing. (DONE)

# Implement a block creator/editor/miner (NIP)
# Create a user file system for saving RSA keys (WIP)
# implement whitedoable env loading that's organized (WIP)
# implement online communication-wide encryption (integrity and confidentiallity) (NIP)
# implement a changing PoW difficulty (NIP)
# Implement the gui (NIP)

# Behavior of miner:
#   Will use the most rewarding transactions to form a block.
#   Will actively attempt to solve the block by finding the nonce solution
# Behavior of non-miner:
#   Does not try to form a block using transactions
#   Does not attempt to solve any blocks

APPLICATION_PATH = os.path.dirname(os.path.abspath(__file__)) + "\\"

class Server:
    singleton = None
    PEER_STATUS_CONVERSED = "CONVERSED"
    PEER_STATUS_OFFLINE = "OFFLINE"
    PEER_STATUS_UNKNOWN = "UNKNOWN"
    TRUST_HEIGHT = 6

    def __init__(self, version:str, host_keys:RSA.RsaKey, blockchain:dreamveil.Blockchain, peer_pool:dict, transaction_pool:list, address:str, is_miner:bool, miner_msg:str="", port:int=22222, max_peer_amount:int=150):
        if Server.singleton is not None:
            raise Exception("Singleton class limited to one instance")
        Server.singleton = self

        self.difficulty_target = int(2**11) # 16 zeros TEMPORARLY USING A STATIC DIFFICULTY TARGET!!!
        self.host_keys = host_keys
        self.version = version
        self.address = address
        self.port = port
        self.max_peer_amount = max_peer_amount
        self.socket = None
        self.blockchain = blockchain
        self.peers = {}
        self.peer_pool = peer_pool
        self.transaction_pool = transaction_pool
        self.is_miner = is_miner
        self.peer_lock = threading.Lock()
        if len(self.blockchain.chain) == 0:
            self.miner_msg = dreamveil.Blockchain.GENESIS_MESSAGE
        else:
            self.miner_msg = miner_msg

        self.closed = False
        self.miner_thread = threading.Thread(target=self.miner)
        self.seeker_thread = threading.Thread(target=self.seeker)
        self.accepter_thread = threading.Thread(target=self.accepter)
        self.run_thread = threading.Thread(target=self.run)

        self.run_thread.start()

    def roll_peer(self):
        peer_options = []
        offline_peer_options = []
        for peer, status in self.peer_pool.items():
            if status != Server.PEER_STATUS_OFFLINE and peer not in self.peers.keys():
                peer_options.append(peer)
            elif status == Server.PEER_STATUS_OFFLINE and peer not in self.peers.keys():
                offline_peer_options.append(peer)
        if len(peer_options) > 0:
            output = random.choice(peer_options)
            print(f"### Rolled {output} from peer options")
        elif len(offline_peer_options) > 0:
            output = random.choice(offline_peer_options)
        else:
            output = None
        return output

    def run(self):
        print("Starting server and assigning seeker and accepter threads")
        print("-----------------------------------------------------------")
        self.accepter_thread.start()
        self.seeker_thread.start()

        print("Server is now running...")
        if self.is_miner:
            self.miner_thread.start()
        while True:
           print(f"### {len(self.peers)}/{self.max_peer_amount} connected. Current peer pool size: {len(self.peer_pool)}")
           time.sleep(60)

    def seeker(self):
        time.sleep(5)
        print(f"Server is now seeking new connections")

        while not self.closed:
            # Once connection amount is too low, seek connections if possible.
            while len(self.peers) < math.floor(self.max_peer_amount*(2/3)) and not self.closed:
                self.peer_lock.acquire()
                new_peer = self.roll_peer()
                if new_peer is not None:
                    connection_result = self.connect(new_peer)
                    if connection_result is None:
                        # TODO: Define peer status system
                        if peer_pool[new_peer] != Server.PEER_STATUS_OFFLINE:
                            peer_pool[new_peer] = Server.PEER_STATUS_OFFLINE
                            print(f"### Marked {new_peer} as OFFLINE")
                    else:
                        peer_pool[new_peer] = Server.PEER_STATUS_CONVERSED
                self.peer_lock.release()

    def accepter(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.address, self.port))
        self.socket.listen(self.max_peer_amount)
        print(f"Server is now accepting incoming connections and is binded to {(self.address, self.port)}")

        while not self.closed:
            # Do not accept new connections once peer count exceeds maximum allowed
            while len(self.peers) < self.max_peer_amount and not self.closed:
                peer_socket, peer_address = self.socket.accept()
                self.peer_lock.acquire()
                Connection(peer_socket, peer_address[0])
                print(f"### {peer_address[0]} connected to node")
                self.peer_lock.release()

    def connect(self, address):
        if len(self.peers) <= self.max_peer_amount and address not in self.peers.keys():
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                peer_socket.connect((address, self.port))
            except (TimeoutError, OSError):
                print(f"!!! Failed to connect to {address} due ")
                return None
            new_peer = Connection(peer_socket, address)
            print(f"### Server connected to {address}")
            return new_peer
        else:
            print(f"!!! Failed to connect to {address}")
            if len(self.peers) <= self.max_peer_amount:
                print(f"### Server rules do not allow making more than {self.max_peer_amount} connections.")
            else:
                print(f"### Cannot form two connections to the same address {self.address}")
            return None

    def close(self):
        """Terminated the server and all of its ongoing connections"""
        print("### SHUTTING DOWN SERVER")
        for peer in self.peers:
            peer.close()

        self.closed = True

    def add_to_transaction_pool(self, transaction:dreamveil.Transaction):
        self.transaction_pool.append(transaction)
        self.transaction_pool.sort(key=transaction.calculate_efficiency)

    def find_in_transaction_pool(self, signature:str):
        for tr in self.transaction_pool:
            if tr.signature == signature:
                return tr
        raise ValueError(f"{signature} is not in list")

    def miner(self):
        # TODO: Properly and fully implement
        transaction_pool_len = None
        my_chain_len = None
        my_address = dreamveil.key_to_address(self.host_keys.public_key())
        while not self.closed:
            # Refresh the currently mined block when a new transaction is added to the pool
            # Also refresh the block once our top block changes (We chained a block.)
            if len(self.transaction_pool) != transaction_pool_len or len(self.blockchain.chain) != my_chain_len:
                transaction_pool_len = len(self.transaction_pool)
                my_chain_len = len(self.blockchain.chain)
                top_bk_hash = self.blockchain.chain[-1].block_hash if len(self.blockchain.chain) > 0 else ""
                mined_block = dreamveil.Block(top_bk_hash, [], 0, "")
                block_reward = dreamveil.to_decimal(self.blockchain.calculate_block_reward(len(self.blockchain.chain)))
                for pool_transaction in self.transaction_pool:
                    try:
                        block_reward += pool_transaction.get_miner_fee()
                        mined_block.add_transaction(pool_transaction)
                        if not dreamveil.Block.verify_transactions(mined_block.transactions) or self.blockchain.verify_block(mined_block, len(self.blockchain.chain)):
                            mined_block.remove_transaction(pool_transaction)
                    except ValueError:
                        break
                miner_reward_transaction = dreamveil.Transaction(my_address, {"BLOCK": block_reward}, {my_address: block_reward}, self.miner_msg, "", "").sign(self.host_keys)
                mined_block.add_transaction(miner_reward_transaction)

            if dreamveil.Block.calculate_block_hash_difficulty(mined_block.block_hash) >= self.difficulty_target:
                if self.blockchain.chain_block(mined_block):
                    print(f"### SUCCESFULY MINED AND CHAINED BLOCK {mined_block.block_hash}")
                    if len(self.blockchain.chain) == 1:
                        self.miner_msg = ""
                    for transaction in mined_block.transactions:
                        if "BLOCK" not in transaction.inputs:
                            if transaction in self.transaction_pool:
                                self.transaction_pool.remove(transaction)
                    for peer_connection in self.peers.values():
                        action_thread = threading.Thread(target=peer_connection.SENDBK, args=(mined_block,))
                        action_thread.start()
                else:
                    print(f"!!! FAILED TO CHAIN MINED BLOCK WITH THAT PASSED POW ({mined_block.block_hash}, {mined_block.nonce})\n   SAVING BLOCK TO POWfailed")
                    with open(APPLICATION_PATH + f"POWfailed\\{mined_block.block_hash}.json.old", "w+", encoding="utf-8") as backup_file:
                        backup_file.write(mined_block.dumps())
                    mined_block.mine()
            else:
                mined_block.mine()

class Connection:
    COMMAND_SIZE = 6
    HEADER_LEN = len(str(dreamveil.Block.MAX_SIZE))
    MAX_MESSAGE_SIZE = HEADER_LEN + dreamveil.Block.MAX_SIZE
    connection_lock = threading.Lock()

    def __init__(self, socket, address):
        Connection.connection_lock.acquire()
        self.lock = threading.Lock()
        self.socket = socket
        self.address = address
        self.closed = False
        self.peer_chain_mass = None
        self.commanding = False

        if address not in Server.singleton.peers:
            Server.singleton.peers[self.address] = self
        else:
            Connection.connection_lock.release()
            self.close(remove_peer=False)
            return
        Connection.connection_lock.release()

        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def setup(self):
        try:
            # Check that node versions match
            self.send(Server.singleton.version)
            peer_version = self.recv()
            assert peer_version == Server.singleton.version

            # Exchange chain masses
            self.send(f"{Server.singleton.blockchain.mass}")
            peer_chain_mass = self.recv()
            peer_chain_mass = int(peer_chain_mass)
            assert peer_chain_mass >= 0
            self.peer_chain_mass = peer_chain_mass

            # Send and recieve 100 random peers to further establish the connection of nodes into the network
            peers_to_share = random.sample(list(Server.singleton.peer_pool.keys()), min(100, len(Server.singleton.peer_pool)))
            self.send(json.dumps(peers_to_share))
            newly_given_peers = self.recv()
            newly_given_peers = json.loads(newly_given_peers)
            assert len(newly_given_peers) <= 100 and type(newly_given_peers) == list
            for peer in newly_given_peers:
                assert ipaddress.ip_address(peer)
                if peer not in Server.singleton.peer_pool and peer != Server.singleton.address:
                    Server.singleton.peer_pool[peer] = Server.PEER_STATUS_UNKNOWN

            print(f"### Connection with {self.address} completed setup (version: {peer_version})")
        except (AssertionError, TimeoutError, ValueError) as err:
            print(f"!!! Failed to initialize connection in setup with {self.address} (ver: {peer_version}) due to {err}")
            # Terminate the connection
            self.close()

    def run(self):
        self.lock.acquire()
        self.setup()
        self.lock.release()
        while not self.closed:
            try:
                print(f"### Listening to {self.address}...")
                command_message = self.recv()
                if self.execute_command(command_message):
                    print(f"### Succesfuly executed {command_message} with {self.address}")
            except Exception as err:
                print(f"!!! Connection at {self.address} failed and forced to close due to {err}.")
                self.close()

    def execute_command(self, command:str):
        commands = ("SENDTX", "SENDBK", "CHNSYN")
        if len(command) < Connection.COMMAND_SIZE or command not in commands:
                return False
        self.lock.acquire()
        try:
            self.send(f"ACK {command}")
            # I GOT ...
            match command:
                case "SENDTX":
                    tx_signature = self.recv().split(' ')
                    try:
                        assert Server.singleton.blockchain.unspent_transactions_tree.find(tx_signature)
                        Server.find_in_transaction_pool(tx_signature)
                        self.send("False")
                    except (ValueError, AssertionError):
                        self.send("True")
                        new_tx = dreamveil.Transaction.loads(self.recv())
                        if new_tx.signature == tx_signature and "BLOCK" not in new_tx.inputs:
                            Server.singleton.add_to_transaction_pool(new_tx)
                            for peer_addr, peer_connection in Server.singleton.peers.items():
                                if peer_addr != self.address:
                                    action_thread = threading.Thread(target=peer_connection.SENDTX, args=(new_tx,))
                                    action_thread.start()
                        else:
                            self.close()
                case "SENDBK":
                    bk_prev_hash, bk_hash = json.loads(self.recv())
                    my_top_hash = Server.singleton.blockchain.chain[-1].block_hash if len(Server.singleton.blockchain.chain) > 0 else ''
                    self.peer_chain_mass += dreamveil.Block.calculate_block_hash_difficulty(bk_hash)
                    if my_top_hash == bk_prev_hash and dreamveil.Block.calculate_block_hash_difficulty(bk_hash) >= Server.singleton.difficulty_target:
                        self.send("True")
                        new_bk = dreamveil.Block.loads(self.recv())
                        if new_bk.block_hash == bk_hash:
                            if Server.singleton.blockchain.chain_block(new_bk):
                                for transaction in new_bk.transactions:
                                    if "BLOCK" not in transaction.inputs:
                                        if transaction in Server.singleton.transaction_pool:
                                            Server.singleton.transaction_pool.remove(transaction)
                                for peer_addr, peer_connection in Server.singleton.peers.items():
                                    if peer_addr != self.address:
                                        action_thread = threading.Thread(target=peer_connection.SENDBK, args=(new_bk,))
                                        action_thread.start()
                        else:
                            raise AssertionError("Value not as client specified")
                    else:
                        self.send("False")
                        #region Check to see if peer's chain is significantly larger than the current one used
                        if self.peer_chain_mass >= Server.singleton.blockchain.mass + Server.TRUST_HEIGHT * Server.singleton.difficulty_target:
                            print(f"### Noticed that {self.address} uses a significantly larger chain (dM-chain = {self.peer_chain_mass - Server.singleton.blockchain.mass} Starting to sync with it")
                            chnsyn_thread = threading.Thread(target=self.CHNSYN)
                            chnsyn_thread.start()
                case "CHNSYN":
                    peer_chain_mass, peer_chain_len = self.recv().split(' ')
                    peer_chain_mass = int(peer_chain_mass)
                    peer_chain_len = int(peer_chain_len)
                    assert peer_chain_mass >= 0 and peer_chain_len >= 0
                    self.peer_chain_mass = peer_chain_mass

                    my_chain_mass = Server.singleton.blockchain.mass
                    self.send(f"{my_chain_mass}")

                    if self.recv() == "True":
                        hash_batches_sent = 0
                        while True:
                            hash_batch = [block.block_hash for block in Server.singleton.blockchain.chain[:peer_chain_len:][::-1][100*hash_batches_sent:100*(hash_batches_sent+1)]]
                            if len(hash_batch) > 0:
                                self.send(" ".join(hash_batch))
                                split_index = self.recv()
                                if split_index != "continue":
                                    break
                            else:
                                raise AssertionError(f"!!! hash_batch came out empty while helping {self.address} to sync!")
                        split_index = int(split_index)
                        assert split_index >= 0 and split_index < len(Server.singleton.blockchain.chain)
                        blocks_sent = 0
                        for block in Server.singleton.blockchain.chain[split_index::]:
                            self.send(block.dumps())
                            blocks_sent+=1
                            self.recv()
                        print(f"Succesfully helped {self.address} sync up! Sent {blocks_sent} blocks.")
            return True
        except (AssertionError, ValueError) as command_err:
            log_str  = f"!!! Failure while executing {command} from {self.address}\n"
            log_str += f"Error that was caught: {command_err}"
            print(log_str)
            return False
        finally:
            self.lock.release()

    def send(self, message:str):
        assert len(message) <= Connection.MAX_MESSAGE_SIZE

        print(f"### Sending message to ({self.address}): {message}")
        if not self.closed:
            message = str(len(message)).zfill(Connection.HEADER_LEN) + message
            self.socket.send(message.encode())

    def recv(self):
        try:
            message = self.socket.recv(Connection.MAX_MESSAGE_SIZE).decode()
            try:
                assert len(message) > Connection.HEADER_LEN
                message_len = message[:Connection.HEADER_LEN]
                assert len(message_len) == Connection.HEADER_LEN
                message_len = int(message_len)
                assert message_len > 0
                message_contents = message[Connection.HEADER_LEN:Connection.HEADER_LEN + message_len]
                assert len(message_contents) == message_len
            except (ValueError, AssertionError):
                print(f"Recieved invalid message from ({self.address})")
                self.close()
                return
            print(f"### Recieved message from ({self.address}): {message_contents}")
            return message_contents
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            if not self.closed:
                self.close()

    def connection_command(command_func):
        def wrapper(self, *args, **kwargs):
            try:
                self.lock.acquire()
                self.send(command_func.__name__)
                self.commanding = True
                print(f"### Locked {command_func.__name__} in {self.address}")
                output = command_func(self, *args, **kwargs)
                self.commanding = False
                self.lock.release()
                return output
            except Exception as err:
                print(f"!!! Connection with {self.address} forcibly closed due to failure {err}")
                self.close()
        return wrapper

    #region connection commands
    @connection_command
    def SENDTX(self, transaction:dreamveil.Transaction):
        self.send(transaction.signature)
        ans = self.recv()
        if ans == "True":
            self.send(transaction.dumps())

    @connection_command
    def SENDBK(self, block:dreamveil.Block):
        self.send(block.get_header())
        ans = self.recv()
        if ans == "True":
            self.send(block.dumps())

    @connection_command
    def CHNSYN(self):
        # Locate the split where the current blockchain is different from the proposed blockchain by the peer.
        my_chain_mass = Server.singleton.blockchain.mass
        my_chain_len = len(Server.singleton.blockchain.chain)
        self.send(f"{my_chain_mass}")

        peer_chain_mass = self.recv()
        peer_chain_mass = int(peer_chain_mass)
        assert peer_chain_mass > 0
        self.peer_chain_mass = peer_chain_mass

        if peer_chain_mass < my_chain_mass + Server.singleton.difficulty_target * Server.TRUST_HEIGHT:
            self.send("False")
            return
        self.send("True")
        hashes = []
        inventory = []
        split_index = 0
        while True:
            hashes = self.recv().split(' ')
            #TODO: DEBUG splicing
            for i in range(my_chain_len - len(inventory) - len(hashes), my_chain_len - len(inventory))[::-1]:
                if Server.singleton.blockchain.chain[i].block_hash == hashes[i]:
                    split_index = i+1
                    hashes = []
                    break
                else:
                    inventory += hashes[i]
            if len(hashes) == 100:
                self.send("continue")
            else:
                break
        form_new_chain = len(inventory) > 0
        # Create the new blockchain object and fill in the known blocks
        inventory = inventory[::-1]
        if form_new_chain:
            new_blockchain = dreamveil.Blockchain()
            for i in range(split_index):
                new_blockchain.chain_block(Server.singleton.blockchain.chain[i])
        else:
            new_blockchain = Server.singleton.blockchain
        self.send(str(split_index))

        # Download all the blocks mentioned in the inventory list from the peer
        while new_blockchain.mass < peer_chain_mass:
            new_bk = dreamveil.Block.loads(self.recv())
            chain_result = new_blockchain.chain_block(new_bk)

            if chain_result:
                for transaction in new_bk.transactions:
                    if "BLOCK" not in transaction.inputs:
                        if transaction in Server.singleton.transaction_pool:
                            Server.singleton.transaction_pool.remove(transaction)
            else:
                print(f"!!! Block recieved in CHNSYN from ({self.address}) failed to chain. Using new blockchain: {form_new_chain}.")
                if form_new_chain and not new_blockchain is Server.singleton.blockchain:
                    del new_blockchain
                self.close()
                return
            self.send("continue")

            # If the given blockchain is indeed larger than the current blockchain used
            if new_blockchain.mass == peer_chain_mass and form_new_chain:
                # We swap the blockchain objects to the new larger one.
                Server.singleton.blockchain = new_blockchain
            else:
                print(f"!!! Given blockchain mass is not the same as specified by ({self.address}). specified: {peer_chain_mass.mass} given: {new_blockchain.mass}")
                if form_new_chain and not new_blockchain is Server.singleton.blockchain:
                    del new_blockchain
                self.close()
        print(f"### With ({self.address}) finished syncing new chain with mass {Server.singleton.blockchain.chain.mass} and length {len(Server.singleton.blockchain.chain)} (old: {my_chain_mass})")
    #endregion

    def close(self, remove_peer=True):
        self.closed = True

        print(f"### Terminated connection with {self.address}")

        if self.address in Server.singleton.peers and remove_peer:
            del Server.singleton.peers[self.address]

        self.socket.close()
        del self

def exit_handler():
    user_file.close()

def load_bench():
    if not os.path.isdir(APPLICATION_PATH + "bench"):
        os.mkdir(APPLICATION_PATH + "bench")
    if not os.path.isdir(APPLICATION_PATH + "bench\\backup"):
        os.mkdir(APPLICATION_PATH + "bench\\backup")

    read_param = "r+" if os.path.isfile(APPLICATION_PATH + "bench\\blockchain.json") else "w+"
    with open(APPLICATION_PATH + "bench\\blockchain.json", read_param) as f:
        try:
            contents = f.read()
            if contents == "":
                contents = "[]"
                f.write(contents)
            blockchain = dreamveil.Blockchain.loads(contents)
        except (ValueError, AssertionError) as err:
            print("!!! Could not loads blockchain from bench")
            print(err)

            f.close()
            if os.path.isfile(APPLICATION_PATH + "bench\\blockchain.json"):
                os.rename(APPLICATION_PATH + "bench\\blockchain.json", APPLICATION_PATH + f"bench\\backup\\blockchain-{secrets.token_hex(8)}.json.old")

    read_param = "r+" if os.path.isfile(APPLICATION_PATH + "bench\\peer_pool.json") else "w+"
    with open(APPLICATION_PATH + "bench\\peer_pool.json", read_param) as f:
        try:
            contents = f.read()
            if contents == "":
                contents = "{}"
                f.write(contents)
            peer_pool = json.loads(contents)
            assert type(peer_pool) == dict
        except (ValueError, AssertionError) as err:
            print("!!! Could not loads peer pool from bench")
            print(err)
            f.close()
            if os.path.isfile("bench\\peer_pool.json"):
                os.rename("bench\\peer_pool.json", f"bench\\backup\\peer_pool-{secrets.token_hex(8)}.json.old")

    return blockchain, peer_pool

application_config = configparser.ConfigParser()
application_config.read(APPLICATION_PATH + "node.cfg")
VERSION = application_config["METADATA"]["version"]

print("Loading bench from saved files...")
blockchain, peer_pool = load_bench()
print("Finished loading bench")

username = ""
while username == "" or not os.path.isfile(APPLICATION_PATH + f"users\\{username}"):
    username = input("Username: ")

while True:
    password = getpass.getpass(prompt="Password: ")
    with open(APPLICATION_PATH + f"users\\{username}", "rb") as user_file:
        atexit.register(exit_handler)
        try:
            # Encrypts
            #user_file_contents = RSA.generate(2048)
            #user_file_contents = user_file_contents.export_key('PEM')
            #user_file_contents = json.dumps([user_file_contents.decode()])
            #user_file_contents = dreamshield.encrypt(password, user_file_contents)
            #user_file.write(user_file_contents)
            user_file_contents = user_file.read()
            host_keys = [RSA.import_key(key) for key in json.loads(dreamshield.decrypt(password, user_file_contents).decode())]
            break
        except (ValueError, json.JSONDecodeError):
            print("Invalid password!")

server = Server(VERSION, host_keys[0], blockchain, peer_pool, [], application_config["SERVER"]["address"], True, port=int(application_config["SERVER"]["port"]))

# Main thread loop
while True:
    pass