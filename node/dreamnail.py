import dreamveil
import dreamshield
import dreambench

import configparser
import ipaddress
import os
import sys
import secrets
import json
import random
import math
import timeit
import atexit
import time

from Crypto.PublicKey import RSA
from PyQt6 import QtWidgets, QtCore
from PyQt6.QtWidgets import QApplication, QMainWindow

import socket
import threading

# TODO TASKS (AMOGUS):
# Implement transaction pool storing (DONE)
# in setup implement peer and transaction syncing. (DONE)
# Create a user file system for saving RSA keys (DONE)
# Implement a block creator/editor/miner (DONE)
# Fix threading and rework CHNSYN (DONE)

# implement whitedoable env loading that's organized (WIP)
# Implement the gui (WIP)
# implement online communication-wide encryption (integrity and confidentiallity) (NIP)
# implement a changing PoW difficulty (NIP)

# Behavior of miner:
#   Will use the most rewarding transactions to form a block.
#   Will actively attempt to solve the block by finding the nonce solution
# Behavior of non-miner:
#   Does not try to form a block using transactions
#   Does not attempt to solve any blocks

APPLICATION_PATH = os.path.dirname(os.path.abspath(__file__))

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

        self.difficulty_target = int(2**16) # 16 zeros TEMPORARLY USING A STATIC DIFFICULTY TARGET!!!
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
        self.chain_lock = threading.Lock()
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
           print(f"### {len(self.peers)}/{self.max_peer_amount} connected. Current peer pool size: {len(self.peer_pool)} Current blockchain length and mass {len(self.blockchain.chain)} {self.blockchain.mass}")
           time.sleep(60)

    def seeker(self):
        time.sleep(5)
        print(f"Server is now seeking new connections")

        while not self.closed:
            # Once connection amount is too low, seek connections if possible.
            while len(self.peers) < math.floor(self.max_peer_amount*(2/3)) and not self.closed:
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

    def accepter(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.address, self.port))
        self.socket.listen(self.max_peer_amount)
        print(f"Server is now accepting incoming connections and is binded to {(self.address, self.port)}")

        while not self.closed:
            # Do not accept new connections once peer count exceeds maximum allowed
            while len(self.peers) < self.max_peer_amount and not self.closed:
                peer_socket, peer_address = self.socket.accept()
                Connection(peer_socket, peer_address[0])
                print(f"### {peer_address[0]} connected to node")

    def connect(self, address):
        if len(self.peers) <= self.max_peer_amount and address not in self.peers.keys():
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                peer_socket.connect((address, self.port))
            except (TimeoutError, OSError) as err:
                #print(f"!!! Failed to connect to {address} due to {type(err)}: {err.args[1]}")
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
                mined_block = dreamveil.Block(top_bk_hash, [], "", "")
                block_reward = self.blockchain.calculate_block_reward(len(self.blockchain.chain))
                for pool_transaction in self.transaction_pool:
                    try:
                        block_reward += pool_transaction.get_miner_fee()
                        mined_block.add_transaction(pool_transaction)
                        if not dreamveil.Block.verify_transactions(mined_block.transactions) or self.blockchain.verify_block(mined_block, len(self.blockchain.chain)):
                            mined_block.remove_transaction(pool_transaction)
                    except ValueError:
                        break
                miner_reward_transaction = dreamveil.Transaction(my_address, {"BLOCK": str(block_reward)}, {my_address: str(block_reward)}, self.miner_msg, "", "").sign(self.host_keys)
                mined_block.add_transaction(miner_reward_transaction)

            if dreamveil.Block.calculate_block_hash_difficulty(mined_block.block_hash) >= self.difficulty_target:
                if self.try_chain_block(mined_block):
                    print(f"### MINED BLOCK {mined_block.block_hash}")
                else:
                    print(f"!!! FAILED TO CHAIN MINED BLOCK WITH THAT PASSED POW ({mined_block.block_hash}, {mined_block.nonce})\n   SAVING BLOCK TO POWfailed")
                    with open(APPLICATION_PATH + f"\\POWfailed\\{mined_block.block_hash}.json.old", "w+", encoding="utf-8") as backup_file:
                        backup_file.write(mined_block.dumps())
                    mined_block.mine()
            else:
                mined_block.mine()

    def try_chain_block(self, block, exclusions:list=None):
        """Attempts to chain a given block to the current blockchain.
        On success sends the block to all connected peers.
        Will not share with peer addresses given in :exclusions:"""
        if exclusions is None:
            exclusions = []
        self.chain_lock.acquire()
        try:
            if self.blockchain.chain_block(block):
                print(f"### SUCCESFULY CHAINED BLOCK {block.block_hash}")
                if len(self.blockchain.chain) == 1:
                    self.miner_msg = ""
                for transaction in block.transactions:
                    if "BLOCK" not in transaction.inputs:
                        if transaction in self.transaction_pool:
                            self.transaction_pool.remove(transaction)
                current_peer_addresses = list(self.peers.keys())
                for peer_addr in current_peer_addresses:
                    if peer_addr not in exclusions:
                        action_thread = threading.Thread(target=self.peers[peer_addr].SENDBK, args=(block,))
                        action_thread.start()
                return True
            else:
                return False
        except KeyError:
            return False
        finally:
            self.chain_lock.release()

class Connection:
    COMMAND_SIZE = 6
    HEADER_LEN = len(str(dreamveil.Block.MAX_SIZE))
    MAX_MESSAGE_SIZE = HEADER_LEN + dreamveil.Block.MAX_SIZE
    connection_lock = threading.Lock()

    def __init__(self, socket, address):
        Connection.connection_lock.acquire()
        try:
            self.lock = threading.Lock()
            self.last_message = None
            self.socket = socket
            self.address = address
            self.closed = False
            self.peer_chain_mass = None
            self.completed_setup = False
            self.first_to_move = Server.singleton.address > address

            if address not in Server.singleton.peers:
                Server.singleton.peers[self.address] = self
            else:
                self.close(remove_peer=False)
                return
        finally:
            Connection.connection_lock.release()
        self.run_thread = threading.Thread(target=self.run)
        self.run_thread.start()
        self.setup()

    def setup(self):
        self.lock.acquire()
        try:
            # Check that node versions match
            peer_version = None
            if self.first_to_move:
                self.send(Server.singleton.version)
                peer_version = self.read_last_message(60.0)
            else:
                peer_version = self.read_last_message()
                self.send(Server.singleton.version)
            assert peer_version == Server.singleton.version

            # Exchange chain masses
            if self.first_to_move:
                self.send(f"{Server.singleton.blockchain.mass}")
                peer_chain_mass = self.read_last_message()
            else:
                peer_chain_mass = self.read_last_message()
                self.send(f"{Server.singleton.blockchain.mass}")
            peer_chain_mass = int(peer_chain_mass)
            assert peer_chain_mass >= 0
            self.peer_chain_mass = peer_chain_mass

            # Send and recieve 100 random peers to further establish the connection of nodes into the network
            peers_to_share = random.sample(list(Server.singleton.peer_pool.keys()), min(100, len(Server.singleton.peer_pool)))
            if self.first_to_move:
                self.send(json.dumps(peers_to_share))
                newly_given_peers = self.read_last_message()
            else:
                newly_given_peers = self.read_last_message()
                self.send(json.dumps(peers_to_share))
            newly_given_peers = json.loads(newly_given_peers)
            assert len(newly_given_peers) <= 100 and type(newly_given_peers) == list
            for peer in newly_given_peers:
                assert ipaddress.ip_address(peer)
                if peer not in Server.singleton.peer_pool and peer != Server.singleton.address:
                    Server.singleton.peer_pool[peer] = Server.PEER_STATUS_UNKNOWN

            print(f"### Connection with {self.address} completed setup (version: {peer_version})")
            self.completed_setup = True
        except (AssertionError, TimeoutError, ValueError) as err:
            print(f"!!! Failed to initialize connection in setup with {self.address} (ver: {peer_version}) due to {type(err)}: {err.args}")
            # Terminate the connection
            self.close()
        finally:
            self.lock.release()
            if self.peer_chain_mass > Server.singleton.blockchain.mass + Server.singleton.difficulty_target * Server.TRUST_HEIGHT:
                print(f"### Noticed that we use a significantly larger chain than {self.address} (dM-chain = {Server.singleton.blockchain.mass - self.peer_chain_mass} Starting to sync with it")
                chnsyn_thread = threading.Thread(target=self.CHNSYN)
                chnsyn_thread.start()

    def run(self):
        while not self.closed:
            try:
                command_message = self.recv()
                if command_message == "TERMINATE":
                    self.close()
                    break
                self.last_message = command_message
                if self.completed_setup:
                    cmd_thread = threading.Thread(target=self.execute_command, args=(command_message,))
                    cmd_thread.start()
            except Exception as err:
                print(f"!!! Connection at {self.address} failed and forced to close due to {err}.")
                self.close()

    def read_last_message(self, timeout=15.0):
        start = timeit.default_timer()
        while self.last_message is None:
            if self.closed:
                return
            if timeit.default_timer() - start >= timeout:
                raise TimeoutError("Did not recieve answer from peer")
        output = self.last_message
        self.last_message = None
        return output

    def send(self, message:str):
        try:
            assert len(message) <= Connection.MAX_MESSAGE_SIZE

            print(f"### Sending message to ({self.address}): {message}")
            if not self.closed:
                message = str(len(message)).zfill(Connection.HEADER_LEN) + message
                self.socket.send(message.encode())
        except Exception as err:
            print(f"Failed to send message to {self.address} due to error: {type(err)}: {err.args}")
            self.close()
            return

    def recv(self):
        try:
            message = self.socket.recv(Connection.MAX_MESSAGE_SIZE).decode()
            try:
                assert len(message) >= Connection.HEADER_LEN
                message_len = message[:Connection.HEADER_LEN]
                assert len(message_len) == Connection.HEADER_LEN
                message_len = int(message_len)
                assert message_len >= 0
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
            self.lock.acquire()
            try:
                print(f"### Locked {command_func.__name__} in {self.address}")
                self.send(command_func.__name__)
                output = command_func(self, *args, **kwargs)
                return output
            except Exception as err:
                print(f"!!! Failed commanding {self.address} due to error {err}. {command_func}")
            finally:
                time.sleep(0.05)
                print(f"{command_func} finished {self.address}")
                self.lock.release()
        return wrapper

    #region connection commands
    @connection_command
    def SENDTX(self, transaction:dreamveil.Transaction):
        assert self.read_last_message() == "ACK"
        self.send(transaction.signature)
        ans = self.read_last_message()
        if ans == "True":
            self.send(transaction.dumps())

    @connection_command
    def SENDBK(self, block:dreamveil.Block):
        assert self.read_last_message() == "ACK"
        self.send(block.get_header())
        ans = self.read_last_message()
        if ans == "True":
            self.send(block.dumps())

    @connection_command
    def CHNSYN(self):
        """Syncs ourselves with the peer's larger chain"""
        peer_chain_mass = self.read_last_message()
        peer_chain_mass = int(peer_chain_mass)
        assert peer_chain_mass > 0
        self.peer_chain_mass = peer_chain_mass
        my_chain_mass = Server.singleton.blockchain.mass
        my_chain_len = len(Server.singleton.blockchain.chain)

        if peer_chain_mass > my_chain_mass + Server.singleton.difficulty_target * Server.TRUST_HEIGHT:
            # Locate the split where the current blockchain is different from the proposed blockchain by the peer.
            self.send(f"{my_chain_mass} {my_chain_len}")
            assert self.read_last_message() == "ACK"
            hash_batches_sent = 0
            split_index = "continue"
            while split_index == "continue":
                # We send a block hash batch to the peer (max length 100)
                # The peer will match the hashes against his own chain to find where they split
                # Repeats this proccess until the split is found.
                # split_index: index on the chain where the blocks are different but on split_index-1 are the same for both chains.
                hash_batch = [block.block_hash for block in Server.singleton.blockchain.chain[::-1][100*hash_batches_sent:100*(hash_batches_sent+1)]]
                hash_batch = hash_batch[::-1]
                self.send(" ".join(hash_batch))
                split_index = self.read_last_message()
            split_index = int(split_index)
            assert split_index >= 0 and split_index <= my_chain_len
            form_new_chain = split_index < my_chain_len and my_chain_len != 0

            # Create the new blockchain object and fill in the known blocks
            if form_new_chain:
                new_blockchain = dreamveil.Blockchain()
                for i in range(split_index):
                    new_blockchain.chain_block(Server.singleton.blockchain.chain[i])
            else:
                new_blockchain = Server.singleton.blockchain

            self.send("start")
            # Download all the blocks mentioned in the inventory list from the peer
            try:
                while new_blockchain.mass != peer_chain_mass:
                    new_bk = dreamveil.Block.loads(self.read_last_message())
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

                # We swap the blockchain objects to the new larger one.
                Server.singleton.blockchain = new_blockchain
                print(f"### With ({self.address}) finished syncing new chain with mass {Server.singleton.blockchain.mass} and length {len(Server.singleton.blockchain.chain)} (old: {my_chain_mass})")
            except Exception as err:
                print(f"!!! Error {err} while getting blocks from peer in CHNSYN ({self.address}). specified: {peer_chain_mass.mass} given: {new_blockchain.mass}")
                if form_new_chain and not new_blockchain is Server.singleton.blockchain:
                    del new_blockchain
                return False
        else:
            # We are not interested in the chain of the peer.
            self.send("False")
    #endregion

    def execute_command(self, command:str):
        commands = ("SENDTX", "SENDBK", "CHNSYN")
        if command is None:
            return False
        if len(command) < Connection.COMMAND_SIZE or command not in commands:
            return False
        self.lock.acquire()
        self.last_message = None
        try:
            # I GOT ...
            match command:
                case "SENDTX":
                    self.send("ACK")
                    tx_signature = self.read_last_message().split(' ')
                    try:
                        assert Server.singleton.blockchain.unspent_transactions_tree.find(tx_signature)
                        Server.find_in_transaction_pool(tx_signature)
                        self.send("False")
                    except (ValueError, AssertionError):
                        self.send("True")
                        new_tx = dreamveil.Transaction.loads(self.read_last_message())
                        if new_tx.signature == tx_signature and "BLOCK" not in new_tx.inputs:
                            Server.singleton.add_to_transaction_pool(new_tx)
                            for peer_addr, peer_connection in Server.singleton.peers.items():
                                if peer_addr != self.address:
                                    action_thread = threading.Thread(target=peer_connection.SENDTX, args=(new_tx,))
                                    action_thread.start()
                        else:
                            self.close()
                case "SENDBK":
                    self.send("ACK")
                    bk_prev_hash, bk_hash = json.loads(self.read_last_message())
                    my_top_hash = Server.singleton.blockchain.chain[-1].block_hash if len(Server.singleton.blockchain.chain) > 0 else ''
                    self.peer_chain_mass += dreamveil.Block.calculate_block_hash_difficulty(bk_hash)
                    if my_top_hash == bk_prev_hash and dreamveil.Block.calculate_block_hash_difficulty(bk_hash) >= Server.singleton.difficulty_target:
                        self.send("True")
                        recieved_block_json = self.read_last_message()
                        new_bk = dreamveil.Block.loads(recieved_block_json)
                        if new_bk.block_hash == bk_hash:
                            Server.singleton.try_chain_block(new_bk, exclusions=self.address)
                        else:
                            raise AssertionError("Value not as client specified")
                    else:
                        self.send("False")
                case "CHNSYN":
                    """Syncs peer with our larger blockchain"""
                    my_chain_mass = Server.singleton.blockchain.mass
                    my_chain_len  = len(Server.singleton.blockchain.chain)
                    self.send(f"{my_chain_mass}")

                    resp = self.read_last_message()
                    if resp != "False":
                        peer_chain_mass, peer_chain_len = resp.split(' ')
                        peer_chain_mass = int(peer_chain_mass)
                        peer_chain_len = int(peer_chain_len)
                        assert peer_chain_mass >= 0 and peer_chain_len >= 0
                        self.peer_chain_mass = peer_chain_mass

                        self.send("ACK")

                        hashes = []
                        split_index = 0
                        batches_recieved = 0
                        while True:
                            hashes = self.read_last_message().split(' ')
                            if hashes == ['']:
                                hashes = []
                            assert len(hashes) <= 100
                            hashes = hashes[:max(0, my_chain_len - batches_recieved*100)]
                            for i in range(len(hashes))[::-1]:
                                # Have we found the split index?
                                if Server.singleton.blockchain.chain[batches_recieved*100 + i].block_hash == hashes[i]:
                                    split_index = batches_recieved*100 + i + 1
                                    hashes = []
                                    break
                            if len(hashes) == 100:
                                # There could still be more hashes to send.
                                self.send("continue")
                            else:
                                break
                            batches_recieved += 1
                        self.send(str(split_index))

                        assert self.read_last_message() == "start"
                        blocks_sent = 0
                        for block in Server.singleton.blockchain.chain[split_index::]:
                            self.send(block.dumps())
                            blocks_sent+=1
                            resp = self.read_last_message()
                            if resp != "continue":
                                print(f"Failed to CHNSYN with {self.address} while giving blocks!")
                                self.close()
                                return
                        # Update the peer chain after the sync.
                        self.peer_chain_mass = my_chain_mass
                        print(f"Succesfully helped {self.address} sync up! Sent {blocks_sent} blocks.")
                    else:
                        print(f"### Peer {self.address} refused chain sync.")
                        print(f"### Succesfuly executed {command} with {self.address}")

            print(f"### Succesfuly executed {command} with {self.address}")
            if self.peer_chain_mass > Server.singleton.blockchain.mass + Server.singleton.difficulty_target * Server.TRUST_HEIGHT:
                print(f"### Noticed that we use a significantly larger chain than {self.address} (dM-chain = {Server.singleton.blockchain.mass - self.peer_chain_mass} Starting to sync with it")
                chnsyn_thread = threading.Thread(target=self.CHNSYN)
                chnsyn_thread.start()
            return True
        except (AssertionError, ValueError, TimeoutError) as command_err:
            log_str  = f"!!! Failure while executing {command} from {self.address}\n"
            log_str += f"Error that was caught: {command_err}"
            print(log_str)
            return False
        finally:
            self.lock.release()

    def close(self, remove_peer=True):
        if self.closed:
            return
        try:
            self.closed = True
            print(f"### Terminated connection with {self.address}")
            self.send("TERMINATE")
            if self.address in Server.singleton.peers and remove_peer:
                del Server.singleton.peers[self.address]
        finally:
            self.socket.close()
            del self

def exit_handler():
    print("Exit")

# Main thread loop
if __name__ == '__main__':
    atexit.register(exit_handler)
    QtCore.QDir.addSearchPath("resources", APPLICATION_PATH + "/resources/")
    import dreamui
    application_config = configparser.ConfigParser()
    application_config.read(APPLICATION_PATH + "\\node.cfg")
    VERSION = application_config["METADATA"]["version"]

    print("Loading bench from saved files...")
    blockchain, peer_pool = dreambench.load_bench()
    print("Finished loading bench")

    app = QApplication(sys.argv)
    win = QMainWindow()
    ui = dreamui.Ui_MainWindow()
    ui.setupUi(win)
    win.show()
    #server = Server(VERSION, host_keys[0], blockchain, peer_pool, [], application_config["SERVER"]["address"], True, port=int(application_config["SERVER"]["port"]))
    sys.exit(app.exec())