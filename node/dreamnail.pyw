import dreamveil
import dreambench
import dreamui

import configparser
import ipaddress
import os
import sys
import json
import random
import math
import timeit
import socket
import time
import atexit
import pyperclip
import decimal

from Crypto.Hash import SHA256
from PyQt6 import QtWidgets, QtCore, QtGui
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

class dreamnail:
    singleton = None

    class Server:
        singleton = None
        PEER_STATUS_CONVERSED = "CONVERSED"
        PEER_STATUS_OFFLINE = "OFFLINE"
        PEER_STATUS_UNKNOWN = "UNKNOWN"
        TRUST_HEIGHT = 6

        def __init__(self, address:str, port:int=22222, max_peer_amount:int=150):
            if dreamnail.Server.singleton is not None:
                raise Exception("Singleton class limited to one instance")
            dreamnail.Server.singleton = self

            self.address = address
            self.port = port
            self.max_peer_amount = max_peer_amount
            self.user_key = dreamnail.singleton.user_data["key"]
            self.version = dreamnail.singleton.VERSION
            self.blockchain = dreamnail.singleton.blockchain
            self.peer_pool = dreamnail.singleton.peer_pool
            self.transaction_pool = dreamnail.singleton.transaction_pool

            self.difficulty_target = int(2**4) # TEMPORARLY USING A STATIC DIFFICULTY TARGET!!!
            self.peers = {}
            self.miner_open = False
            self.socket = None
            self.chain_lock = threading.Lock()

            self.closed = False
            self.miner_thread = None
            self.seeker_thread = threading.Thread(target=self.seeker)
            self.accepter_thread = threading.Thread(target=self.accepter)
            self.run_thread = threading.Thread(target=self.run)

            self.run_thread.start()

        def roll_peer(self):
            peer_options = []
            offline_peer_options = []
            for peer, status in self.peer_pool.items():
                if status != dreamnail.Server.PEER_STATUS_OFFLINE and peer not in self.peers.keys():
                    peer_options.append(peer)
                elif status == dreamnail.Server.PEER_STATUS_OFFLINE and peer not in self.peers.keys():
                    offline_peer_options.append(peer)
            if len(peer_options) > 0:
                output = random.choice(peer_options)
                dreamnail.singleton.log(f"### Rolled {output} from peer options")
            elif len(offline_peer_options) > 0:
                output = random.choice(offline_peer_options)
            else:
                output = None
            return output

        def run(self):
            dreamnail.singleton.log("Starting server and assigning seeker and accepter threads")
            dreamnail.singleton.log("-----------------------------------------------------------")
            self.accepter_thread.start()
            self.seeker_thread.start()

            dreamnail.singleton.log("Server is now running...")

        def seeker(self):
            time.sleep(5)
            dreamnail.singleton.log(f"Server is now seeking new connections")
            try:
                while not self.closed:
                    # Once connection amount is too low, seek connections if possible.
                    while len(self.peers) < math.floor(self.max_peer_amount*(2/3)) and not self.closed:
                        new_peer = self.roll_peer()
                        if new_peer is not None:
                            connection_result = self.connect(new_peer)
                            if connection_result is None:
                                # TODO: Define peer status system
                                if self.peer_pool[new_peer] != dreamnail.Server.PEER_STATUS_OFFLINE:
                                    self.peer_pool[new_peer] = dreamnail.Server.PEER_STATUS_OFFLINE
                                    dreamnail.singleton.log(f"### Marked {new_peer} as OFFLINE")
                            else:
                                self.peer_pool[new_peer] = dreamnail.Server.PEER_STATUS_CONVERSED
            finally:
                dreamnail.singleton.log("### Server connection seeker is shutdown.")

        def accepter(self):
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    self.socket.bind((self.address, self.port))
                except OSError as err:
                    dreamnail.singleton.close_server()
                    return
                self.socket.listen(self.max_peer_amount)
                dreamnail.singleton.log(f"Server is now accepting incoming connections and is binded to {(self.address, self.port)}")

                while not self.closed:
                    # Do not accept new connections once peer count exceeds maximum allowed
                    try:
                        while len(self.peers) < self.max_peer_amount and not self.closed:
                            peer_socket, peer_address = self.socket.accept()
                            dreamnail.Connection(peer_socket, peer_address[0])
                            dreamnail.singleton.log(f"### {peer_address[0]} connected to node")
                    except OSError:
                        pass
            finally:
                dreamnail.singleton.log("### Server connection accepter is shutdown.")

        def connect(self, address):
            if len(self.peers) <= self.max_peer_amount and address not in self.peers.keys():
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    peer_socket.connect((address, self.port))
                except (TimeoutError, OSError) as err:
                    #dreamnail.singleton.log(f"!!! Failed to connect to {address} due to {type(err)}: {err.args[1]}")
                    return None
                new_peer = dreamnail.Connection(peer_socket, address)
                dreamnail.singleton.log(f"### Server connected to {address}")
                return new_peer
            else:
                dreamnail.singleton.log(f"!!! Failed to connect to {address}")
                if len(self.peers) <= self.max_peer_amount:
                    dreamnail.singleton.log(f"### Server rules do not allow making more than {self.max_peer_amount} connections.")
                else:
                    dreamnail.singleton.log(f"### Cannot form two connections to the same address {self.address}")
                return None

        def close(self):
            """Terminated the server and all of its ongoing connections"""
            dreamnail.singleton.log("### SHUTTING DOWN SERVER")
            self.socket.close()
            for conn in list(self.peers.values()):
                conn.close()

            self.closed = True
            dreamnail.Server.singleton = None

        def add_to_transaction_pool(self, transaction:dreamveil.Transaction, exclusions:list=None):
            if exclusions is None:
                exclusions = []
            self.transaction_pool.append(transaction)
            self.transaction_pool.sort(key=dreamveil.Transaction.calculate_efficiency)
            self.transaction_pool.reverse()

            current_peer_addresses = list(self.peers.keys())
            for peer_addr in current_peer_addresses:
                if peer_addr not in exclusions:
                    action_thread = threading.Thread(target=self.peers[peer_addr].SENDTX, args=(dreamnail.singleton.edited_transaction,))
                    action_thread.start()

        def find_in_transaction_pool(self, signature:str):
            for tr in self.transaction_pool:
                if tr.signature == signature:
                    return tr
            return None

        def remove_from_transaction_pool(self, signature:str):
            for i, tr in enumerate(self.transaction_pool):
                if tr.signature == signature:
                    del self.transaction_pool[i]
                    return True
            return False

        def miner(self):
            dreamnail.singleton.log("Miner started")
            transaction_pool_len = None
            my_chain_len = None
            my_address = dreamveil.key_to_address(self.user_key)
            try:
                while not self.closed and self.miner_open:
                    # Refresh the currently mined block when a new transaction is added to the pool
                    # Also refresh the block once our top block changes (We chained a block.)
                    if len(self.transaction_pool) != transaction_pool_len or len(self.blockchain.chain) != my_chain_len:
                        transaction_pool_len = len(self.transaction_pool)
                        my_chain_len = len(self.blockchain.chain)
                        top_bk_hash = self.blockchain.chain[-1].block_hash if len(self.blockchain.chain) > 0 else ""
                        mined_block = dreamveil.Block(top_bk_hash, [], "", "")

                        for pool_transaction in self.transaction_pool.copy():
                            if pool_transaction.signature not in [tx.signature for tx in mined_block.transactions]:
                                mined_block.transactions.append(pool_transaction)
                                if not mined_block.verify_transactions():
                                    mined_block.transactions = mined_block.transactions[:-1]
                                elif len(mined_block.dumps()) > dreamveil.Block.MAX_SIZE:
                                    mined_block.transactions = mined_block.transactions[:-2]
                                    break

                        curr_miner_msg = dreamnail.singleton.miner_msg if len(self.blockchain.chain) > 0 else dreamveil.Blockchain.GENESIS_MESSAGE
                        block_reward = self.blockchain.calculate_block_reward(len(self.blockchain.chain))
                        for transaction in mined_block.transactions:
                            block_reward += transaction.get_miner_fee()
                        miner_reward_transaction = dreamveil.Transaction(my_address, {"BLOCK": str(block_reward)}, {my_address: str(block_reward)}, curr_miner_msg, "", "").sign(self.user_key)
                        mined_block.transactions.append(miner_reward_transaction)
                        mined_block.mine()


                    if dreamveil.Block.calculate_block_hash_difficulty(mined_block.block_hash) >= self.difficulty_target:
                        if self.try_chain_block(mined_block):
                            dreamnail.singleton.log(f"### MINED BLOCK {mined_block.block_hash}")
                        else:
                            dreamnail.singleton.log(f"!!! FAILED TO CHAIN MINED BLOCK WITH THAT PASSED POW ({mined_block.block_hash}, {mined_block.nonce})\n   SAVING BLOCK TO POWfailed")
                            with open(APPLICATION_PATH + f"\\bench\\POWfailed\\{mined_block.block_hash}.json.old", "w+", encoding="utf-8") as backup_file:
                                backup_file.write(mined_block.dumps())
                            mined_block.mine()
                    else:
                        mined_block.mine()
            finally:
                dreamnail.singleton.log("Miner is now shutdown.")

        def start_miner(self):
            if not self.miner_open:
                self.miner_thread = threading.Thread(target=self.miner)
                self.miner_thread.start()
                self.miner_open = True

        def close_miner(self):
            if self.miner_open:
                self.miner_open = False

        def try_chain_block(self, block, exclusions:list=None):
            """Attempts to chain a given block to the current blockchain.
            On success sends the block to all connected peers.
            Will not share with peer addresses given in :exclusions:"""
            if exclusions is None:
                exclusions = []
            self.chain_lock.acquire()
            try:
                if self.blockchain.chain_block(block):
                    dreamnail.singleton.log(f"### SUCCESFULY CHAINED BLOCK {block.block_hash}")
                    if dreamnail.singleton.ui.tabWidget.currentIndex() == 3:
                        dreamnail.singleton.updateBlockchainExplorerTab()

                    for transaction in block.transactions:
                        if "BLOCK" not in transaction.inputs:
                            self.remove_from_transaction_pool(transaction)

                        user_address = dreamveil.key_to_address(dreamnail.singleton.user_data["key"])
                        new_balance = decimal.Decimal(0)
                        input_transactions = {}
                        for relevant_transaction_block_index, transaction_signature in self.blockchain.tracked[user_address][::-1]:
                            for transaction in self.blockchain.chain[relevant_transaction_block_index].transactions:
                                if transaction.signature == transaction_signature:
                                    transaction_value = self.blockchain.calculate_transaction_value(transaction, user_address)
                                    if transaction_value is not None:
                                        new_balance += dreamveil.to_decimal(transaction_value)
                                        input_transactions[transaction.signature] = transaction_value
                        dreamnail.singleton.user_data["balance"] = new_balance

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
            dreamnail.Connection.connection_lock.acquire()
            try:
                self.lock = threading.Lock()
                self.lock.acquire()
                self.last_message = None
                self.socket = socket
                self.address = address
                self.closed = False
                self.peer_chain_mass = None
                self.completed_setup = False
                self.first_to_move = dreamnail.Server.singleton.address > address

                if address not in dreamnail.Server.singleton.peers:
                    dreamnail.Server.singleton.peers[self.address] = self
                    dreamnail.singleton.add_peer(address)
                else:
                    self.close(remove_peer=False)
                    return
            finally:
                dreamnail.Connection.connection_lock.release()
            self.run_thread = threading.Thread(target=self.run)
            self.run_thread.start()
            self.setup()

        def setup(self):
            try:
                # Check that node versions match
                peer_version = None
                if self.first_to_move:
                    self.send(dreamnail.Server.singleton.version)
                    peer_version = self.read_last_message()
                else:
                    peer_version = self.read_last_message()
                    self.send(dreamnail.Server.singleton.version)
                assert peer_version == dreamnail.Server.singleton.version

                # Exchange chain masses
                if self.first_to_move:
                    self.send(f"{dreamnail.Server.singleton.blockchain.mass}")
                    peer_chain_mass = self.read_last_message()
                else:
                    peer_chain_mass = self.read_last_message()
                    self.send(f"{dreamnail.Server.singleton.blockchain.mass}")
                peer_chain_mass = int(peer_chain_mass)
                assert peer_chain_mass >= 0
                self.peer_chain_mass = peer_chain_mass

                # Send and recieve 100 random peers to further establish the connection of nodes into the network
                peers_to_share = random.sample(list(dreamnail.Server.singleton.peer_pool.keys()), min(100, len(dreamnail.Server.singleton.peer_pool)))
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
                    if peer not in dreamnail.Server.singleton.peer_pool and peer != dreamnail.Server.singleton.address:
                        dreamnail.Server.singleton.peer_pool[peer] = dreamnail.Server.PEER_STATUS_UNKNOWN

                if self.peer_chain_mass > dreamnail.Server.singleton.blockchain.mass + dreamnail.Server.singleton.difficulty_target * dreamnail.Server.TRUST_HEIGHT:
                    dreamnail.singleton.log(f"### Noticed that we use a significantly larger chain than {self.address} (dM-chain = {dreamnail.Server.singleton.blockchain.mass - self.peer_chain_mass} Starting to sync with it")
                    chnsyn_thread = threading.Thread(target=self.CHNSYN)
                    chnsyn_thread.start()

                dreamnail.singleton.log(f"### Connection with {self.address} completed setup (version: {peer_version})")
                self.completed_setup = True
                self.lock.release()
            except (AssertionError, TimeoutError, ValueError) as err:
                dreamnail.singleton.log(f"!!! Failed to initialize connection in setup with {self.address} (ver: {peer_version}) due to {type(err)}: {err.args}")
                # Terminate the connection
                self.close()

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
                    dreamnail.singleton.log(f"!!! Connection at {self.address} failed and forced to close due to {err}.")
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
                assert len(message) <= dreamnail.Connection.MAX_MESSAGE_SIZE

                dreamnail.singleton.log(f"### Sending message to ({self.address}): {message}")
                if not self.closed:
                    message = str(len(message)).zfill(dreamnail.Connection.HEADER_LEN) + message
                    self.socket.send(message.encode())
            except Exception as err:
                dreamnail.singleton.log(f"Failed to send message to {self.address} due to error: {type(err)}: {err.args}")
                self.close()
                raise
                return

        def recv(self):
            try:
                message = self.socket.recv(dreamnail.Connection.MAX_MESSAGE_SIZE).decode()
                try:
                    assert len(message) >= dreamnail.Connection.HEADER_LEN
                    message_len = message[:dreamnail.Connection.HEADER_LEN]
                    assert len(message_len) == dreamnail.Connection.HEADER_LEN
                    message_len = int(message_len)
                    assert message_len >= 0
                    message_contents = message[dreamnail.Connection.HEADER_LEN:dreamnail.Connection.HEADER_LEN + message_len]
                    assert len(message_contents) == message_len
                except (ValueError, AssertionError):
                    dreamnail.singleton.log(f"Recieved invalid message from ({self.address})")
                    self.close()
                    return
                dreamnail.singleton.log(f"### Recieved message from ({self.address}): {message_contents}")
                return message_contents
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                if not self.closed:
                    self.close()

        def connection_command(command_func):
            def wrapper(self, *args, **kwargs):
                self.lock.acquire()
                try:
                    dreamnail.singleton.log(f"### Locked {command_func.__name__} in {self.address}")
                    self.send(command_func.__name__)
                    output = command_func(self, *args, **kwargs)
                    return output
                except Exception as err:
                    dreamnail.singleton.log(f"!!! Failed commanding {self.address} due to error {err}. {command_func}")
                finally:
                    time.sleep(0.05)
                    dreamnail.singleton.log(f"{command_func} finished {self.address}")
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
            my_chain_mass = dreamnail.Server.singleton.blockchain.mass
            my_chain_len = len(dreamnail.Server.singleton.blockchain.chain)

            if peer_chain_mass > my_chain_mass + dreamnail.Server.singleton.difficulty_target * dreamnail.Server.TRUST_HEIGHT:
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
                    hash_batch = [block.block_hash for block in dreamnail.Server.singleton.blockchain.chain[::-1][100*hash_batches_sent:100*(hash_batches_sent+1)]]
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
                        new_blockchain.chain_block(dreamnail.Server.singleton.blockchain.chain[i])
                else:
                    new_blockchain = dreamnail.Server.singleton.blockchain

                self.send("start")
                # Download all the blocks mentioned in the inventory list from the peer
                try:
                    while new_blockchain.mass != peer_chain_mass:
                        new_bk = dreamveil.Block.loads(self.read_last_message())
                        chain_result = new_blockchain.chain_block(new_bk)

                        if chain_result:
                            self.send("continue")
                        else:
                            dreamnail.singleton.log(f"!!! Block recieved in CHNSYN from ({self.address}) failed to chain. Using new blockchain: {form_new_chain}.")
                            if form_new_chain and not new_blockchain is dreamnail.Server.singleton.blockchain:
                                del new_blockchain
                            self.close()
                            return

                    # We swap the blockchain objects to the new larger one.
                    new_blockchain.tracked = dreamnail.Server.singleton.blockchain.tracked.copy()
                    dreamnail.singleton.blockchain = new_blockchain
                    self.blockchain = dreamnail.singleton.blockchain

                    # Remove all of the outdated pool transactions
                    for block in new_blockchain.chain:
                        for transaction in block.transactions:
                            dreamnail.Server.singleton.remove_from_transaction_pool(transaction.signature)

                    dreamnail.singleton.log(f"### With ({self.address}) finished syncing new chain with mass {dreamnail.Server.singleton.blockchain.mass} and length {len(dreamnail.Server.singleton.blockchain.chain)} (old: {my_chain_mass})")
                except Exception as err:
                    dreamnail.singleton.log(f"!!! Error {err} while getting blocks from peer in CHNSYN ({self.address}). specified: {peer_chain_mass.mass} given: {new_blockchain.mass}")
                    if form_new_chain and not new_blockchain is dreamnail.Server.singleton.blockchain:
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
            if len(command) < dreamnail.Connection.COMMAND_SIZE or command not in commands:
                return False
            self.lock.acquire()
            self.last_message = None
            try:
                # I GOT ...
                match command:
                    case "SENDTX":
                        self.send("ACK")
                        tx_signature = self.read_last_message()
                        try:
                            assert dreamnail.Server.singleton.blockchain.unspent_transactions_tree.find(tx_signature)
                            assert dreamnail.Server.find_in_transaction_pool(tx_signature)
                            self.send("False")
                        except (ValueError, AssertionError):
                            self.send("True")
                            new_tx = dreamveil.Transaction.loads(self.read_last_message())
                            if new_tx.signature == tx_signature and "BLOCK" not in new_tx.inputs:
                                dreamnail.Server.singleton.add_to_transaction_pool(new_tx, [self.address])
                            else:
                                self.close()
                    case "SENDBK":
                        self.send("ACK")
                        bk_prev_hash, bk_hash = json.loads(self.read_last_message())
                        my_top_hash = dreamnail.Server.singleton.blockchain.chain[-1].block_hash if len(dreamnail.Server.singleton.blockchain.chain) > 0 else ''
                        self.peer_chain_mass += dreamveil.Block.calculate_block_hash_difficulty(bk_hash)
                        if my_top_hash == bk_prev_hash and dreamveil.Block.calculate_block_hash_difficulty(bk_hash) >= dreamnail.Server.singleton.difficulty_target:
                            self.send("True")
                            recieved_block_json = self.read_last_message()
                            new_bk = dreamveil.Block.loads(recieved_block_json)
                            if new_bk.block_hash == bk_hash:
                                dreamnail.Server.singleton.try_chain_block(new_bk, exclusions=self.address)
                            else:
                                raise AssertionError("Value not as client specified")
                        else:
                            self.send("False")
                    case "CHNSYN":
                        """Syncs peer with our larger blockchain"""
                        my_chain_mass = dreamnail.Server.singleton.blockchain.mass
                        my_chain_len  = len(dreamnail.Server.singleton.blockchain.chain)
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
                                    if dreamnail.Server.singleton.blockchain.chain[batches_recieved*100 + i].block_hash == hashes[i]:
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
                            for block in dreamnail.Server.singleton.blockchain.chain[split_index::]:
                                self.send(block.dumps())
                                blocks_sent+=1
                                resp = self.read_last_message()
                                if resp != "continue":
                                    dreamnail.singleton.log(f"Failed to CHNSYN with {self.address} while giving blocks!")
                                    self.close()
                                    return
                            # Update the peer chain after the sync.
                            self.peer_chain_mass = my_chain_mass
                            dreamnail.singleton.log(f"Succesfully helped {self.address} sync up! Sent {blocks_sent} blocks.")
                        else:
                            dreamnail.singleton.log(f"### Peer {self.address} refused chain sync.")
                            dreamnail.singleton.log(f"### Succesfuly executed {command} with {self.address}")

                dreamnail.singleton.log(f"### Succesfuly executed {command} with {self.address}")
                if self.peer_chain_mass > dreamnail.Server.singleton.blockchain.mass + dreamnail.Server.singleton.difficulty_target * dreamnail.Server.TRUST_HEIGHT:
                    dreamnail.singleton.log(f"### Noticed that we use a significantly larger chain than {self.address} (dM-chain = {dreamnail.Server.singleton.blockchain.mass - self.peer_chain_mass} Starting to sync with it")
                    chnsyn_thread = threading.Thread(target=self.CHNSYN)
                    chnsyn_thread.start()
                return True
            except (AssertionError, ValueError, TimeoutError) as command_err:
                log_str  = f"!!! Failure while executing {command} from {self.address}\n"
                log_str += f"Error that was caught: {command_err}"
                dreamnail.singleton.log(log_str)
                return False
            finally:
                self.lock.release()

        def close(self, remove_peer=True):
            if self.closed:
                return
            try:
                self.closed = True
                dreamnail.singleton.log(f"### Terminated connection with {self.address}")
                self.send("TERMINATE")
                if self.address in dreamnail.Server.singleton.peers and remove_peer:
                    del dreamnail.Server.singleton.peers[self.address]
                    dreamnail.singleton.remove_peer(self.address)
            finally:
                self.socket.close()

    def __init__(self):
        if dreamnail.singleton is not None:
            raise Exception("Singleton object limited to one instance.")
        dreamnail.singleton = self
        QtCore.QDir.addSearchPath("resources", APPLICATION_PATH + "/resources/")
        self.exited = False
        atexit.register(self.exit_handler)

        self.app = QApplication(sys.argv)
        self.win = QMainWindow()
        self.ui = dreamui.Ui_MainWindow()
        self.ui.setupUi(self.win)

        self.win.closeEvent = lambda event: self.exit_handler()
        self.ui.tabWidget.currentChanged.connect(self.tabWidget_currentChanged)
        self.ui.loginButton.clicked.connect(self.loginButton_clicked)
        self.ui.logoutButton.clicked.connect(self.logoutButton_clicked)
        self.ui.walletAddressCopyButton.clicked.connect(self.walletAddressCopyButton_clicked)
        self.ui.serverStateButton.clicked.connect(self.serverStateButton_clicked)
        self.ui.registerButton.clicked.connect(self.registerButton_clicked)
        self.ui.usernameLineEdit.textChanged.connect(self.usernameLineEdit_textChanged)
        self.ui.passwordLineEdit.textChanged.connect(self.passwordLineEdit_textChanged)
        self.ui.minerMsgTextEdit.textChanged.connect(self.minerMsgTextEdit_textChanged)
        self.ui.minerStateButton.clicked.connect(self.minerStateButton_clicked)
        self.ui.peerPoolComboBox.currentIndexChanged.connect(self.peerPoolComboBox_currentIndexChanged)
        self.ui.blockchainNextButton.clicked.connect(self.blockchainNextButton_clicked)
        self.ui.blockchainPreviousButton.clicked.connect(self.blockchainPreviousButton_clicked)
        self.ui.gotoBlockButton.clicked.connect(self.gotoBlockButton_clicked)
        self.ui.Block1TransactionCombobox.currentTextChanged.connect(self.Block1TransactionCombobox_currentTextChanged)
        self.ui.Block2TransactionCombobox.currentTextChanged.connect(self.Block2TransactionCombobox_currentTextChanged)
        self.ui.Block3TransactionCombobox.currentTextChanged.connect(self.Block3TransactionCombobox_currentTextChanged)
        self.ui.Block4TransactionCombobox.currentTextChanged.connect(self.Block4TransactionCombobox_currentTextChanged)
        self.ui.TransactionAddOutputButton.clicked.connect(self.TransactionAddOutputbutton_clicked)
        self.ui.TransactionRemoveOutputButton.clicked.connect(self.TransactionRemoveOutputButton_clicked)
        self.ui.TransactionEditAddressLineEdit.textChanged.connect(self.TransactionEditorLineEdit_textChanged)
        self.ui.TransactionEditValueLineEdit.textChanged.connect(self.TransactionEditorLineEdit_textChanged)
        self.ui.TransactionOutputSelectCombobox.currentTextChanged.connect(self.TransactionOutputSelectCombobox_currentTextChanged)
        self.ui.transactionMsgTextEdit.textChanged.connect(self.TransactionMsgTextEdit_textChanged)
        self.ui.createTransactionButton.clicked.connect(self.createTransactionButton_clicked)

        self.ui.userLabel.setStyleSheet("QLabel { color: white; }")
        self.ui.balanceLabel.setStyleSheet("QLabel { color: white; }")

        self.ui.peersConnectedLabel.setStyleSheet("QLabel { color: white; }")
        self.ui.peerPoolLabel.setStyleSheet("QLabel { color: white; }")
        self.ui.peerStatusLabel.setStyleSheet("QLabel { color: white; }")

        self.ui.hashRateLabel.setStyleSheet("QLabel { color: white; }")
        self.ui.workingMinerThreadsLabel.setStyleSheet("QLabel { color: white; }")

        self.ui.blockchainMassLabel.setStyleSheet("QLabel { color: white; }")
        self.ui.Block1HashLabel.setStyleSheet("QLabel { color: black; background: lightGray; font-size: 10pt; }")
        self.ui.Block1PrevHashLabel.setStyleSheet("QLabel { color: black; background: lightGray; font-size: 10pt; }")
        self.ui.Block2HashLabel.setStyleSheet("QLabel { color: black; background: lightGray; font-size: 10pt; }")
        self.ui.Block2PrevHashLabel.setStyleSheet("QLabel { color: black; background: lightGray; font-size: 10pt; }")
        self.ui.Block3HashLabel.setStyleSheet("QLabel { color: black; background: lightGray; font-size: 10pt; }")
        self.ui.Block3PrevHashLabel.setStyleSheet("QLabel { color: black; background: lightGray; font-size: 10pt; }")
        self.ui.Block4HashLabel.setStyleSheet("QLabel { color: black; background: lightGray; font-size: 10pt; }")
        self.ui.Block4PrevHashLabel.setStyleSheet("QLabel { color: black; background: lightGray; font-size: 10pt; }")

        self.application_config = configparser.ConfigParser()
        self.application_config.read(APPLICATION_PATH + "\\node.cfg")
        self.VERSION = self.application_config["METADATA"]["version"]

        self.user_data = dreambench.USER_DATA_TEMPLATE.copy()
        self.miner_msg = ""
        self.edited_transaction = None

        self.server = None

        # TODO: IMPLEMENT
        self.transaction_pool = []

        dreamnail.singleton.log("Loading bench from saved files...")
        self.blockchain, self.peer_pool = dreambench.load_bench()
        for peer_address in self.peer_pool.keys():
            self.add_to_peer_pool_gui(peer_address)
        dreamnail.singleton.log("Finished loading bench")

        self.win.show()
        sys.exit(self.app.exec())

    #region ui events
    def tabWidget_currentChanged(self):
        match self.ui.tabWidget.currentIndex():
            case 3:
                self.updateBlockchainExplorerTab()
            case 2:
                self.updateUserTab()
            case 6:
                self.updateTransactionEditorTab()

    def loginButton_clicked(self):
        username = self.ui.usernameLineEdit.text()
        passphrase = SHA256.new(self.ui.passwordLineEdit.text().encode()).hexdigest()
        self.user_passphrase = passphrase

        if os.path.isfile(APPLICATION_PATH + f"\\bench\\users\\{username}"):
            user_data = dreambench.try_read_user_file(passphrase, username)
            if user_data is not None:
                self.user_data = user_data
                self.ui.passwordLineEdit.setText("")
                self.ui.usernameLineEdit.setText("")

                self.ui.UserTab.setEnabled(True)
                self.ui.LoginTab.setEnabled(False)
                self.ui.ServerTab.setEnabled(True)
                self.ui.tabWidget.setCurrentIndex(2)

                self.ui.userLabel.setText(self.user_data["username"])
                self.ui.balanceLabel.setText(str(self.user_data["balance"]))
                return user_data
            else:
                QtWidgets.QMessageBox.critical(self.win, "Failed to login", "Invalid password.")
        else:
            QtWidgets.QMessageBox.critical(self.win, "Failed to login", "User does not exist!")

    def logoutButton_clicked(self):
        self.ui.LoginTab.setEnabled(True)
        self.ui.UserTab.setEnabled(False)
        self.ui.ServerTab.setEnabled(False)
        self.ui.tabWidget.setCurrentIndex(1)
        self.user_passphrase = None

        self.user_data = dreambench.USER_DATA_TEMPLATE.copy()
        self.ui.userLabel.setText(self.user_data["username"])
        self.ui.balanceLabel.setText(str(self.user_data["balance"]))
        self.ui.userWalletAddressLineEdit.setText("")

    def walletAddressCopyButton_clicked(self):
        pyperclip.copy(self.ui.userWalletAddressLineEdit.text())

    def usernameLineEdit_textChanged(self):
        if self.ui.usernameLineEdit.text().isalnum() and len(self.ui.passwordLineEdit.text()) > 0:
            self.ui.loginButton.setEnabled(True)
            self.ui.registerButton.setEnabled(True)
        else:
            self.ui.loginButton.setEnabled(False)
            self.ui.registerButton.setEnabled(False)

    def passwordLineEdit_textChanged(self):
        if self.ui.usernameLineEdit.text().isalnum() and len(self.ui.passwordLineEdit.text()) > 0:
            self.ui.loginButton.setEnabled(True)
            self.ui.registerButton.setEnabled(True)
        else:
            self.ui.loginButton.setEnabled(False)
            self.ui.registerButton.setEnabled(False)

    def serverStateButton_clicked(self):
        if self.server is None:
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.bind((self.application_config["SERVER"]["address"],
                             int(self.application_config["SERVER"]["port"])))
                test_sock.close()
                del test_sock
                self.open_server()
                self.ui.MinerTab.setEnabled(True)
                self.ui.TransactionEditorTab.setEnabled(True)
                self.ui.serverStateButton.setIcon(QtGui.QIcon("resources:onLogo.png"))
            except OSError as err:
                QtWidgets.QMessageBox.critical(self.win, "Failed to start server", f"{type(err)}: {err.args[1]}")
        else:
            self.close_server()
            self.ui.MinerTab.setEnabled(False)
            self.ui.TransactionEditorTab.setEnabled(False)
            self.ui.serverStateButton.setIcon(QtGui.QIcon("resources:offLogo.png"))
            self.ui.minerStateButton.setIcon(QtGui.QIcon("resources:offLogo.png"))

    def registerButton_clicked(self):
        username = self.ui.usernameLineEdit.text()
        passphrase = SHA256.new(self.ui.passwordLineEdit.text().encode()).hexdigest()
        self.user_passphrase = passphrase

        if dreambench.try_create_user(passphrase, username):
            new_user_data = self.loginButton_clicked()
            if new_user_data is not None:
                self.blockchain.tracked[dreamveil.key_to_address(new_user_data["key"])] = []
        else:
            QtWidgets.QMessageBox.critical(self.win, "Failed to register new user", "User already exists!")

    def minerMsgTextEdit_textChanged(self):
        self.miner_msg = self.ui.minerMsgTextEdit.toPlainText()

    def minerStateButton_clicked(self):
        if self.server is not None:
            if self.server.miner_open == False:
                self.server.start_miner()
                self.ui.minerStateButton.setIcon(QtGui.QIcon("resources:onLogo.png"))
                return
            else:
                self.server.close_miner()
        self.ui.minerStateButton.setIcon(QtGui.QIcon("resources:offLogo.png"))

    def peerPoolComboBox_currentIndexChanged(self):
        self.ui.peerStatusLabel.setText(self.peer_pool[self.ui.peerPoolComboBox.currentText()])

    def blockchainNextButton_clicked(self):
        current_block_index = int(self.ui.BlockchainTallyLabel.text().split('/')[0])
        if current_block_index + 4 <= len(self.blockchain.chain):
            current_block_index += 4
            self.ui.BlockchainTallyLabel.setText(f"{str(current_block_index)}/{len(self.blockchain.chain)}")
            self.updateBlockchainExplorerTab()

    def blockchainPreviousButton_clicked(self):
        current_block_index = int(self.ui.BlockchainTallyLabel.text().split('/')[0])
        if current_block_index == 1:
            return
        current_block_index = max(current_block_index-4, 1)
        self.ui.BlockchainTallyLabel.setText(f"{str(current_block_index)}/{len(self.blockchain.chain)}")
        self.updateBlockchainExplorerTab()

    def gotoBlockButton_clicked(self):
        try:
            seeked_block_index = int(self.ui.gotoBlockLineEdit.text())
        except ValueError:
            return
        if seeked_block_index <= len(self.blockchain.chain) and seeked_block_index > 0:
            self.ui.BlockchainTallyLabel.setText(f"{str(seeked_block_index)}/{len(self.blockchain.chain)}")
            self.updateBlockchainExplorerTab()

    def Block1TransactionCombobox_currentTextChanged(self):
        current_transaction_signature = self.ui.Block1TransactionCombobox.currentText()
        if current_transaction_signature == "":
            return
        current_block_index = int(self.ui.BlockchainTallyLabel.text().split('/')[0]) - 1
        current_block = self.blockchain.chain[current_block_index]
        for transaction in current_block.transactions:
            if transaction.signature == current_transaction_signature:
                self.ui.Block1TransactionInputCombobox.clear()
                for input_source, input_value in transaction.inputs.items():
                    self.ui.Block1TransactionInputCombobox.addItem(f"{input_value} - {input_source}")
                self.ui.Block1TransactionOutputCombobox.clear()
                for output_source, output_value in transaction.outputs.items():
                    self.ui.Block1TransactionOutputCombobox.addItem(f"{output_value} - {output_source}")
                self.ui.block1TextBrowser.setText(transaction.message)

    def Block2TransactionCombobox_currentTextChanged(self):
        current_transaction_signature = self.ui.Block2TransactionCombobox.currentText()
        if current_transaction_signature == "":
            return
        current_block_index = int(self.ui.BlockchainTallyLabel.text().split('/')[0])
        current_block = self.blockchain.chain[current_block_index]
        for transaction in current_block.transactions:
            if transaction.signature == current_transaction_signature:
                self.ui.Block2TransactionInputCombobox.clear()
                for input_source, input_value in transaction.inputs.items():
                    self.ui.Block2TransactionInputCombobox.addItem(f"{input_value} - {input_source}")
                self.ui.Block2TransactionOutputCombobox.clear()
                for output_source, output_value in transaction.outputs.items():
                    self.ui.Block2TransactionOutputCombobox.addItem(f"{output_value} - {output_source}")
                self.ui.block2TextBrowser.setText(transaction.message)

    def Block3TransactionCombobox_currentTextChanged(self):
        current_transaction_signature = self.ui.Block3TransactionCombobox.currentText()
        if current_transaction_signature == "":
            return
        current_block_index = int(self.ui.BlockchainTallyLabel.text().split('/')[0]) + 1
        current_block = self.blockchain.chain[current_block_index]
        for transaction in current_block.transactions:
            if transaction.signature == current_transaction_signature:
                self.ui.Block3TransactionInputCombobox.clear()
                for input_source, input_value in transaction.inputs.items():
                    self.ui.Block3TransactionInputCombobox.addItem(f"{input_value} - {input_source}")
                self.ui.Block3TransactionOutputCombobox.clear()
                for output_source, output_value in transaction.outputs.items():
                    self.ui.Block3TransactionOutputCombobox.addItem(f"{output_value} - {output_source}")
                self.ui.block3TextBrowser.setText(transaction.message)

    def Block4TransactionCombobox_currentTextChanged(self):
        current_transaction_signature = self.ui.Block4TransactionCombobox.currentText()
        if current_transaction_signature == "":
            return
        current_block_index = int(self.ui.BlockchainTallyLabel.text().split('/')[0]) + 2
        current_block = self.blockchain.chain[current_block_index]
        for transaction in current_block.transactions:
            if transaction.signature == current_transaction_signature:
                self.ui.Block4TransactionInputCombobox.clear()
                for input_source, input_value in transaction.inputs.items():
                    self.ui.Block4TransactionInputCombobox.addItem(f"{input_value} - {input_source}")
                self.ui.Block4TransactionOutputCombobox.clear()
                for output_source, output_value in transaction.outputs.items():
                    self.ui.Block4TransactionOutputCombobox.addItem(f"{output_value} - {output_source}")
                self.ui.block4TextBrowser.setText(transaction.message)

    def createTransactionButton_clicked(self):
        user_address = dreamveil.key_to_address(self.user_data["key"])
        if user_address in self.blockchain.tracked:
            output_sum = sum([dreamveil.to_decimal(val) for val in self.edited_transaction.outputs.values()])
            funds_sum = decimal.Decimal(0)
            input_transactions = {}
            for relevant_transaction_block_index, transaction_signature in self.blockchain.tracked[user_address][::-1]:
                for transaction in self.blockchain.chain[relevant_transaction_block_index].transactions:
                    if transaction.signature not in self.edited_transaction.inputs and transaction.signature == transaction_signature:
                        transaction_value = self.blockchain.calculate_transaction_value(transaction, user_address)
                        if transaction_value is not None:
                            funds_sum += dreamveil.to_decimal(transaction_value)
                            input_transactions[transaction.signature] = transaction_value
                        if funds_sum >= output_sum:
                            break
                if funds_sum >= output_sum:
                    break
            if funds_sum >= output_sum:
                for signature, value in input_transactions.items():
                    self.edited_transaction.inputs[signature] = value
                diffrential_tx_value = funds_sum - output_sum
                if diffrential_tx_value > 0:
                    self.edited_transaction.outputs[user_address] = str(diffrential_tx_value)
            self.edited_transaction.sign(self.user_data["key"])
            verify = dreamveil.Transaction.loads(self.edited_transaction.dumps())
            verify = verify is not None
            if verify:
                self.server.add_to_transaction_pool(self.edited_transaction)

                QtWidgets.QMessageBox.information(self.win, "Transaction issued", "Succesfuly created and broadcasted transaction to all connected peers.")
                self.updateTransactionEditorTab()
                return
        QtWidgets.QMessageBox.critical(self.win, "Failed to issue transaction", "Insufficient funds.")

    def TransactionOutputSelectCombobox_currentTextChanged(self):
        self.ui.TransactionRemoveOutputButton.setEnabled(self.ui.TransactionOutputSelectCombobox.currentText() != "")
        self.ui.createTransactionButton.setEnabled(self.ui.TransactionOutputSelectCombobox.currentText() != "")

    def TransactionEditorLineEdit_textChanged(self):
        output_address = self.ui.TransactionEditAddressLineEdit.text()
        output_value = self.ui.TransactionEditValueLineEdit.text()
        try:
            dreamveil.address_to_key(output_address)
            assert output_address not in self.edited_transaction.outputs
            assert output_address != dreamveil.key_to_address(self.user_data["key"])
            output_address_valid = True
        except (ValueError, AssertionError):
            if output_address != "MINER" or self.edited_transaction.get_miner_fee() != 0:
                output_address_valid = False
            else:
                output_address_valid = True

        try:
            output_value = dreamveil.to_decimal(output_value)
            assert output_value > 0
            output_value_valid = True
        except (decimal.InvalidOperation, AssertionError):
            output_value_valid = False

        self.ui.TransactionAddOutputButton.setEnabled(output_address_valid and output_value_valid)

    def TransactionAddOutputbutton_clicked(self):
        self.ui.createTransactionButton.setEnabled(False)
        output_address = self.ui.TransactionEditAddressLineEdit.text()
        output_value = self.ui.TransactionEditValueLineEdit.text()

        self.edited_transaction.outputs[output_address] = output_value
        self.ui.TransactionOutputSelectCombobox.addItem(f"{output_value} - {output_address}")
        self.ui.TransactionEditAddressLineEdit.setText("")
        self.ui.TransactionEditValueLineEdit.setText("")

    def TransactionRemoveOutputButton_clicked(self):
        self.ui.createTransactionButton.setEnabled(False)
        output_address = self.ui.TransactionOutputSelectCombobox.currentText().split(" - ")[-1]
        del self.edited_transaction.outputs[output_address]
        self.ui.TransactionOutputSelectCombobox.removeItem(self.ui.TransactionOutputSelectCombobox.currentIndex())

    def TransactionMsgTextEdit_textChanged(self):
        if self.edited_transaction is not None:
            self.edited_transaction.message = self.ui.transactionMsgTextEdit.toPlainText()
    #endregion

    #region Tab updates
    def updateBlockchainExplorerTab(self):
        current_block_index = int(self.ui.BlockchainTallyLabel.text().split('/')[0])
        self.ui.BlockchainTallyLabel.setText(f"{str(current_block_index)}/{len(self.blockchain.chain)}")
        self.ui.blockchainMassLabel.setText(str(self.blockchain.mass))

        for i in range(4):
            block_index = current_block_index + i - 1
            if len(self.blockchain.chain) > block_index:
                current_block = self.blockchain.chain[block_index]
            else:
                # Initialze empty block
                current_block = dreamveil.Block("", [], "", "")

            if i+1 == 1:
                if self.ui.Block1HashLabel.text() != current_block.block_hash:
                    self.ui.Block1HashLabel.setText(current_block.block_hash)
                    self.ui.Block1PrevHashLabel.setText(current_block.previous_block_hash)
                    self.ui.Block1TransactionCombobox.clear()
                    self.ui.block1TextBrowser.setText("")
                    self.ui.Block1TransactionInputCombobox.clear()
                    self.ui.Block1TransactionOutputCombobox.clear()

                    for transaction in current_block.transactions:
                        self.ui.Block1TransactionCombobox.addItem(transaction.signature)
            elif i+1 == 2:
                if self.ui.Block2HashLabel.text() != current_block.block_hash:
                    self.ui.Block2HashLabel.setText(current_block.block_hash)
                    self.ui.Block2PrevHashLabel.setText(current_block.previous_block_hash)
                    self.ui.Block2TransactionCombobox.clear()
                    self.ui.block2TextBrowser.setText("")
                    self.ui.Block2TransactionInputCombobox.clear()
                    self.ui.Block2TransactionOutputCombobox.clear()

                    for transaction in current_block.transactions:
                        self.ui.Block2TransactionCombobox.addItem(transaction.signature)
            elif i+1 == 3:
                if self.ui.Block3HashLabel.text() != current_block.block_hash:
                    self.ui.Block3HashLabel.setText(current_block.block_hash)
                    self.ui.Block3PrevHashLabel.setText(current_block.previous_block_hash)
                    self.ui.Block3TransactionCombobox.clear()
                    self.ui.block3TextBrowser.setText("")
                    self.ui.Block3TransactionInputCombobox.clear()
                    self.ui.Block3TransactionOutputCombobox.clear()

                    for transaction in current_block.transactions:
                        self.ui.Block3TransactionCombobox.addItem(transaction.signature)
            else:
                if self.ui.Block4HashLabel.text() != current_block.block_hash:
                    self.ui.Block4HashLabel.setText(current_block.block_hash)
                    self.ui.Block4PrevHashLabel.setText(current_block.previous_block_hash)
                    self.ui.Block4TransactionCombobox.clear()
                    self.ui.block4TextBrowser.setText("")
                    self.ui.Block4TransactionInputCombobox.clear()
                    self.ui.Block4TransactionOutputCombobox.clear()

                    for transaction in current_block.transactions:
                        self.ui.Block4TransactionCombobox.addItem(transaction.signature)

    def updateUserTab(self):
        if self.user_data != dreambench.USER_DATA_TEMPLATE:
            user_address = dreamveil.key_to_address(dreamnail.singleton.user_data["key"])
            new_balance = decimal.Decimal(0)
            input_transactions = {}
            if user_address in self.blockchain.tracked:
                for relevant_transaction_block_index, transaction_signature in self.blockchain.tracked[user_address][::-1]:
                    for transaction in self.blockchain.chain[relevant_transaction_block_index].transactions:
                        if transaction.signature == transaction_signature:
                            transaction_value = self.blockchain.calculate_transaction_value(transaction, user_address)
                            if transaction_value is not None:
                                new_balance += dreamveil.to_decimal(transaction_value)
                                input_transactions[transaction.signature] = transaction_value
            dreamnail.singleton.user_data["balance"] = new_balance

            self.ui.balanceLabel.setText(str(self.user_data["balance"]))
            self.ui.userWalletAddressLineEdit.setText(dreamveil.key_to_address(self.user_data["key"]))

    def updateTransactionEditorTab(self):
        if self.user_data != dreambench.USER_DATA_TEMPLATE:
            self.edited_transaction = dreamveil.Transaction(dreamveil.key_to_address(self.user_data["key"]), {}, {}, "", "", "")
        self.ui.TransactionEditAddressLineEdit.setText("")
        self.ui.TransactionEditValueLineEdit.setText("")
        self.ui.transactionMsgTextEdit.setPlainText("")
        self.ui.TransactionOutputSelectCombobox.clear()
        self.ui.createTransactionButton.setEnabled(False)
    #endregion

    def open_server(self):
        server_address = self.application_config["SERVER"]["address"]
        server_port = int(self.application_config["SERVER"]["port"])
        self.server = dreamnail.Server(server_address, server_port)

    def close_server(self):
        if self.server is not None:
            self.server.close()
            self.server = None

    def add_peer(self, peer_address):
        self.ui.peersConnectedComboBox.addItem(peer_address)
        self.ui.peersConnectedLabel.setText(str(int(self.ui.peersConnectedLabel.text()) + 1))

    def remove_peer(self, peer_address):
        for i in range(self.ui.peersConnectedComboBox.count()):
            if self.ui.peersConnectedComboBox.itemText(i) == peer_address:
                self.ui.peersConnectedComboBox.removeItem(i)
        self.ui.peersConnectedLabel.setText(str(int(self.ui.peersConnectedLabel.text()) - 1))

    def add_to_peer_pool_gui(self, peer_address):
        self.ui.peerPoolComboBox.addItem(peer_address)
        self.ui.peerPoolLabel.setText(str(int(self.ui.peerPoolLabel.text()) + 1))

    def log(self, message):
        print(message)
        self.ui.logTextBrowser.append(f"{message}")

    def exit_handler(self):
        if not self.exited:
            self.close_server()
            dreambench.write_blockchain_file(self.blockchain)
            dreambench.write_peer_pool_file(self.peer_pool)
            if self.user_data != dreambench.USER_DATA_TEMPLATE and self.user_passphrase is not None:
                dreambench.write_user_file(self.user_passphrase, self.user_data)
            self.log("Application Exit")
            self.exited = True

if __name__ == '__main__':
    application = dreamnail()