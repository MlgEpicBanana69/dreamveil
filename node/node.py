import dreamveil

import configparser
import ipaddress
import os
import secrets
import json
import random
import math


import socket
import threading

from node.dreamveil import Block, Transaction

class Server:
    singleton = None

    def __init__(self, version:str, peer_pool:dict, address:str, port=22727, max_peer_amount=150):
        if Server.singleton is not None:
            raise Exception("Singleton class limited to one instance")

        Server.singleton = self
        self.version = version
        self.address = address
        self.port = port
        self.max_peer_amount = max_peer_amount
        self.socket = None
        self.peers = {}
        self.accepted_peer_addrs = set()
        self.seeked_peer_addrs = set()
        self.peer_pool = peer_pool
        self.closed = False

        self.run()

    def roll_peer(self):
        peer_options = []
        deprecated_peer_options = []
        for peer, status in self.peer_pool.items():
            if status != "DEPRECATED" and peer not in self.peers.keys():
                peer_options.append(peer)
            elif status == "DEPRECATED" and peer not in self.peers.keys():
                deprecated_peer_options.append(peer)
        if len(peer_options) > 0:
            return random.choice(peer_options)
        elif len(deprecated_peer_options) > 0:
            return random.choice(deprecated_peer_options)
        else:
            print("!!! In roll_peer no suitable peer was found!")
            return None

    def run(self):
       self.seeker_thread = threading.Thread(target=self.seeker)
       self.accepter_thread = threading.Thread(target=self.accepter)
       print("Starting server and assigning seeker and accepter threads")
       print("_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-")
       self.seeker_thread.run()
       self.accepter_thread.run()

    def seeker(self):
        print(f"Server is now seeking new connections")
        print("============================================")

        while not self.closed:
            # Once connection amount is too low, seek connections if possible.
            while len(self.peers) < math.floor(self.max_peer_amount*(2/3)) and not self.closed:
                new_peer = self.roll_peer()
                if new_peer is None:
                    print("!!! Failed to find new peer in Server.run()!")
                    peer_pool
                    break
                else:
                    connection_result = self.connect(new_peer)
                    if connection_result is None:
                        # TODO: Define peer status system
                        peer_pool[new_peer] = "DEPRECATED"
                        print(f"### Marked {new_peer} as DEPRECATED")
                    else:
                        peer_pool[new_peer] = "CONVERSED"

    def accepter(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.address, self.port))
        self.socket.listen(self.max_peer_amount)

        print(f"Server is now accepting incoming connections and is binded to {(self.address, self.port)}")
        print("============================================")

        while not self.closed:
            # Do not accept new connections once peer count exceeds maximum allowed
            while len(self.peers) < self.max_peer_amount and not self.closed:
                peer_socket, peer_address = self.socket.accept()
                self.peers[peer_address] = Connection(peer_socket, peer_address)
                print(f"### {peer_address} connected to node")

    def connect(self, address):
        if len(self.peers) <= self.max_peer_amount:
            try:
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.connect((address, self.port))
                new_peer = Connection(peer_socket, address)
                self.peers[address] = new_peer
                print(f"### Server connected to {address}")
                return new_peer
            except TimeoutError:
                print(f"!!! Failed to connect to {address}")
                return None
        else:
            print(f"!!! Failed to connect to {address}")
            print(f"### Server rules do not allow making more than {self.max_peer_amount} connections.")
            return None

    def close(self):
        """Terminated the server and all of its ongoing connections"""
        print("### SHUTTING DOWN SERVER")
        for peer in self.peers:
            peer.close()

        self.closed = True

    def broadcast(self, message, exclusions=[]):
        for peer_addr, peer in self.peers.items():
            if peer_addr not in exclusions:
                peer.send(message)

class Connection:
    COMMAND_SIZE = 6
    HEADER_LEN = len(str(dreamveil.Block.MAX_BLOCK_SIZE))
    MAX_MESSAGE_SIZE = HEADER_LEN + COMMAND_SIZE + dreamveil.Block.MAX_BLOCK_SIZE

    def __init__(self, socket, address):
        self.socket = socket
        self.address = address
        self.closed = False
        self.working = None

        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        self.conversation_setup()
        try:
            while not self.closed:
                try:
                    message = self.socket.recv(Connection.HEADER_LEN + Connection.COMMAND_SIZE + dreamveil.Block.MAX_BLOCK_SIZE)
                    if len(message) >= Connection.HEADER_LEN + Connection.COMMAND_SIZE:
                        commands = self.parse_messages(message.decode())
                        for command, param in commands:
                            self.parse_command(command, param)
                    else:
                        print(f"### Recieved invalid message (too small in size): {message.decode()}")
                except:
                    print(f"!!! Internal server error at Connection({Connection.address}). (last message: {message})")
        except (ConnectionResetError):
            self.close()

    def close(self):
        self.closed = True
        self.socket.close()

        print(f"### Closed connection with {self.address}")

        del Server.singleton.peers[self.address]

    def send(self, message:str):
        assert len(message) <= Connection.MAX_MESSAGE_SIZE

        if not self.closed:
            message = str(len(message)).zfill(Connection.HEADER_LEN) + message
            self.socket.send(message.encode())
        else:
            raise Exception("Cannot send message. Connection is already closed.")

    def recv(message:str):
        output = []
        scanned_count = 0
        while scanned_count < len(message):
            command_len = message[scanned_count:scanned_count + Connection.HEADER_LEN]
            try:
                command_len = command_len.lstrip("0")
                command_len = int(command_len)
            except ValueError:
                print(f"### Recieved invalid message (Wrongly formatted): {message}")
                break
            scanned_count += Connection.HEADER_LEN
            command = message[scanned_count:Connection.COMMAND_SIZE]
            scanned_count += Connection.COMMAND_SIZE
            command_message = message[scanned_count: scanned_count + command_len]
            scanned_count += command_len
            output.append((command, command_message))
        return output

    #region connection commands
    def connection_command(self, command_func):
        def wrapper(*args, **kwargs):
            # Halt sending commands until the previous command has finished
            while self.working is not None and not self.closed:
                pass

            self.working = command_func.__name__
            output = command_func(*args, **kwargs)
            self.working = None
            return output
        return wrapper

    @connection_command
    def setup(self):
        self.socket.send(Server.singleton.version.encode())
        peer_version = self.socket.recv(6).decode()
        if peer_version != Server.singleton.version:
            print(f"!!! Peer version {peer_version} is not compatible with the current application version {Server.singleton.version}")
            # Terminate the connection
            self.close()
        else:
            print(f"### Connection with {self.address} completed setup (version: {Server.singleton.version})")

    @connection_command
    def SENDTX(self, transaction:Transaction):
        pass

    @connection_command
    def SENDBK(self, block:Block):
        pass
    #endregion

    def parse_command(self, command:str, param):
        try:
            match command:
                case "SENDTX":
                    param = str(param)
                case "YELLBK":
                    param = int(param)
                case "GIVEBK":
                    param = int(param)
                case "FRIEND":
                    param = str(param).split(',')
                    for peer_addr in param:
                        assert ipaddress.ip_address(peer_addr)
                case "LONELY":
                    param = str(param)
                    assert ipaddress.ip_address(peer_addr)
                case _:
                    raise ValueError("Unknown command")
            Server.singleton.events[self.address, command](param)
            return True
        except (AssertionError, ValueError) as command_err:
            print(f"!!! Could not parse command {command} from {self.address}")
            print(f"COMMAND PARAM\n{param}\nEND COMMAND PARAM")
            print(f"Error that was caught: {command_err}")
            return False

def load_state():
    with open("state\\blockchain.json", "w+") as f:
        try:
            contents = f.read()
            if contents == "":
                contents = "[]"
                f.write(contents)
            blockchain = dreamveil.Blockchain.loads(contents)
        except (ValueError, AssertionError) as err:
            print("!!! Could not loads blockchain from state")
            print(err)
            if os.path.isfile("state\\blockchain.json"):
                os.rename("state\\blockchain.json", f"state\\backup\\blockchain{secrets.token_hex(8)}.json.old")
    with open("state\\peer_pool.json", "w+") as f:
        try:
            contents = f.read()
            if contents == "":
                contents = "{}"
                f.write(contents)
            peer_pool = json.loads(contents)
            assert type(peer_pool) == dict
        except (ValueError, AssertionError) as err:
            print("!!! Could not loads peer pool from state")
            print(err)
            if os.path.isfile("state\\peer_pool.json"):
                os.rename("state\\peer_pool.json", f"state\\backup\\peer_pool{secrets.token_hex(8)}.json.old")

    return blockchain, peer_pool

application_config = configparser.ConfigParser()
application_config.read("node.cfg")
VERSION = application_config["METADATA"]["version"]

print("Loading state from saved files...")
blockchain, peer_pool = load_state()
print("Finished loading state")

server = Server(VERSION, peer_pool, application_config["SERVER"]["address"])

for p in server.peers.values():
    p.send("hello")