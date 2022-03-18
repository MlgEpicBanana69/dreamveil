import dreamveil

import socket
import threading

class Server:
    singleton = None

    def __init__(self, version, address, port=22727, max_peer_amount=150):
        if Server.singleton is not None:
            raise Exception("Singleton class limited to one instance")

        Server.singleton = self
        self.address = address
        self.port = port
        self.max_peer_amount = max_peer_amount
        self.socket = None
        self.peers = {}
        self.closed = False
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.address, self.port))
        self.socket.listen(self.max_peer_amount)

        print(f"Server is now running and binded to {(self.address, self.port)}")
        print("============================================")

        while not self.closed:
            peer_socket, peer_address = self.socket.accept()
            self.peers[peer_address] = Connection(peer_socket, peer_address)
            print(f"### {peer_address} connected to node")

    def connect(self, address):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((address, self.port))
            new_peer = Connection(peer_socket, address)
            self.peers[address] = new_peer
            return new_peer
        except TimeoutError:
            print(f"!!! Failed to connect to {address}")
            return None

    def close(self):
        """Terminated the server and all of its ongoing connections"""
        print("### SHUTTING DOWN SERVER")

        for peer in self.peers:
            peer.close()

        self.closed = True

class Connection:
    def __init__(self, socket, address):
        self.socket = socket
        self.address = address
        self.closed = False
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def close(self):
        self.socket.close()
        self.closed = True

        print(f"### Closed connection with {self.address}")

        del Server.singleton.peers[self.address]

    def send(self, message:str):
        self.socket.send(message.encode())

    def run(self):
        try:
            while not self.closed:
                message = self.socket.recv(dreamveil.Block.MAX_BLOCK_SIZE)
                print(message)
        except (ConnectionResetError):
            self.close()