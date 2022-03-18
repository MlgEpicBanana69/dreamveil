from ctypes import addressof
import socket
import asyncio

class Server:
    singleton = None

    def __init__(self, address, port=22727, max_peer_amount=150):
        if Server.singleton is not None:
            raise Exception("Singleton class limited to one instance")

        Server.singleton = self
        self.address = address
        self.port = port
        self.max_peer_amount = max_peer_amount
        self.socket = None
        self.peers = []
        self.closed = False

    def run(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.address, self.port))
        self.socket.listen(self.max_peer_amount)

        print(f"Server is now running and binded to {(self.address, self.port)}")
        print("============================================")

        while not self.closed:
            peer_socket, peer_address = self.socket.accept()
            self.peers.append(Connection(peer_socket, peer_address))
            print(f"### {peer_socket, peer_address} connected to node")

    def connect(self, address):
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_socket.connect(address, self.port)
        new_peer = Connection(peer_socket, address)
        self.peers.append(new_peer)
        return new_peer

    def close(self):
        for peer in self.peers:
            peer.close()

        self.closed = True

class Connection:
    def __init__(self, socket, address):
        self.socket = socket
        self.address = address
        self.closed = False

    def close(self):
        self.socket.shutdown()
        self.socket.close()
        self.closed = True

    async def send(self, message):
        self.socket.send(message)

    async def run(self):
        while not self.closed:
            message = self.socket.receive()
            print(message)