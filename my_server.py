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
        self.terminated = False

    async def run(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.address, self.port))
        self.socket.listen(self.max_peer_amount)

        while not self.terminated:
            peer_socket, peer_address = self.socket.accept()
            self.peers.append(Connection())
            print(f"### {peer_socket, peer_address} connected to node")

class Connection:
    def __init__(self, peer_socket, peer_address):
        self.socket = socket
        self.address = addressof