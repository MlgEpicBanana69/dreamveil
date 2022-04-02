import dreamveil

import socket
import threading

class Server:
    singleton = None

    def __init__(self, version, address, port=22727, max_peer_amount=150):
        if Server.singleton is not None:
            raise Exception("Singleton class limited to one instance")

        Server.singleton = self
        self.version = version
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
            # Do not accept new connections once peer count exceeds maximum allowed
            while len(self.peers) >= self.max_peer_amount:
                pass
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

class Connection:
    def __init__(self, socket, address):
        self.socket = socket
        self.address = address
        self.closed = False
        self.setup = False

        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def close(self):
        self.closed = True
        self.socket.close()

        print(f"### Closed connection with {self.address}")

        del Server.singleton.peers[self.address]

    def send(self, message:str):
        # Halt sending messages until the connection setup is made
        while not self.setup and not self.closed:
            pass

        if not self.closed:
            self.socket.send(message.encode())
        else:
            raise Exception("Cannot send message. Connection is already closed.")

    def run(self):
        self.conversation_setup()
        try:
            while not self.closed:
                message = self.socket.recv(dreamveil.Block.MAX_BLOCK_SIZE)
                print(message)
        except (ConnectionResetError):
            self.close()

    def conversation_setup(self):
        self.socket.send(Server.singleton.version.encode())
        peer_version = self.socket.recv(6).decode()
        if peer_version != Server.singleton.version:
            print(f"!!! Peer version {peer_version} is not compatible with the current application version {Server.singleton.version}")
            # Terminate the connection
            self.setup = False
            self.close()
        else:
            self.setup = True
            print(f"### Connection with {self.address} completed setup (version: {Server.singleton.version})")
            return