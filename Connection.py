import socket

class Connection:
    def __init__(self, peer_addr, port=22727):
        self.port = port
        self.peer_addr = peer_addr
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind()

class Connections:
    def __init__(self):
        return