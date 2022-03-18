import dreamveil

import secrets

from getpass import getpass
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from my_server import Server

import tracemalloc
tracemalloc.start()


VERSION = "1.0"

server = Server("127.0.0.1", 22726)
server.run()

print("?")

while True:
    pass
