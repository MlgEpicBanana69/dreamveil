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

# 192.168.1.19
server = Server("192.168.1.19")
server.run()

p = server.connect("192.168.1.36")
p.send("hello")

print("?")

while True:
    pass
