import dreamveil

import secrets

from getpass import getpass
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES


password = b"gaming"
info = b"that's poggers bruv"
salt = b"COPE"
key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)
nonce = get_random_bytes(8)
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
ct = cipher.encrypt(info)

#with open("test.json", "wb") as test:
#    test.write(nonce + ct)

with open("test.json", "rb") as test:
    contents = test.read()
    nonce = contents[:8:]
    ct = contents[8::]

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    print(nonce)
    print(cipher.decrypt(ct))



