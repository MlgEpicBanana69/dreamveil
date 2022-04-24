import secrets

from getpass import getpass
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

def encrypt(passphrase:str, pt:str):
    """
    A passphrase based decryption function that uses PBKDF2 with an
    encrypt-then-mac scheme using AES-CTR for confidentially with HMAC for integrity.

    :str passphrase: The passphrase used for the encryption of the plaintext
    :str pt: The message to be encrypted using the passphrase
    :returns: The binary information: HMAC || salt || nonce || ct
    """
    passphrase = passphrase.encode()
    pt = pt.encode()

    salt = get_random_bytes(16)
    expansion = PBKDF2(passphrase, salt, 32, count=1000000, hmac_hash_module=SHA256)
    nonce = get_random_bytes(8)
    ct = AES.new(key=expansion[:16:], mode=AES.MODE_CTR, nonce=nonce).encrypt(pt)

    mac = HMAC.new(expansion[16::], salt + nonce + ct, digestmod=SHA256)
    return mac.digest() + salt + nonce + ct

def decrypt(passphrase:str, ct:bytes):
    """
    A passphrase based decryption function that uses PBKDF2 with an
    encrypt-then-mac scheme using AES-CTR for confidentially with HMAC for integrity.

    :str passphrase: The passphrase used for decryption
    :bytes ct: The ciphertext to be decrypted
    :returns: The decrypted plaintext as str
    """
    passphrase = passphrase.encode()
    proposed_mac = ct[:32:]
    salt = ct[32:48]
    expansion = PBKDF2(passphrase, salt, 32, count=1000000, hmac_hash_module=SHA256)
    nonce = ct[48:56]
    encrypted_pt = ct[56::]
    mac = HMAC.new(expansion[16::], salt + nonce + encrypted_pt, digestmod=SHA256)
    if not secrets.compare_digest(mac.digest(), proposed_mac):
        raise ValueError("Incorrect passphrase or invalid message")

    pt = AES.new(key=expansion[:16:], mode=AES.MODE_CTR, nonce=nonce).decrypt(encrypted_pt)
    return pt
