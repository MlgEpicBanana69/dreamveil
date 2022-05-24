import dreamveil
import dreamshield

import os
import secrets
import json

from Crypto.PublicKey import RSA

APPLICATION_PATH = os.path.dirname(os.path.abspath(__file__)) + "\\"

def load_bench():
    if not os.path.isdir(APPLICATION_PATH + "bench"):
        os.mkdir(APPLICATION_PATH + "bench")
    if not os.path.isdir(APPLICATION_PATH + "bench\\backup"):
        os.mkdir(APPLICATION_PATH + "bench\\backup")

    read_param = "r+" if os.path.isfile(APPLICATION_PATH + "bench\\blockchain.json") else "w+"
    with open(APPLICATION_PATH + "bench\\blockchain.json", read_param) as f:
        try:
            contents = f.read()
            if contents == "":
                contents = "[]"
                f.write(contents)
            blockchain = dreamveil.Blockchain.loads(contents)
        except (ValueError, AssertionError) as err:
            print("!!! Could not loads blockchain from bench")
            print(err)

            f.close()
            if os.path.isfile(APPLICATION_PATH + "bench\\blockchain.json"):
                os.rename(APPLICATION_PATH + "bench\\blockchain.json", APPLICATION_PATH + f"bench\\backup\\blockchain-{secrets.token_hex(8)}.json.old")

    read_param = "r+" if os.path.isfile(APPLICATION_PATH + "bench\\peer_pool.json") else "w+"
    with open(APPLICATION_PATH + "bench\\peer_pool.json", read_param) as f:
        try:
            contents = f.read()
            if contents == "":
                contents = "{}"
                f.write(contents)
            peer_pool = json.loads(contents)
            assert type(peer_pool) == dict
        except (ValueError, AssertionError) as err:
            print("!!! Could not loads peer pool from bench")
            print(err)
            f.close()
            if os.path.isfile("bench\\peer_pool.json"):
                os.rename("bench\\peer_pool.json", f"bench\\backup\\peer_pool-{secrets.token_hex(8)}.json.old")

    return blockchain, peer_pool

def read_user_file(passphrase:str, username:str):
    with open(APPLICATION_PATH + f"users\\{username}", "rb") as user_file:
        try:
            # Encrypts
            #user_file_contents = RSA.generate(2048)
            #user_file_contents = user_file_contents.export_key('PEM')
            #user_file_contents = json.dumps([user_file_contents.decode()])
            #user_file_contents = dreamshield.encrypt(password, user_file_contents)
            #user_file.write(user_file_contents)
            user_file_contents = user_file.read()
            host_keys = [RSA.import_key(key) for key in json.loads(dreamshield.decrypt(passphrase, user_file_contents).decode())]
            return host_keys
        except (ValueError, json.JSONDecodeError):
            return None

def write_user_file(passphrase, username:str, user_keys:list):
    with open(APPLICATION_PATH + f"users\\{username}", "wb") as user_file:
        try:
            # Encrypts
            #user_file_contents = RSA.generate(2048)
            #user_file_contents = user_file_contents.export_key('PEM')
            user_file_contents = json.dumps(user_keys)
            user_file_contents = dreamshield.encrypt(passphrase, user_file_contents)
            user_file.write(user_file_contents)
            user_file_contents = user_file.read()
            return True
        except (ValueError, json.JSONDecodeError):
            return None