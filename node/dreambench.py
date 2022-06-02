import dreamveil
import dreamshield

import os
import secrets
import json

from Crypto.PublicKey import RSA

APPLICATION_PATH = os.path.dirname(os.path.abspath(__file__))

USER_DATA_TEMPLATE = {"username": None,
                          "key": None,
                          "balance": 0,
                          "outgoing": [],
                          "ingoing": []}

def load_bench():
    bench_dirs = ["..\\bench", "backup", "users"]
    for bench_dir in bench_dirs:
        if not os.path.isdir(f"{APPLICATION_PATH}\\bench\\{bench_dir}"):
            os.mkdir(f"{APPLICATION_PATH}\\bench\\{bench_dir}")

    read_param = "r+" if os.path.isfile(APPLICATION_PATH + "\\bench\\blockchain.json") else "w+"
    with open(APPLICATION_PATH + "\\bench\\blockchain.json", read_param) as f:
        try:
            contents = f.read()
            if contents == "":
                contents = "[]"
                f.write(contents)
            blockchain = dreamveil.Blockchain.loads(contents)
        except (ValueError, AssertionError) as err:
            print("!!! Could not loads blockchain from bench")
            print(f"{type(err): {err.args[1]}}")

            f.close()
            if os.path.isfile(APPLICATION_PATH + "\\bench\\blockchain.json"):
                os.rename(APPLICATION_PATH + "\\bench\\blockchain.json", APPLICATION_PATH + f"\\bench\\backup\\blockchain-{secrets.token_hex(8)}.json.old")

    read_param = "r+" if os.path.isfile(APPLICATION_PATH + "\\bench\\peer_pool.json") else "w+"
    with open(APPLICATION_PATH + "\\bench\\peer_pool.json", read_param) as f:
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

def write_blockchain_file(blockchain:dreamveil.Blockchain):
    with open(APPLICATION_PATH + f"\\bench\\blockchain.json", "w") as blockchain_file:
        blockchain_file.write(blockchain.dumps())

def write_peer_pool_file(peer_pool:dict):
    with open(APPLICATION_PATH + "\\bench\\peer_pool.json", "w") as peer_pool_file:
        peer_pool_file.write(json.dumps(peer_pool))

def try_read_user_file(passphrase:str, username:str):
    with open(APPLICATION_PATH + f"\\bench\\users\\{username}", "rb") as user_file:
        try:
            user_file_contents = user_file.read()
            user_file_contents = dreamshield.decrypt(passphrase, user_file_contents)
            user_data = json.loads(user_file_contents)
            user_data["key"] = RSA.import_key(user_data["key"])
            return user_data
        except (ValueError, json.JSONDecodeError):
            return None

def write_user_file(passphrase:str, user_data:dict):
    with open(APPLICATION_PATH + f"\\bench\\users\\{user_data['username']}", "wb") as user_file:
        try:
            user_file_contents = user_data.copy()
            user_file_contents["key"] = user_file_contents["key"].export_key('PEM').decode()
            user_file_contents = json.dumps(user_file_contents)
            user_file_contents = dreamshield.encrypt(passphrase, user_file_contents)
            user_file.write(user_file_contents)
            return True
        except (ValueError, json.JSONDecodeError):
            return False

def try_create_user(passphrase:str, username:str):
    """
    Attempts to create a user given a username and a passphrase.
    :returns: boolean succesfully created user.
    """
    user_file_path = APPLICATION_PATH + f"\\bench\\users\\{username}"
    if not os.path.isfile(user_file_path):
        with open(user_file_path, "w"):
            pass
        new_user_data = USER_DATA_TEMPLATE.copy()
        new_user_data["username"] = username
        new_user_data["key"] = RSA.generate(2048)
        write_user_file(passphrase, new_user_data)
        return True
    else:
        return False