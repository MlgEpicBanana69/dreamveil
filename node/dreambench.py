import math
import dreamveil
import dreamshield

import os
import secrets
import json

from Crypto.PublicKey import RSA

APPLICATION_PATH = os.path.dirname(os.path.abspath(__file__))

USER_DATA_TEMPLATE = {"username": None,
                          "key": None,
                          "balance": "0"}

def load_bench_file(filename, loading_func):
    read_param = "r+" if os.path.isfile(APPLICATION_PATH + f"\\bench\\{filename}") else "w+"
    with open(APPLICATION_PATH + f"\\bench\\{filename}", read_param) as f:
        try:
            contents = f.read()
            return loading_func(contents, f)
        except (ValueError, AssertionError) as err:
            print(f"!!! Could not loads {filename} from bench")
            print(err)
            f.close()
            if os.path.isfile(f"bench\\{filename}"):
                os.rename(f"bench\\{filename}", f"bench\\backup\\{filename}-{secrets.token_hex(8)}.old")

def load_bench():
    outputs = []
    bench_dirs = ["..\\bench", "backup", "users", "POWfailed"]
    for bench_dir in bench_dirs:
        if not os.path.isdir(f"{APPLICATION_PATH}\\bench\\{bench_dir}"):
            os.mkdir(f"{APPLICATION_PATH}\\bench\\{bench_dir}")

    def loading_func(contents, f):
        if contents == "":
            contents = "[]"
            f.write(contents)
        return dreamveil.Blockchain.loads(contents)
    outputs.append(load_bench_file("blockchain.json", loading_func))

    def loading_func(contents, f):
        if contents == "":
            contents = "{}"
            f.write(contents)
        peer_pool = json.loads(contents)
        assert type(peer_pool) == dict
        return peer_pool
    outputs.append(load_bench_file("peer_pool.json", loading_func))

    def loading_func(contents, f):
        if contents == "":
            contents = "[]"
            f.write(contents)
        transaction_pool = json.loads(contents)
        assert type(transaction_pool) == list
        for i in range(len(transaction_pool)):
            transaction_pool[i] = dreamveil.Transaction.loads(transaction_pool[i])
        return transaction_pool
    outputs.append(load_bench_file("transaction_pool.json", loading_func))

    return outputs

def write_blockchain_file(blockchain:dreamveil.Blockchain):
    with open(APPLICATION_PATH + f"\\bench\\blockchain.json", "w") as blockchain_file:
        blockchain_file.write(blockchain.dumps())

def write_peer_pool_file(peer_pool:dict):
    with open(APPLICATION_PATH + "\\bench\\peer_pool.json", "w") as peer_pool_file:
        peer_pool_file.write(json.dumps(peer_pool))

def write_transaction_pool_file(transaction_pool:list):
    output = []
    for i in range(len(transaction_pool)):
        output[i] = dreamveil.Transaction.dumps(transaction_pool[i])
    with open(APPLICATION_PATH + "\\bench\\transaction_pool.json", "w") as transaction_pool_file:
        transaction_pool_file.write(json.dumps(output))

def write_config_file(application_config):
    with open(APPLICATION_PATH + "\\node.cfg", "w") as cfg_file:
        application_config["SERVER"]["difficulty_target"] = str(int(math.log2(int(application_config["SERVER"]["difficulty_target"]))))
        cfg_file.write(application_config)

def try_read_user_file(passphrase:str, username:str):
    with open(APPLICATION_PATH + f"\\bench\\users\\{username}", "rb") as user_file:
        try:
            user_file_contents = user_file.read()
            user_file_contents = dreamshield.decrypt(passphrase, user_file_contents)
            user_data = json.loads(user_file_contents)
            user_data["key"] = RSA.import_key(user_data["key"])
            user_data["balance"] = dreamveil.to_decimal(user_data["balance"])
            return user_data
        except (ValueError, json.JSONDecodeError):
            return None

def write_user_file(passphrase:str, user_data:dict):
    with open(APPLICATION_PATH + f"\\bench\\users\\{user_data['username']}", "wb") as user_file:
        try:
            user_file_contents = user_data.copy()
            user_file_contents["key"] = user_file_contents["key"].export_key('PEM').decode()
            user_file_contents["balance"] = str(user_file_contents["balance"])
            user_file_contents = json.dumps(user_file_contents)
            user_file_contents = dreamshield.encrypt(passphrase, user_file_contents)
            user_file.write(user_file_contents)
            del user_file_contents
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