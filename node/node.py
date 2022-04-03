import dreamveil

from server import Server
import configparser
import ipaddress
import os
import secrets

def load_state():
    with open("state\\blockchain.json", "w+") as f:
        try:
            contents = f.read()
            if contents == "":
                f.write("[]")
            blockchain = dreamveil.Blockchain.loads(contents)
        except ValueError as err:
            print("!!! Could not loads blockchain from state")
            print(err)
            if os.path.isfile("state\\blockchain.json"):
                os.rename("state\\blockchain.json", f"state\\backup\\blockchain{secrets.token_hex(8)}.old")



# Function: Broadcast transaction json to all connected peers
# Param: Transaction json
def SENDTX(ctx, param):
    sent_transaction = dreamveil.Transaction.loads(param)

# Function: Attempt to add the given block to the chain
# Param: block_json
def SENDBK(ctx, param):
    sent_block = dreamveil.Block.loads(param)

# Function: Broadcasts to peers that you've attempted to chain a block
# Param: Block height
def YELLBK(ctx, param):
    pass
# Function: Ask for a block of certain height to be sent to commander
# Param: Block height
def GIVEBK(ctx, param):
    pass
# Function: Register the following peers in the peer pool
# Param: p1_addr,p2_addr,p3_addr...pn_addr
def FRIEND(ctx, param):
    pass
# Function: Ask for a list of peers in the network
# Param: commander_addr
def LONELY(ctx, param):
    server.broadcast("LONELY" + param, [ctx, param])

application_config = configparser.ConfigParser()
application_config.read("node.cfg")
VERSION = application_config["METADATA"]["version"]




server = Server(VERSION, application_config["SERVER"]["address"], [SENDBK, ])

for p in server.peers.values():
    p.send("hello")


