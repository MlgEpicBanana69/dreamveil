import dreamveil

from my_server import Server
import configparser
import ipaddress

# Function: Broadcast transaction json to all connected peers
# Param: transaction_json
def SENDTX(param):
    transaction_json = str(param)
    sent_transaction = dreamveil.Transaction.loads(transaction_json)

# Function: Attempt to add the given block to the chain
# Param: block_json
def SENDBK(param):
    block_json = str(param)
    sent_block = dreamveil.Block.loads(block_json)

# Function: Broadcasts to peers that you've attempted to chain a block
# Param: Block height
def YELLBK(param):
    block_height = int(param)

# Function: Ask for a block of certain height to be sent to commander
# Param: Block height
def GIVEBK(param):
    block_height = int(param)
# Function: Register the following peers in the peer pool
# Param: p1_addr,p2_addr,p3_addr...pn_addr
def FRIEND(param):
    peers = param.split(',')

# Function: Ask for a list of peers in the network
# Param: commander_addr
def LONELY(param):
    param = str(param)
    assert ipaddress.IPv4Address(param)
    server.broadcast("LONELY" + param, [param])

application_config = configparser.ConfigParser()
application_config.read("node.cfg")
VERSION = application_config["METADATA"]["version"]

server = Server(VERSION, application_config["SERVER"]["address"], [SENDBK, ])

for p in server.peers.values():
    p.send("hello")


