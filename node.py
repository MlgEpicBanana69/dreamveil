import dreamveil


from my_server import Server
import configparser

application_config = configparser.ConfigParser()
application_config.read("node.cfg")
VERSION = application_config["METADATA"]["version"]

server = Server(VERSION, application_config["SERVER"]["address"])

for p in server.peers.values():
    p.send("hello")


