import dreamveil


from my_server import Server
import configparser

application_config = configparser.ConfigParser()
application_config.read("node.cfg")
VERSION = application_config["METADATA"]["version"]

server = Server(VERSION, application_config["SERVER"]["address"])

p = server.connect("192.168.1.36")
p.send("hello")


