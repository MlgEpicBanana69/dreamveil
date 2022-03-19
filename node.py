import dreamveil

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow
import sys

from my_server import Server
import configparser

application_config = configparser.ConfigParser()
application_config.read("node.cfg")
VERSION = application_config["METADATA"]["version"]

server = Server(VERSION, application_config["SERVER"]["address"])

p = server.connect("192.168.1.36")
p.send("hello")

def window():
    node_app = QApplication(sys.argv)
    node_window = QMainWindow()
    node_window.setGeometry(650, 200, 1100, 650)
    node_window.setWindowTitle("Dreamveil")

    node_window.show()
    sys.exit(node_app.exec_())

window()
