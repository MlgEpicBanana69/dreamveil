# Form implementation generated from reading ui file 'd:\Projects\dreamveil\application.ui'
#
# Created by: PyQt6 UI code generator 6.2.3
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setWindowModality(QtCore.Qt.WindowModality.NonModal)
        MainWindow.resize(1100, 650)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(0, 610, 47, 13))
        self.label.setObjectName("label")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1100, 21))
        self.menubar.setObjectName("menubar")
        self.menuAbout = QtWidgets.QMenu(self.menubar)
        self.menuAbout.setObjectName("menuAbout")
        self.menuInternal_server = QtWidgets.QMenu(self.menubar)
        self.menuInternal_server.setObjectName("menuInternal_server")
        MainWindow.setMenuBar(self.menubar)
        self.actionStart_server = QtGui.QAction(MainWindow)
        self.actionStart_server.setObjectName("actionStart_server")
        self.actionStop_server = QtGui.QAction(MainWindow)
        self.actionStop_server.setObjectName("actionStop_server")
        self.actionConnect_to_node_manually = QtGui.QAction(MainWindow)
        self.actionConnect_to_node_manually.setObjectName("actionConnect_to_node_manually")
        self.actionDreamveil = QtGui.QAction(MainWindow)
        self.actionDreamveil.setObjectName("actionDreamveil")
        self.menuAbout.addAction(self.actionDreamveil)
        self.menuInternal_server.addAction(self.actionStart_server)
        self.menuInternal_server.addAction(self.actionStop_server)
        self.menuInternal_server.addAction(self.actionConnect_to_node_manually)
        self.menubar.addAction(self.menuAbout.menuAction())
        self.menubar.addAction(self.menuInternal_server.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Dreamveil"))
        self.label.setText(_translate("MainWindow", "TextLabel"))
        self.menuAbout.setTitle(_translate("MainWindow", "About"))
        self.menuInternal_server.setTitle(_translate("MainWindow", "Internal server"))
        self.actionStart_server.setText(_translate("MainWindow", "Start server"))
        self.actionStop_server.setText(_translate("MainWindow", "Stop server"))
        self.actionConnect_to_node_manually.setText(_translate("MainWindow", "Connect to node manually"))
        self.actionDreamveil.setText(_translate("MainWindow", "Dreamveil"))