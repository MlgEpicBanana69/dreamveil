# Form implementation generated from reading ui file 'd:\Projects\dreamveil\node\dreamui.ui'
#
# Created by: PyQt6 UI code generator 6.2.3
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(968, 671)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setMinimumSize(QtCore.QSize(968, 671))
        MainWindow.setMaximumSize(QtCore.QSize(968, 671))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("resources:dreamveil.ico"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setAutoFillBackground(False)
        MainWindow.setToolButtonStyle(QtCore.Qt.ToolButtonStyle.ToolButtonIconOnly)
        MainWindow.setAnimated(False)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.centralwidget.sizePolicy().hasHeightForWidth())
        self.centralwidget.setSizePolicy(sizePolicy)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(0, 0, 971, 661))
        self.tabWidget.setAutoFillBackground(True)
        self.tabWidget.setUsesScrollButtons(False)
        self.tabWidget.setTabBarAutoHide(False)
        self.tabWidget.setObjectName("tabWidget")
        self.AboutTab = QtWidgets.QWidget()
        self.AboutTab.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.NoContextMenu)
        self.AboutTab.setAccessibleName("")
        self.AboutTab.setObjectName("AboutTab")
        self.aboutBackground = QtWidgets.QLabel(self.AboutTab)
        self.aboutBackground.setGeometry(QtCore.QRect(0, 0, 971, 631))
        self.aboutBackground.setText("")
        self.aboutBackground.setPixmap(QtGui.QPixmap("resources:main page.png"))
        self.aboutBackground.setObjectName("aboutBackground")
        self.tabWidget.addTab(self.AboutTab, "")
        self.UserTab = QtWidgets.QWidget()
        self.UserTab.setObjectName("UserTab")
        self.verticalLayoutWidget = QtWidgets.QWidget(self.UserTab)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(160, 80, 621, 451))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.verticalLayoutWidget.sizePolicy().hasHeightForWidth())
        self.verticalLayoutWidget.setSizePolicy(sizePolicy)
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setSizeConstraint(QtWidgets.QLayout.SizeConstraint.SetMinAndMaxSize)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setSpacing(10)
        self.verticalLayout.setObjectName("verticalLayout")
        self.usernameLabel = QtWidgets.QLabel(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.usernameLabel.sizePolicy().hasHeightForWidth())
        self.usernameLabel.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Trajan Pro")
        font.setPointSize(30)
        self.usernameLabel.setFont(font)
        self.usernameLabel.setIndent(100)
        self.usernameLabel.setObjectName("usernameLabel")
        self.verticalLayout.addWidget(self.usernameLabel)
        self.usernameLineEdit = QtWidgets.QLineEdit(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.usernameLineEdit.sizePolicy().hasHeightForWidth())
        self.usernameLineEdit.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Perpetua")
        font.setPointSize(36)
        self.usernameLineEdit.setFont(font)
        self.usernameLineEdit.setText("")
        self.usernameLineEdit.setAlignment(QtCore.Qt.AlignmentFlag.AlignLeading|QtCore.Qt.AlignmentFlag.AlignLeft|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.usernameLineEdit.setObjectName("usernameLineEdit")
        self.verticalLayout.addWidget(self.usernameLineEdit, 0, QtCore.Qt.AlignmentFlag.AlignHCenter)
        self.passwordLabel = QtWidgets.QLabel(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.passwordLabel.sizePolicy().hasHeightForWidth())
        self.passwordLabel.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Trajan Pro")
        font.setPointSize(30)
        self.passwordLabel.setFont(font)
        self.passwordLabel.setIndent(100)
        self.passwordLabel.setObjectName("passwordLabel")
        self.verticalLayout.addWidget(self.passwordLabel)
        self.passwordLineEdit = QtWidgets.QLineEdit(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.passwordLineEdit.sizePolicy().hasHeightForWidth())
        self.passwordLineEdit.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Perpetua")
        font.setPointSize(36)
        self.passwordLineEdit.setFont(font)
        self.passwordLineEdit.setText("")
        self.passwordLineEdit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.passwordLineEdit.setAlignment(QtCore.Qt.AlignmentFlag.AlignLeading|QtCore.Qt.AlignmentFlag.AlignLeft|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.passwordLineEdit.setObjectName("passwordLineEdit")
        self.verticalLayout.addWidget(self.passwordLineEdit, 0, QtCore.Qt.AlignmentFlag.AlignHCenter)
        spacerItem = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Fixed)
        self.verticalLayout.addItem(spacerItem)
        self.loginButton = QtWidgets.QPushButton(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.loginButton.sizePolicy().hasHeightForWidth())
        self.loginButton.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Trajan Pro")
        font.setPointSize(36)
        self.loginButton.setFont(font)
        self.loginButton.setLayoutDirection(QtCore.Qt.LayoutDirection.LeftToRight)
        self.loginButton.setObjectName("loginButton")
        self.verticalLayout.addWidget(self.loginButton, 0, QtCore.Qt.AlignmentFlag.AlignHCenter)
        self.registerButton = QtWidgets.QPushButton(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.registerButton.sizePolicy().hasHeightForWidth())
        self.registerButton.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Perpetua")
        font.setPointSize(20)
        font.setItalic(False)
        self.registerButton.setFont(font)
        self.registerButton.setObjectName("registerButton")
        self.verticalLayout.addWidget(self.registerButton, 0, QtCore.Qt.AlignmentFlag.AlignHCenter)
        self.userBackground = QtWidgets.QLabel(self.UserTab)
        self.userBackground.setGeometry(QtCore.QRect(0, 0, 965, 635))
        self.userBackground.setText("")
        self.userBackground.setPixmap(QtGui.QPixmap("resources:Background.png"))
        self.userBackground.setObjectName("userBackground")
        self.userBackground.raise_()
        self.verticalLayoutWidget.raise_()
        self.tabWidget.addTab(self.UserTab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.background_3 = QtWidgets.QLabel(self.tab_2)
        self.background_3.setGeometry(QtCore.QRect(0, 0, 965, 635))
        self.background_3.setText("")
        self.background_3.setPixmap(QtGui.QPixmap("resources:Background.png"))
        self.background_3.setObjectName("background_3")
        self.tabWidget.addTab(self.tab_2, "")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Dreamveil"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.AboutTab), _translate("MainWindow", "About"))
        self.usernameLabel.setText(_translate("MainWindow", "<html><head/><body><p><span style=\" color:#ffffff;\">Username:</span></p></body></html>"))
        self.passwordLabel.setText(_translate("MainWindow", "<html><head/><body><p><span style=\" color:#ffffff;\">Password:</span></p></body></html>"))
        self.loginButton.setText(_translate("MainWindow", "   Log in   "))
        self.registerButton.setText(_translate("MainWindow", "Register"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.UserTab), _translate("MainWindow", "User"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "Tab 2"))
