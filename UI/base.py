# -*- coding: utf-8 -*-
from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import QRect, QSize, Qt

from PyQt4.QtGui import QApplication, QWidget, QDesktopWidget, QMessageBox, QFont
from PyQt4.QtGui import *

from UI.component import AccountList, NavList, TxList
from UI.layout.borderlayout import BorderLayout

__author__ = 'zhouqi'

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QApplication.UnicodeUTF8


    def _translate(context, text, disambig):
        return QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QApplication.translate(context, text, disambig)

DEFAULT_FONT = QFont('SansSerif', 10)
DEFAULT_TITLE = 'ElectrumQ'
DEFAULT_MAIN_SIZE = (800, 600)


class EQApplication(QApplication):
    pass


class EQMainWindow(QMainWindow):
    def __init__(self, **kwargs):
        # QWidget.__init__(self, **kwargs)
        super(EQMainWindow, self).__init__()
        self.init()

    def init(self):
        self.main = Window()
        self.setObjectName(_fromUtf8("MainWindow"))
        self.resize(*DEFAULT_MAIN_SIZE)
        self.setCentralWidget(self.main)

        # sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.MinimumExpanding,
        #                                QtGui.QSizePolicy.Preferred)
        # sizePolicy.setHorizontalStretch(0)
        # sizePolicy.setVerticalStretch(0)
        # sizePolicy.setHeightForWidth(self.sizePolicy().hasHeightForWidth())
        # self.setSizePolicy(sizePolicy)
        # self.centralwidget = QtGui.QWidget(self)
        # self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        #
        # self.horizontalLayoutWidget = QtGui.QWidget(self.centralwidget)
        # self.horizontalLayoutWidget.setGeometry(QtCore.QRect(0, 0, 800, 600))
        # self.horizontalLayoutWidget.setObjectName(_fromUtf8("horizontalLayoutWidget"))
        # self.horizontalLayout = QtGui.QHBoxLayout(self.horizontalLayoutWidget)
        # self.horizontalLayout.setSizeConstraint(QtGui.QLayout.SetDefaultConstraint)
        # self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        #
        # # account
        # self.account = QtGui.QWidget(self.horizontalLayoutWidget)
        # sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Preferred)
        # sizePolicy.setHorizontalStretch(0)
        # sizePolicy.setVerticalStretch(0)
        # sizePolicy.setHeightForWidth(self.account.sizePolicy().hasHeightForWidth())
        # self.account.setSizePolicy(sizePolicy)
        # self.account.setMinimumSize(QtCore.QSize(120, 0))
        # self.account.setMaximumSize(QtCore.QSize(120, 16777215))
        # self.account.setBaseSize(QtCore.QSize(120, 0))
        # self.account.setStyleSheet("background-color: red")
        # # self.account.setToolTipDuration(-1)
        # self.account.setObjectName(_fromUtf8("account"))
        # self.horizontalLayout.addWidget(self.account)
        #
        # self.verticalLayoutWidget = QtGui.QWidget(self.account)
        # self.verticalLayoutWidget.setGeometry(QtCore.QRect(0, 0, 120, 221))
        # self.verticalLayoutWidget.setObjectName(_fromUtf8("verticalLayoutWidget"))
        # self.verticalLayout = QtGui.QVBoxLayout(self.verticalLayoutWidget)
        # self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        # spacerItem = QtGui.QSpacerItem(0, 20, QtGui.QSizePolicy.Minimum,
        #                                QtGui.QSizePolicy.Maximum)
        # self.verticalLayout.addItem(spacerItem)
        # self.pushButton = QtGui.QPushButton(self.verticalLayoutWidget)
        # self.pushButton.setMinimumSize(QtCore.QSize(50, 50))
        # self.pushButton.setObjectName(_fromUtf8("pushButton"))
        # self.verticalLayout.addWidget(self.pushButton)
        # spacerItem = QtGui.QSpacerItem(0, 20, QtGui.QSizePolicy.Minimum,
        #                                QtGui.QSizePolicy.Maximum)
        # self.verticalLayout.addItem(spacerItem)
        # self.pushButton_2 = QtGui.QPushButton(self.verticalLayoutWidget)
        # self.pushButton_2.setMinimumSize(QtCore.QSize(50, 50))
        # self.pushButton_2.setObjectName(_fromUtf8("pushButton_2"))
        # self.verticalLayout.addWidget(self.pushButton_2)
        # spacerItem = QtGui.QSpacerItem(0, 20, QtGui.QSizePolicy.Minimum,
        #                                QtGui.QSizePolicy.Maximum)
        # self.verticalLayout.addItem(spacerItem)
        #
        # # nav
        # self.nav = QtGui.QWidget(self.horizontalLayoutWidget)
        # sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Preferred)
        # sizePolicy.setHorizontalStretch(0)
        # sizePolicy.setVerticalStretch(0)
        # sizePolicy.setHeightForWidth(self.nav.sizePolicy().hasHeightForWidth())
        # self.nav.setSizePolicy(sizePolicy)
        # self.nav.setMinimumSize(QtCore.QSize(120, 0))
        # self.nav.setMaximumSize(QtCore.QSize(120, 16777215))
        # self.nav.setBaseSize(QtCore.QSize(120, 0))
        # self.nav.setObjectName(_fromUtf8("nav"))
        # self.horizontalLayout.addWidget(self.nav)
        #
        # # tab
        # self.tab = QtGui.QWidget(self.horizontalLayoutWidget)
        # self.tab.setObjectName(_fromUtf8("tab"))
        # self.horizontalLayout.addWidget(self.tab)
        #
        # # self.horizontalLayoutWidget.raise_()
        # # self.nav.raise_()
        # # self.nav.raise_()
        # # self.tab.raise_()
        # # self.verticalLayoutWidget.raise_()
        #
        # # self.tab.raise_()
        # # self.account.raise_()
        # # self.nav.raise_()
        # self.setCentralWidget(self.centralwidget)
        #
        # # menu
        # self.menubar = QtGui.QMenuBar(self)
        # self.menubar.setGeometry(QtCore.QRect(0, 0, 717, 22))
        # self.menubar.setObjectName(_fromUtf8("menubar"))
        # self.menu = QtGui.QMenu(self.menubar)
        # self.menu.setObjectName(_fromUtf8("menu"))
        # self.setMenuBar(self.menubar)
        # self.statusbar = QtGui.QStatusBar(self)
        # self.statusbar.setObjectName(_fromUtf8("statusbar"))
        # self.setStatusBar(self.statusbar)
        # self.sample_action = QtGui.QAction(self)
        # self.sample_action.setObjectName(_fromUtf8("action1"))
        # self.menu.addSeparator()
        # self.menu.addAction(self.sample_action)
        # self.menubar.addAction(self.menu.menuAction())
        #
        # self.retranslateUi()
        # QtCore.QMetaObject.connectSlotsByName(self)


    # def retranslateUi(self):
    #     self.setWindowTitle(_translate("MainWindow", "MainWindow", None))
    #     self.pushButton.setText(_translate("MainWindow", "PushButton", None))
    #     self.pushButton_2.setText(_translate("MainWindow", "PushButton", None))
    #     self.menu.setTitle(_translate("MainWindow", "哈哈", None))
    #     self.sample_action.setText(_translate("MainWindow", "1", None))


class Window(QWidget):
    def __init__(self):
        super(Window, self).__init__()
        # !!! note: !!!
        # Because BorderLayout doesn't call its super-class addWidget() it
        # doesn't take ownership of the widgets until setLayout() is called.
        # Therefore we keep a local reference to each label to prevent it being
        # garbage collected too soon.

        layout = BorderLayout()

        centralWidget = TxList()
        # centralWidget.setPlainText("tab")
        layout.addWidget(centralWidget, BorderLayout.Center)


        label_w1 = AccountList()#self.createLabel("Account")
        layout.addWidget(label_w1, BorderLayout.West)

        label_w = NavList()
        layout.addWidget(label_w, BorderLayout.West)

        self.setLayout(layout)
        self.setWindowTitle("ElectrumQ")

    def createLabel(self, text):
        label = QLabel(text)
        label.setFrameStyle(QFrame.Box | QFrame.Raised)

        return label







class MainFrame(QWidget):
    def __init__(self):
        QWidget.__init__(self)
        self.init_ui()

    def init_ui(self):
        self.setBaseSize(*DEFAULT_MAIN_SIZE)
        self.setWindowTitle(DEFAULT_TITLE)
        self.center()

        left_layout = QVBoxLayout(self)

        qbtn = QPushButton('Quit', self)
        qbtn.resize(qbtn.sizeHint())
        left_layout.addChildWidget(qbtn)

        # left_layout.addItem(qbtn)

        self.show()

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Message', "Are you sure to quit?", QMessageBox.Yes |
                                     QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()
