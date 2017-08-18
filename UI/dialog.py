# -*- coding: utf-8 -*-
from PyQt4.QtCore import QFileInfo
from PyQt4.QtGui import *

__author__ = 'zhouqi'


class NewAccountDialog(QDialog):
    def __init__(self, parent=None):
        super(NewAccountDialog, self).__init__(parent)

        tab_widget = QTabWidget()
        tab_widget.addTab(SimpleWalletTab(), "Simple Wallet")
        tab_widget.addTab(HDWalletTab(), "HD Wallet")

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.addWidget(tab_widget)
        main_layout.addWidget(button_box)
        self.setLayout(main_layout)

        self.setWindowTitle("New Account")

    def accept(self):
        print 'accept'


class SimpleWalletTab(QWidget):
    def __init__(self, parent=None):
        super(SimpleWalletTab, self).__init__(parent)

        random_label = QLabel("Random:")
        random_edit = QLineEdit('0'*64)
        random_edit.setMinimumWidth(500)

        mainLayout = QVBoxLayout()
        mainLayout.addWidget(random_label)
        mainLayout.addWidget(random_edit)
        mainLayout.addStretch(1)
        self.setLayout(mainLayout)


class HDWalletTab(QWidget):
    def __init__(self, parent=None):
        super(HDWalletTab, self).__init__(parent)

        permissionsGroup = QGroupBox("Permissions")

        readable = QCheckBox("Readable")
        readable.setChecked(True)

        writable = QCheckBox("Writable")


        executable = QCheckBox("Executable")

        ownerGroup = QGroupBox("Ownership")

        ownerLabel = QLabel("Owner")


        groupLabel = QLabel("Group")

        permissionsLayout = QVBoxLayout()
        permissionsLayout.addWidget(readable)
        permissionsLayout.addWidget(writable)
        permissionsLayout.addWidget(executable)
        permissionsGroup.setLayout(permissionsLayout)

        ownerLayout = QVBoxLayout()
        ownerLayout.addWidget(ownerLabel)

        ownerLayout.addWidget(groupLabel)

        ownerGroup.setLayout(ownerLayout)

        mainLayout = QVBoxLayout()
        mainLayout.addWidget(permissionsGroup)
        mainLayout.addWidget(ownerGroup)
        mainLayout.addStretch(1)
        self.setLayout(mainLayout)