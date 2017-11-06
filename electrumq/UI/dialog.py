# -*- coding: utf-8 -*-
import os
import random

from PyQt4.QtCore import QFileInfo, QString
from PyQt4.QtGui import *

from electrumq.db.sqlite.tx import TxStore
from electrumq.utils.key import public_key_from_private_key, SecretToASecret
from electrumq.utils.key_store import SimpleKeyStore
from electrumq.wallet.manager import Wallet

__author__ = 'zhouqi'


class NewAccountDialog(QDialog):
    def __init__(self, parent=None):
        super(NewAccountDialog, self).__init__(parent)

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(SimpleWalletTab(), "Simple Wallet")
        self.tab_widget.addTab(HDWalletTab(), "HD Wallet")

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tab_widget)
        main_layout.addWidget(button_box)
        self.setLayout(main_layout)

        self.setWindowTitle("New Account")

    def accept(self):
        wallet_id = str(len(Wallet().wallet_dict.keys())) + str(random.randint(0,9))
        wallet = Wallet().init_wallet('simple', wallet_id + '.json')
        s = self.tab_widget.currentWidget().get_secret()
        secret = s.decode('hex')
        wallet.init_key_store(
            SimpleKeyStore.create(SecretToASecret(secret, True), None))
        wallet.sync()
        Wallet().new_wallet(wallet_id, 'simple', wallet_id + '.json', wallet)
        self.close()


class SimpleWalletTab(QWidget):
    def __init__(self, parent=None):
        super(SimpleWalletTab, self).__init__(parent)

        random_label = QLabel("Random:")
        self.random_edit = QLineEdit('2012100909090909090909090909090909090909090909090909090909090909')
        self.random_edit.setMinimumWidth(500)

        self.random_btn = QPushButton('random again')
        self.random_btn.clicked.connect(self.random)

        mainLayout = QVBoxLayout()
        mainLayout.addWidget(random_label)
        mainLayout.addWidget(self.random_edit)
        mainLayout.addWidget(self.random_btn)
        mainLayout.addStretch(1)
        self.setLayout(mainLayout)

    def get_secret(self):
        qs = QString()

        return str(self.random_edit.text())

    def random(self):
        self.random_edit.setText(os.urandom(32).encode('hex'))


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


class TxDetailDialog(QDialog):
    def __init__(self, parent=None):
        super(TxDetailDialog, self).__init__(parent)

        self.tx_detail_view = TxDetailView()

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tx_detail_view)
        main_layout.addWidget(button_box)
        self.setLayout(main_layout)

        self.setWindowTitle("Transaction Detail")

    def accept(self):
        self.tx_detail_view.tx._inputs = None
        self.tx_detail_view.tx.deserialize()
        TxStore().add_unconfirm_tx(self.tx_detail_view.tx)
        # Wallet().current_wallet.broadcast(self.tx_detail_view.tx)
        self.close()


class TxDetailView(QWidget):
    def __init__(self):
        super(TxDetailView, self).__init__()
        main_layout = QHBoxLayout()
        self.tx_hash = QLabel()
        main_layout.addWidget(self.tx_hash)
        self.in_group = QGroupBox("Inputs")
        self.in_layout = QGridLayout()
        self.in_group.setLayout(self.in_layout)
        main_layout.addWidget(self.in_group)

        self.out_group = QGroupBox("Outputs")
        self.out_layout = QGridLayout()
        self.out_group.setLayout(self.out_layout)
        main_layout.addWidget(self.out_group)
        self.setLayout(main_layout)

    def show_tx(self, tx):
        self.tx = tx
        for idx, each_in in enumerate(tx.input_list()):
            in_address = QLabel(each_in.in_address)
            self.in_layout.addWidget(in_address, idx, 0)
            in_value = QLabel(str(each_in.in_value))
            self.in_layout.addWidget(in_value, idx, 1)
        for idx, each_out in enumerate(tx.output_list()):
            out_address = QLabel(each_out.out_address)
            self.out_layout.addWidget(out_address, idx, 0)
            out_value = QLabel(str(each_out.out_value))
            self.out_layout.addWidget(out_value, idx, 1)
        # self.tx_hash.setText(tx['tx_hash'])