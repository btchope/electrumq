# -*- coding: utf-8 -*-
import os
import random

from PyQt4.QtCore import QString, Qt, QDateTime, QDate, QTime
from PyQt4.QtGui import *

import pyperclip
from electrumq.db.sqlite.tx import TxStore
from electrumq.secret.key import public_key_from_private_key, \
    SecretToASecret, ASecretToSecret, pw_decode
from electrumq.secret.key_store import SimpleKeyStore
from electrumq.engine.engine import Engine
import time

__author__ = 'zhouqi'


class NewAccountDialog(QDialog):
    def __init__(self, parent=None):
        super(NewAccountDialog, self).__init__(parent)

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(SimpleWalletTab(), "Simple Wallet")
        self.tab_widget.addTab(HDWalletTab(), "HD Wallet")
        self.tab_widget.addTab(ImportWalletTab(), 'Import Wallet')
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tab_widget)
        main_layout.addWidget(button_box)
        self.setLayout(main_layout)

        self.setWindowTitle("New Account")

    def accept(self):
        # wallet_id = str(len(Wallet().wallet_dict.keys())) + str(random.randint(0,9))
        wallet_id = str(Engine().get_next_wallet_id())
        wallet = Engine().init_wallet('simple', wallet_id + '.json')
        s = self.tab_widget.currentWidget().get_secret()
        secret = s.decode('hex')
        pwd_dig = PasswordDialog()
        pwd_dig.exec_()
        pwd = pwd_dig.password()
        if pwd is None or len(pwd) == 0:
            self.close()
        else:
            wallet.init_key_store(
                SimpleKeyStore.create(SecretToASecret(secret, True), pwd))
            wallet.sync()
            Engine().new_wallet(wallet_id, 'simple', wallet_id + '.json', wallet)
            self.close()


class PasswordDialog(QDialog):
    def __init__(self, parent=None):
        super(PasswordDialog, self).__init__(parent)
        self._password = None
        pwd_label = QLabel("Password:")
        self.tip_label = QLabel('')
        self.tip_label.setStyleSheet("color:rgb(255,0,0)")
        self.pwd_edit = QLineEdit('')
        self.pwd_edit.setMinimumWidth(50)
        self.pwd_edit.setMaxLength(20)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        button_box.accepted.connect(self.a)
        button_box.rejected.connect(self.r)

        # self.connect(button_box, SIGNAL('accepted()'), self, SLOT("accept()"))
        # self.connect(button_box, SIGNAL('rejected()'), self, SLOT("reject()"))

        self.main_layout = QVBoxLayout()
        self.main_layout.addWidget(pwd_label)
        self.main_layout.addWidget(self.tip_label)
        self.main_layout.addWidget(self.pwd_edit)
        self.main_layout.addWidget(button_box)
        self.main_layout.addStretch(1)
        self.setLayout(self.main_layout)
        self.setWindowTitle("Password")

    def password(self):
        return self._password

    def a(self):
        self._password = str(self.pwd_edit.text())
        if len(self._password) < 6:
            self.tip_label.setFont(QFont("Roman times", 10, QFont.Bold))
            self.tip_label.setText(u'密码位数不够')
        else:
            isright = Engine().check_password(self._password)
            if not isright:
                self.tip_label.setText(u'密码不对')
            else:
                self.close()

    def r(self):
        self._password = None
        self.close()


class SimpleWalletTab(QWidget):
    def __init__(self, parent=None):
        super(SimpleWalletTab, self).__init__(parent)

        random_label = QLabel("Random:")
        prikey = os.urandom(32).encode('hex')
        self.random_edit = QLineEdit(prikey)
        self.random_edit.setMinimumWidth(500)
        self.random_edit.setEnabled(False)
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


class ImportWalletTab(QWidget):
    def __init__(self, parent=None):
        super(ImportWalletTab, self).__init__(parent)

        random_label = QLabel(u"私钥")
        self.random_edit = QLineEdit('')
        self.random_edit.setMinimumWidth(500)

        superGroup = QGroupBox(u"高级")

        self.haspwd = QCheckBox(u"有密码")
        self.haspwd.setChecked(True)

        self.pwd_edit = QLineEdit('')

        superLayout = QHBoxLayout()
        superLayout.addWidget(self.haspwd)
        superLayout.addWidget(self.pwd_edit)
        superGroup.setLayout(superLayout)

        mainLayout = QVBoxLayout()
        mainLayout.addWidget(random_label)
        mainLayout.addWidget(self.random_edit)
        mainLayout.addWidget(superGroup)
        mainLayout.addStretch(1)
        self.setLayout(mainLayout)

    def get_secret(self):
        prikey = str(self.random_edit.text())
        if self.haspwd.isChecked():
            pwd = str(self.pwd_edit.text())
            prikey = pw_decode(prikey, password=pwd)
        sercet = ASecretToSecret(prikey)

        if sercet:
            return str(sercet.encode('hex'))
        raise Exception('Error sercet')


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
    def __init__(self, parent=None, need_send=True):
        super(TxDetailDialog, self).__init__(parent)

        self.tx_detail_view = TxDetailView()

        if need_send:
            button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

            button_box.accepted.connect(self.accept)
            button_box.rejected.connect(self.reject)
        else:
            button_box = QDialogButtonBox(QDialogButtonBox.Ok)
            button_box.accepted.connect(self.close)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tx_detail_view)
        main_layout.addWidget(button_box)
        self.setLayout(main_layout)

        self.setWindowTitle("Transaction Detail")

    def accept(self):
        TxStore().add_unconfirm_tx(self.tx_detail_view.tx)
        Engine().current_wallet.broadcast(self.tx_detail_view.tx)
        self.close()


class TxDetailView(QWidget):
    def __init__(self):
        super(TxDetailView, self).__init__()
        main_layout = QVBoxLayout()
        # self.tx_hash = QLabel()
        self.tx_time = QLabel()
        main_layout.addWidget(self.tx_time)
        line = LineLabel()
        main_layout.addWidget(line)
        self.tip0 = QLabel(u'交易id')
        main_layout.addWidget(self.tip0)
        self.tx_hash = HashLabel()
        main_layout.addWidget(self.tx_hash)
        self.tip1 = QLabel(u'交易源信息')
        main_layout.addWidget(self.tip1)
        self.in_group = QGroupBox()
        self.in_layout = QGridLayout()
        self.in_group.setLayout(self.in_layout)
        main_layout.addWidget(self.in_group)
        self.tip2 = QLabel(u'交易目的信息')
        main_layout.addWidget(self.tip2)
        self.out_group = QGroupBox()
        self.out_layout = QGridLayout()
        self.out_group.setLayout(self.out_layout)
        main_layout.addWidget(self.out_group)
        main_layout.setMargin(1)
        main_layout.setSpacing(1)
        self.setLayout(main_layout)

    def show_tx(self, tx):
        self.tx = tx
        self.tx_time.setText(self.dt_to_time(tx.tx_time))
        for idx, each_in in enumerate(tx.input_list()):
            if each_in.in_address is not None:
                in_address = HashLabel(each_in.in_address)
            else:
                in_address = HashLabel('---')

            self.in_layout.addWidget(in_address, idx, 0, 1, 3)
            if each_in.in_value is not None:
                in_value = QLabel(u'%f' % (each_in.in_value * 1.0 / 100000000,))
            else:
                in_value = QLabel('---')
            self.in_layout.addWidget(in_value, idx, 3)
        for idx, each_out in enumerate(tx.output_list()):
            out_address = HashLabel(each_out.out_address)
            self.out_layout.addWidget(out_address, idx, 0, 1, 3)
            out_value = QLabel(u'%f' % (each_out.out_value * 1.0 / 100000000,))
            self.out_layout.addWidget(out_value, idx, 3)
        self.tx_hash.setText(tx.tx_hash)

    def dt_to_time(self, dt):
        loacl_time = time.localtime(dt)
        return time.strftime("%Y-%m-%d %H:%M:%S", loacl_time)


class HashLabel(QLabel):
    def __init__(self, parent=None):
        super(HashLabel, self).__init__()
        super(HashLabel, self).setAlignment(Qt.AlignLeft)
        super(HashLabel, self).setWordWrap(True)
        if parent is not None:
            self._value = parent
            self.setText(parent)
        else:
            self._value = None

    def mousePressEvent(self, e):
        value = self._value
        if value is not None and len(value) > 0:
            pyperclip.copy(value)

    def setText(self, text):
        self._value = text
        result = ''
        for i in range(len(text)):
            result += text[i]
            if i % 4 == 3:
                result += '  '
        result = result.strip()
        super(HashLabel, self).setText(result)


class LineLabel(QLabel):
    def __init__(self, height=1):
        super(LineLabel, self).__init__()
        super(LineLabel, self).setFixedHeight(height)
