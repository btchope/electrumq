# -*- coding: utf-8 -*-
import logging
import os
from functools import partial

import qrcode
import signal

import sys
from PyQt4 import QtCore
from PyQt4.QtCore import QDateTime, QDate, QTime, QTimer
from PyQt4.QtGui import *
from datetime import datetime

from UI.component import AccountIcon, AddressView, BalanceView, \
    FuncList, TxFilterView, TxTableView, SendView, Image, QRDialog, MainAddressView
from UI.dialog import NewAccountDialog, TxDetailDialog
from UI.layout.borderlayout import BorderLayout
from db.sqlite import init
from network import NetWorkManager
from utils.configuration import style_path
from utils.parameter import TYPE_ADDRESS
from wallet import WalletConfig
from wallet.manager import Wallet
from wallet.single import SimpleWallet
from wallet import EVENT_QUEUE

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
    def __init__(self, List, *__args):
        super(EQApplication, self).__init__(List, *__args)

        self.timer = QTimer()
        self.timer.start(50)  # You may change this if you wish.
        self.timer.timeout.connect(self.ui_loop)

    def ui_loop(self):
        global EVENT_QUEUE
        while not EVENT_QUEUE.empty():
            EVENT_QUEUE.get()()


class EQMainWindow(QMainWindow):
    def __init__(self, **kwargs):
        super(EQMainWindow, self).__init__()
        self.view = MainController()
        self.view.setContentsMargins(0, 0, 0, 0)
        self.setObjectName(_fromUtf8("MainWindow"))
        self.resize(*DEFAULT_MAIN_SIZE)
        self.setCentralWidget(self.view)


class MainController(QWidget):
    def __init__(self):
        super(MainController, self).__init__()
        # !!! note: !!!
        # Because BorderLayout doesn't call its super-class addWidget() it
        # doesn't take ownership of the widgets until setLayout() is called.
        # Therefore we keep a local reference to each label to prevent it being
        # garbage collected too soon.
        self.widget = QWidget(self)
        bg_layout = QVBoxLayout(self)
        bg_layout.setMargin(0)
        bg_layout.addWidget(self.widget)

        layout = BorderLayout()
        self.account_ctr = AccountController()
        layout.addWidget(self.account_ctr, BorderLayout.West)

        self.nav_ctr = NavController()
        self.nav_ctr.parent_controller = self
        self.nav_ctr.init_event()
        layout.addWidget(self.nav_ctr, BorderLayout.West)

        self.detail_ctr = DetailController()
        layout.addWidget(self.detail_ctr, BorderLayout.Center)

        self.widget.setLayout(layout)
        self.setWindowTitle("ElectrumQ")

        self.widget.setStyleSheet(open('UI/main.style').read())

    def show_tab(self):
        self.detail_ctr.show_tab()
        print 'show tab'

    def show_receive(self):
        self.detail_ctr.show_receive()
        print 'show receive'

    def show_send(self):
        self.detail_ctr.show_send()
        print 'show send'


class AccountController(QWidget):
    def __init__(self):
        super(AccountController, self).__init__()

        self.widget = QWidget(self)
        bg_layout = QVBoxLayout(self)
        bg_layout.setMargin(0)
        bg_layout.addWidget(self.widget)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 50, 0, 50)
        accounts = Wallet().wallet_dict.keys()
        is_first = True
        for account in accounts:
            btn = AccountIcon(account)
            btn.setChecked(is_first)
            is_first = False
            layout.addWidget(btn)
            btn.clicked.connect(partial(self.switch_account, btn))

        self.current_account_idx = 0

        self.add_account_btn = QPushButton()
        self.add_account_btn.setText(u'新建')
        self.add_account_btn.setProperty('class', 'addAccount QPushButton')
        self.add_account_btn.clicked.connect(self.add_account)
        layout.addWidget(self.add_account_btn)

        layout.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.widget.setLayout(layout)
        self.account_layout = layout

        Wallet().new_wallet_event.append(self.add_wallet)

    def switch_account(self, btn):
        this_idx = self.layout().indexOf(btn)
        if self.current_account_idx != this_idx:
            Wallet().change_current_wallet(this_idx)
            self.current_account_idx = this_idx

    def add_account(self, account_name=''):
        tabdialog = NewAccountDialog()
        tabdialog.exec_()

    def add_wallet(self, wallet_name):
        btn = AccountIcon(wallet_name)
        self.account_layout.insertWidget(self.account_layout.count() - 2, btn)
        btn.setChecked(True)


class NavController(QWidget):
    def __init__(self):
        super(NavController, self).__init__()

        self.widget = QWidget(self)
        bg_layout = QVBoxLayout(self)
        bg_layout.setMargin(0)
        bg_layout.addWidget(self.widget)

        self.parent_controller = None
        layout = QVBoxLayout()

        addressDesc = QLabel(u"我的地址")
        addressDesc.setProperty('class', 'addressDesc QLabel')
        layout.addWidget(addressDesc)
        self.address_view = MainAddressView()
        layout.addWidget(self.address_view)
        # layout.setContentsMargins(20, 0, 20, 0)

        balanceDesc = QLabel(u"余额")
        balanceDesc.setProperty('class', 'balanceDesc QLabel')
        layout.addWidget(balanceDesc)
        self.balance_view = BalanceView()
        layout.addWidget(self.balance_view)
        self.func_list = FuncList()
        layout.addWidget(self.func_list)
        layout.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.widget.setLayout(layout)

        self.tx_log_btn = self.func_list.tx_log_btn
        self.tx_log_btn.setChecked(True)
        self.receive_btn = self.func_list.receive_btn
        self.send_btn = self.func_list.send_btn

        self.show()
        if Wallet().current_wallet is not None:
            Wallet().current_wallet.wallet_tx_changed_event.append(self.show)
            Wallet().current_wallet_changed_event.append(self.show)

    def init_event(self):
        self.tx_log_btn.clicked.connect(self.parent_controller.show_tab)
        self.receive_btn.clicked.connect(self.parent_controller.show_receive)
        self.send_btn.clicked.connect(self.parent_controller.show_send)

    def show(self):
        super(NavController, self).show()
        if Wallet().current_wallet is not None:
            self.address_view.set_address(Wallet().current_wallet.address)
            self.balance_view.set_blance(Wallet().current_wallet.balance)


class DetailController(QWidget):
    def __init__(self):
        super(DetailController, self).__init__()

        self.widget = QWidget(self)
        bg_layout = QVBoxLayout(self)
        bg_layout.setMargin(0)
        bg_layout.addWidget(self.widget)

        layout = QVBoxLayout()
        self.tab_ctr = TabController()
        self.send_ctr = SendController()
        self.receive_ctl = ReceiveController()
        layout.addWidget(self.tab_ctr)
        layout.addWidget(self.send_ctr)
        layout.addWidget(self.receive_ctl)
        self.ctl_list = [self.tab_ctr, self.send_ctr, self.receive_ctl]
        for c in self.ctl_list:
            c.setVisible(False)
        self.show_ctl(self.tab_ctr)
        self.widget.setLayout(layout)

    def show_ctl(self, ctl):
        for c in self.ctl_list:
            if c is not ctl and c.isVisible():
                c.setVisible(False)
        if not ctl.isVisible():
            ctl.setVisible(True)

    def show_tab(self):
        self.show_ctl(self.tab_ctr)
        print 'show tab'

    def show_receive(self):
        self.show_ctl(self.receive_ctl)
        print 'show receive'

    def show_send(self):
        self.show_ctl(self.send_ctr)
        print 'show send'


class TabController(QWidget):
    def __init__(self):
        super(TabController, self).__init__()
        layout = QVBoxLayout()
        layout.setMargin(0)
        layout.addWidget(TxFilterView())

        self.tx_table_view = TxTableView([])
        layout.addWidget(self.tx_table_view)
        self.update_data_source()
        self.setLayout(layout)
        if Wallet().current_wallet is not None:
            Wallet().current_wallet.wallet_tx_changed_event.append(self.update_data_source)
            Wallet().current_wallet_changed_event.append(self.update_data_source)

    def dt_to_qdt(self, dt):
        array = datetime.fromtimestamp(float(dt)).timetuple()
        return QDateTime(QDate(*array[:3]), QTime(*array[3:6]))

    def update_data_source(self):
        if Wallet().current_wallet is not None:
            txs = Wallet().current_wallet.get_txs()
            data_source = [[e['tx_hash'], self.dt_to_qdt(e['tx_time']), e['tx_delta']] for e in txs]
            self.tx_table_view.data_source = data_source
            self.tx_table_view.reload()


class SendController(QWidget):
    def __init__(self):
        super(SendController, self).__init__()
        layout = QVBoxLayout()
        self.send_view = SendView()
        layout.addWidget(self.send_view)
        self.setLayout(layout)

        self.send_view.send_btn.clicked.connect(self.send)
        self.send_view.dest_address_tb.setText('mkp8FGgySzhh5mmmHDcxRxmeS3X5fXm68i')

    def send(self):
        outputs = [(TYPE_ADDRESS, 'mkp8FGgySzhh5mmmHDcxRxmeS3X5fXm68i', 100000)]
        tx = Wallet().current_wallet.make_unsigned_transaction(Wallet().current_wallet.get_utxo(),
                                                               outputs, {})
        Wallet().current_wallet.sign_transaction(tx, None)
        tx_detail_dialog = TxDetailDialog(self)
        tx_detail_dialog.tx_detail_view.show_tx(tx)
        tx_detail_dialog.exec_()


class ReceiveController(QWidget):
    def __init__(self):
        super(ReceiveController, self).__init__()

        if Wallet().current_wallet is not None:
            self.address = Wallet().current_wallet.address  # 'mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj'
        else:
            self.address = ''
        layout = QVBoxLayout()

        self.addressTB = QTextEdit()
        self.addressTB.setMaximumHeight(20)
        self.addressTB.setMaximumWidth(300)
        self.addressTB.setText(self.address)
        layout.addWidget(self.addressTB)

        self.qrcode = QLabel(self)
        self.qrcode.setMaximumWidth(300)
        self.qrcode.setMaximumHeight(300)
        self.qrcode.setProperty('class', 'bigQRCode QLabel')
        layout.addWidget(self.qrcode)
        self.qrcode.setPixmap(
            qrcode.make(self.address, image_factory=Image, box_size=8).pixmap())
        layout.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.setLayout(layout)

        Wallet().current_wallet_changed_event.append(self.update_address)

    def update_address(self):
        self.address = Wallet().current_wallet.address
        self.addressTB.setText(self.address)
        self.qrcode.setPixmap(
            qrcode.make(self.address, image_factory=Image, box_size=8).pixmap())
