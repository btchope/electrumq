# -*- coding: utf-8 -*-
from PyQt4.QtCore import QDateTime, QDate, QTime, Qt
from PyQt4.QtGui import QVBoxLayout, QPushButton, QSpacerItem, QSizePolicy, QWidget, QHBoxLayout, \
    QTextEdit, QLabel, QFrame, QTreeView, QStandardItemModel

__author__ = 'zhouqi'


class AccountList(QWidget):
    def __init__(self):
        super(AccountList, self).__init__()

        layout = QVBoxLayout()
        accounts = ['btc', 'hd']
        for account in accounts:
            # button = QPushButton("Button %d" % (i + 1))
            layout.addWidget(AccountIcon(account))
        layout.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.setLayout(layout)

    def add_account(self, account_name):
        pass


class AccountIcon(QPushButton):
    def __init__(self, account_name):
        super(AccountIcon, self).__init__()
        self.setFixedSize(50, 50)
        self.setText(account_name)


class NavList(QWidget):
    def __init__(self):
        super(NavList, self).__init__()

        layout = QVBoxLayout()
        layout.addWidget(AddressView())
        layout.addWidget(BalanceView())
        layout.addWidget(FuncList())
        layout.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.setLayout(layout)

class AddressView(QWidget):
    def __init__(self):
        super(AddressView, self).__init__()
        layout = QVBoxLayout()
        addressTB = QTextEdit()
        addressTB.setMaximumHeight(40)
        addressTB.setMaximumWidth(160)
        addressTB.setText('1ZhouQKMethPQLYaQYcSsqqMNCgbNTYVm')
        # addressTB.setMinimumHeight(50)

        layout.addWidget(addressTB)
        self.setLayout(layout)
        self.setMaximumHeight(100)


class BalanceView(QWidget):
    def __init__(self):
        super(BalanceView, self).__init__()
        layout = QVBoxLayout()
        btc_balance_label = QLabel(u"余额：100 BTC")
        btc_balance_label.setFrameStyle(QFrame.Shadow_Mask)
        layout.addWidget(btc_balance_label)
        fiat_balance_label = QLabel(u"余额：2,100,000 RMB")
        fiat_balance_label.setFrameStyle(QFrame.Shadow_Mask)
        layout.addWidget(fiat_balance_label)
        self.setLayout(layout)


class FuncList(QWidget):
    def __init__(self):
        super(FuncList, self).__init__()

        layout = QVBoxLayout()
        funcs = [u'交易记录', u'收币', u'发币']
        for f in funcs:
            layout.addWidget(FuncView(f))
        self.setLayout(layout)


class FuncView(QPushButton):
    def __init__(self, func_name):
        super(FuncView, self).__init__()
        self.setText(func_name)
        self.setMaximumWidth(80)


class TxList(QWidget):
    def __init__(self):
        super(TxList, self).__init__()
        layout = QVBoxLayout()
        layout.addWidget(TxFilterView())
        layout.addWidget(TxTableView())
        self.setLayout(layout)


class TxFilterView(QWidget):
    def __init__(self):
        super(TxFilterView, self).__init__()
        layout = QHBoxLayout()
        texts = [u'查询条件1', u'查询条件2', u'查询条件3']
        for t in texts:
            label = QLabel()
            label.setText(t)
            layout.addWidget(label)
        self.setLayout(layout)


class TxTableView(QWidget):
    def __init__(self):
        super(TxTableView, self).__init__()

        layout = QVBoxLayout()
        self.sourceView = QTreeView()
        self.sourceView.setRootIsDecorated(False)
        self.sourceView.setAlternatingRowColors(True)
        model = self.create_model(self)
        self.sourceView.setModel(model)
        self.sourceView.setColumnWidth(0, 20)
        self.sourceView.setColumnWidth(1, 120)
        self.sourceView.setColumnWidth(2, 120)
        self.sourceView.setColumnWidth(3, 80)
        self.sourceView.setColumnWidth(4, 80)
        layout.addWidget(self.sourceView)
        self.setLayout(layout)


    is_verify, tx_date, tx_desc, tx_amount, tx_balance = range(5)
    def addItem(self, model, is_verify, tx_date, tx_desc, tx_amount, tx_balance):
        model.insertRow(0)
        model.setData(model.index(0, self.is_verify), is_verify)
        model.setData(model.index(0, self.tx_date), tx_date)
        model.setData(model.index(0, self.tx_desc), tx_desc)
        model.setData(model.index(0, self.tx_amount), tx_amount)
        model.setData(model.index(0, self.tx_balance), tx_balance)


    def create_model(self, parent):
        model = QStandardItemModel(0, 5, parent)

        model.setHeaderData(self.is_verify, Qt.Horizontal, "")
        model.setHeaderData(self.tx_date, Qt.Horizontal, "Date")
        model.setHeaderData(self.tx_desc, Qt.Horizontal, "Description")
        model.setHeaderData(self.tx_amount, Qt.Horizontal, "Amount")
        model.setHeaderData(self.tx_balance, Qt.Horizontal, "Balance")

        self.addItem(model, "", QDateTime(QDate(2006, 12, 31), QTime(17, 3)), '', 1000, 1000)
        self.addItem(model, "", QDateTime(QDate(2006, 12, 22), QTime(9, 44)), '', 1000, 1000)
        self.addItem(model, "", QDateTime(QDate(2006, 12, 31), QTime(12, 50)), '', 1000, 1000)
        self.addItem(model, "", QDateTime(QDate(2006, 12, 25), QTime(11, 39)), '', 1000, 1000)
        self.addItem(model, "", QDateTime(QDate(2007, 1, 2), QTime(16, 5)), '', 1000, 1000)
        self.addItem(model, "", QDateTime(QDate(2007, 1, 3), QTime(14, 18)), '', 1000, 1000)
        self.addItem(model, "", QDateTime(QDate(2007, 1, 3), QTime(14, 26)), '', 1000, 1000)
        self.addItem(model, "", QDateTime(QDate(2007, 1, 5), QTime(11, 33)), '', 1000, 1000)
        self.addItem(model, "", QDateTime(QDate(2007, 1, 5), QTime(12, 0)), '', 1000, 1000)
        self.addItem(model, "", QDateTime(QDate(2007, 1, 5), QTime(12, 1)), '', 1000, 1000)

        return model
