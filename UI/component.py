# -*- coding: utf-8 -*-
from functools import partial

import pyperclip
from PyQt4.QtCore import QDateTime, QDate, QTime, Qt
from PyQt4.QtGui import QVBoxLayout, QPushButton, QSpacerItem, QSizePolicy, QWidget, QHBoxLayout, \
    QTextEdit, QLabel, QFrame, QTreeView, QStandardItemModel, QLineEdit, QGridLayout, QTableView, \
    QItemSelectionModel

from UI import address_show_format

__author__ = 'zhouqi'


class AccountIcon(QPushButton):
    def __init__(self, account_name):
        super(AccountIcon, self).__init__()
        # self.setFixedSize(50, 50)
        self.setCheckable(True)
        self.setText(u'账户' + account_name)
        self.setProperty('class', 'accountIcon AccountIcon')


class AddressView(QWidget):
    def __init__(self):
        super(AddressView, self).__init__()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.setMargin(0)
        # layout.insertStretch(-1, 1)
        self.addressTB = QTextEdit()
        # self.addressTB.setContentsMargins(0,0,0,0)
        self.addressTB.setMaximumHeight(40)
        self.addressTB.setMaximumWidth(160)
        self.address = '1ZhouQKMethPQLYaQYcSsqqMNCgbNTYVm'
        self.addressTB.setText(self.address)

        layout.addWidget(self.addressTB)

        self.setLayout(layout)

        self.setMaximumHeight(60)

    def set_address(self, address):
        self.address = address
        self.addressTB.setText(self.address)
        self.update()


class MainAddressView(QWidget):
    def __init__(self):
        super(MainAddressView, self).__init__()
        layout = QVBoxLayout()
        layout.setMargin(0)
        layout.setSpacing(0)
        self.addressTB = QLabel()
        self.addressTB.setProperty('class', 'address QLabel')
        # self.addressTB.setMaximumHeight(40)
        # self.addressTB.setMaximumWidth(160)
        # self.address = '1Zho uQKM ethP\nQLYa QYcS sqqM\nNCgb NTYV m'
        self.address = '1Zho uQKM ethP QLYa\nQYcS sqqM NCgb NTYV\nm'
        self.addressTB.setMargin(10)
        self.addressTB.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.addressTB.setText(self.address)
        layout.addWidget(self.addressTB)

        btn_layout = QHBoxLayout()
        btn_layout.setMargin(0)
        btn_layout.setSpacing(0)
        self.qr_btn = QPushButton()
        self.qr_btn.setText(u"二维码")
        btn_layout.addWidget(self.qr_btn)

        self.clipboard_btn = QPushButton()
        self.clipboard_btn.setText(u"复制")
        btn_layout.addWidget(self.clipboard_btn)

        layout.addLayout(btn_layout)

        self.setLayout(layout)

        self.qr_btn.clicked.connect(self.show_qr)
        self.clipboard_btn.clicked.connect(self.copy_clipboard)

    def set_address(self, address):
        self.address = address
        self.addressTB.setText(address_show_format(self.address))
        self.update()

    def show_qr(self):
        dialog = QRDialog(parent=self, address=self.address)
        if dialog.exec_():
            pass

        dialog.destroy()

    def copy_clipboard(self):
        pyperclip.copy(self.address)


class BalanceView(QWidget):
    def __init__(self):
        super(BalanceView, self).__init__()
        layout = QGridLayout()
        layout.setMargin(0)
        self.btc_balance_label = QLabel(u"100")
        self.btc_balance_label.setProperty('class', 'balanceAmt QLabel')
        # self.btc_balance_label.setFrameStyle(QFrame.Shadow_Mask)
        layout.addWidget(self.btc_balance_label, 0, 0)
        self.fiat_balance_label = QLabel(u"2,100,000")
        self.fiat_balance_label.setProperty('class', 'balanceAmt QLabel')
        # self.fiat_balance_label.setFrameStyle(QFrame.Shadow_Mask)
        layout.addWidget(self.fiat_balance_label, 0, 1)

        btc_unit_label = QLabel(u'BTC')
        btc_unit_label.setProperty('class', 'balanceUnit QLabel')
        layout.addWidget(btc_unit_label, 1, 0)

        fiat_unit_label = QLabel(u'RMB')
        fiat_unit_label.setProperty('class', 'balanceUnit QLabel')
        layout.addWidget(fiat_unit_label, 1, 1)


        self.setLayout(layout)

    def set_blance(self, balance):
        self.btc_balance_label.setText(u'余额: %f BTC' % (balance * 1.0 / 100000000,))
        self.update()


class FuncList(QWidget):
    def __init__(self):
        super(FuncList, self).__init__()

        layout = QGridLayout()
        layout.setMargin(0)
        self.tx_log_btn = FuncView(u'交易记录')
        layout.addWidget(self.tx_log_btn, 0, 0)
        self.receive_btn = FuncView(u'收币')
        layout.addWidget(self.receive_btn, 1, 0)
        self.send_btn = FuncView(u'发币')
        layout.addWidget(self.send_btn, 2, 0)
        self.func_btn_list = [self.tx_log_btn, self.receive_btn, self.send_btn]
        self.setLayout(layout)

        self.tx_log_btn.clicked.connect(partial(self.clicked, self.tx_log_btn))
        self.receive_btn.clicked.connect(partial(self.clicked, self.receive_btn))
        self.send_btn.clicked.connect(partial(self.clicked, self.send_btn))

    def clicked(self, btn):
        for each in self.func_btn_list:
            each.setChecked(each is btn)


class FuncView(QPushButton):
    def __init__(self, func_name):
        super(FuncView, self).__init__()
        self.setText(func_name)
        self.setMaximumWidth(80)
        self.setCheckable(True)
        self.setProperty('class', 'navFunc FuncView')


class TxFilterView(QWidget):
    def __init__(self):
        super(TxFilterView, self).__init__()

        self.widget = QWidget(self)
        bg_layout = QVBoxLayout(self)
        bg_layout.setMargin(0)
        bg_layout.addWidget(self.widget)

        layout = QHBoxLayout()
        layout.setMargin(0)
        texts = []
        for t in texts:
            label = QLabel()
            label.setText(t)
            layout.addWidget(label)
        self.widget.setLayout(layout)


class TableView(QWidget):
    def __init__(self, data_source):
        super(TableView, self).__init__()

        self.data_source = data_source
        layout = QVBoxLayout()
        layout.setMargin(0)
        self.sourceView = QTreeView()
        self.sourceView.setRootIsDecorated(False)
        self.sourceView.setAlternatingRowColors(True)
        layout.addWidget(self.sourceView)
        self.reload()
        self.setLayout(layout)

    def reload(self):
        if len(self.data_source) > 0:
            self.data_model = QStandardItemModel(0, len(self.data_source[0]), self)
        else:
            self.data_model = QStandardItemModel(0, 3, self)
        self.sourceView.setModel(self.data_model)
        self.draw_header()
        for row in self.data_source:
            self.draw_row(row)
        self.update()
        # else:
        #     pass

    def draw_header(self):
        pass

    def draw_row(self, row):
        pass


class TxTableView(TableView):
    def __init__(self, data_source):
        super(TxTableView, self).__init__(data_source)

    def draw_header(self):
        sizes = [200, 160, 80]
        headers = [(Qt.Horizontal, "Tx"), (Qt.Horizontal, "Date"), (Qt.Horizontal, "Amount")]
        for idx, size in enumerate(sizes):
            self.sourceView.setColumnWidth(idx, size)
        for idx, (orientation, text) in enumerate(headers):
            self.data_model.setHeaderData(idx, orientation, text)

    def draw_row(self, row):
        # self.model.insertRow(0)
        self.data_model.appendRow(None)
        last_idx = self.data_model.rowCount() - 1
        for idx, val in enumerate(row):
            self.data_model.setData(self.data_model.index(last_idx, idx), val)


class SendView(QWidget):
    def __init__(self):
        super(SendView, self).__init__()

        layout = QVBoxLayout()
        dest_address_label = QLabel(u"目标地址")
        layout.addWidget(dest_address_label)
        self.dest_address_tb = QTextEdit()
        self.dest_address_tb.setMaximumWidth(300)
        self.dest_address_tb.setMaximumHeight(40)
        layout.addWidget(self.dest_address_tb)

        output_value_label = QLabel(u'发送金额')
        layout.addWidget(output_value_label)
        self.output_value_edit = QLineEdit()
        layout.addWidget(self.output_value_edit)

        self.send_btn = FuncView(u'发送')
        layout.addWidget(self.send_btn)

        layout.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))

        self.setLayout(layout)



from PyQt4 import QtGui, QtCore
import qrcode

class Image(qrcode.image.base.BaseImage):
    def __init__(self, border, width, box_size):
        self.border = border
        self.width = width
        self.box_size = box_size
        size = (width + border * 2) * box_size
        self._image = QtGui.QImage(
            size, size, QtGui.QImage.Format_RGB16)
        self._image.fill(QtCore.Qt.white)

    def pixmap(self):
        return QtGui.QPixmap.fromImage(self._image)

    def drawrect(self, row, col):
        painter = QtGui.QPainter(self._image)
        painter.fillRect(
            (col + self.border) * self.box_size,
            (row + self.border) * self.box_size,
            self.box_size, self.box_size,
            QtCore.Qt.black)

    def save(self, stream, kind=None):
        pass


class QRDialog(QtGui.QDialog):
    def __init__(self, parent=None, address=''):
        QtGui.QDialog.__init__(self, parent)
        self.resize(240, 200)

        layout = QVBoxLayout()

        self.qrcode = QLabel(self)
        layout.addWidget(self.qrcode)
        self.setLayout(layout)

        self.qrcode.setPixmap(
            qrcode.make(address, image_factory=Image).pixmap())