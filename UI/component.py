# -*- coding: utf-8 -*-
from PyQt4.QtCore import QDateTime, QDate, QTime, Qt
from PyQt4.QtGui import QVBoxLayout, QPushButton, QSpacerItem, QSizePolicy, QWidget, QHBoxLayout, \
    QTextEdit, QLabel, QFrame, QTreeView, QStandardItemModel

__author__ = 'zhouqi'


class AccountIcon(QPushButton):
    def __init__(self, account_name):
        super(AccountIcon, self).__init__()
        self.setFixedSize(50, 50)
        self.setText(account_name)


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
        self.qr_btn = QPushButton()
        self.qr_btn.setMaximumWidth(80)
        self.qr_btn.setMaximumHeight(20)
        self.qr_btn.setText("qr")
        layout.addWidget(self.qr_btn)

        self.setLayout(layout)

        self.setMaximumHeight(60)

        self.qr_btn.clicked.connect(self.show_qr)

    def set_address(self, address):
        self.address = address
        self.addressTB.setText(self.address)
        self.update()

    def show_qr(self):
        dialog = QRDialog(parent=self, address=self.address)
        if dialog.exec_():
            pass

        dialog.destroy()


class BalanceView(QWidget):
    def __init__(self):
        super(BalanceView, self).__init__()
        layout = QVBoxLayout()
        self.btc_balance_label = QLabel(u"余额：100 BTC")
        self.btc_balance_label.setFrameStyle(QFrame.Shadow_Mask)
        layout.addWidget(self.btc_balance_label)
        fiat_balance_label = QLabel(u"余额：2,100,000 RMB")
        fiat_balance_label.setFrameStyle(QFrame.Shadow_Mask)
        layout.addWidget(fiat_balance_label)
        self.setLayout(layout)

    def set_blance(self, balance):
        self.btc_balance_label.setText(u'余额: %f BTC' % (balance * 1.0 / 100000000,))
        self.update()


class FuncList(QWidget):
    def __init__(self):
        super(FuncList, self).__init__()

        layout = QVBoxLayout()
        self.tx_log_btn = FuncView(u'交易记录')
        layout.addWidget(self.tx_log_btn)
        self.receive_btn = FuncView(u'收币')
        layout.addWidget(self.receive_btn)
        self.send_btn = FuncView(u'发币')
        layout.addWidget(self.send_btn)
        self.setLayout(layout)


class FuncView(QPushButton):
    def __init__(self, func_name):
        super(FuncView, self).__init__()
        self.setText(func_name)
        self.setMaximumWidth(80)


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


class TableView(QWidget):
    def __init__(self, data_source):
        super(TableView, self).__init__()

        self.data_source = data_source
        layout = QVBoxLayout()
        self.sourceView = QTreeView()
        self.sourceView.setRootIsDecorated(False)
        self.sourceView.setAlternatingRowColors(True)
        layout.addWidget(self.sourceView)
        self.reload()
        self.setLayout(layout)

    def reload(self):
        if len(self.data_source) > 0:
            self.data_model = QStandardItemModel(0, len(self.data_source[0]), self)
            self.sourceView.setModel(self.data_model)
            self.draw_header()
            for row in self.data_source:
                self.draw_row(row)
            self.update()
        else:
            pass

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
        dest_address_tb = QTextEdit()
        dest_address_tb.setMaximumWidth(160)
        layout.addWidget(dest_address_tb)

        self.send_btn = FuncView(u'发送')
        layout.addWidget(self.send_btn)

        self.qrcode = QLabel(self)
        layout.addWidget(self.qrcode)
        self.setLayout(layout)

        self.qrcode.setPixmap(
            qrcode.make('mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj', image_factory=Image).pixmap())


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