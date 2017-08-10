# -*- coding: utf-8 -*-
import sys

import logging

from UI import controller
from UI.controller import EQApplication, EQMainWindow
from db.sqlite import init
from network import NetWorkManager
from wallet import WalletConfig
from wallet.single import SimpleWallet

__author__ = 'zhouqi'


if __name__ == '__main__':

    app = EQApplication(sys.argv)
    main = EQMainWindow()
    main.show()
    sys.exit(app.exec_())
