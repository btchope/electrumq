# -*- coding: utf-8 -*-
import sys

import logging

import signal

from PyQt4.QtCore import QTimer

from UI import controller
from UI.controller import EQApplication, EQMainWindow
from db.sqlite import init
from network import NetWorkManager
from wallet import WalletConfig
from wallet.single import SimpleWallet

__author__ = 'zhouqi'


if __name__ == '__main__':
    try:
        app = EQApplication(sys.argv)
        main = EQMainWindow()
        main.raise_()
        main.show()
        main.activateWindow()

        signal.signal(signal.SIGTERM, lambda sig, frame: app.quit())
        signal.signal(signal.SIGINT, lambda sig, frame: app.quit())

        timer = QTimer()
        timer.start(500)  # You may change this if you wish.
        timer.timeout.connect(lambda: None)

        app.exec_()
    except (KeyboardInterrupt, SystemExit):
        app.exit()
    except Exception:
        pass
    finally:
        NetWorkManager().quit()
        sys.exit()
