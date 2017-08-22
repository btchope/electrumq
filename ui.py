# -*- coding: utf-8 -*-
import sys

import logging

import signal
import traceback

from PyQt4.QtCore import QTimer

from UI import controller
from UI.controller import EQApplication, EQMainWindow
from db.sqlite import init
from network import NetWorkManager
from wallet import WalletConfig
from wallet.single import SimpleWallet
from wallet import EVENT_QUEUE

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

        app.exec_()
    except (KeyboardInterrupt, SystemExit):
        app.exit()
    except Exception as ex:
        print ex
        traceback.print_stack()
    finally:
        NetWorkManager().quit()
        sys.exit()
