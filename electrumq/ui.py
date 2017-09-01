# -*- coding: utf-8 -*-
import sys

import logging

import signal
import traceback

from PyQt4.QtCore import QTimer

from electrumq.UI import controller
from electrumq.UI.controller import EQApplication, EQMainWindow
from electrumq.db.sqlite import init
from electrumq.network import NetWorkManager
from electrumq.wallet import WalletConfig
from electrumq.wallet.single import SimpleWallet
from electrumq.wallet import EVENT_QUEUE

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
        traceback.print_exc()
    finally:
        NetWorkManager().quit()
        sys.exit()
