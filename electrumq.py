# -*- coding: utf-8 -*-
import signal
import sys
import traceback

from electrumq.UI.controller import EQApplication, EQMainWindow
from electrumq.network.manager import NetWorkManager
from electrumq.UI.component import FinalIcon
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
        app.setWindowIcon(FinalIcon())
        app.exec_()
    except (KeyboardInterrupt, SystemExit):
        app.exit()
    except Exception as ex:
        print ex
        traceback.print_exc()
    finally:
        NetWorkManager().quit()
        sys.exit()
