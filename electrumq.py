# -*- coding: utf-8 -*-
import signal
import sys
import traceback

from electrumq.UI.controller import EQApplication, EQMainWindow
from electrumq.network.manager import NetWorkManager

__author__ = 'zhouqi'


if __name__ == '__main__':
    try:

        app = EQApplication(sys.argv)
        main = EQMainWindow()
        main.raise_()
        main.show()
        main.activateWindow()
        #这个关闭 app 的信号处理函数，如果发现退出命令就退出函数
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
