# -*- coding: utf-8 -*-
import sys

from UI.controller import EQApplication, EQMainWindow

__author__ = 'zhouqi'


if __name__ == '__main__':
    app = EQApplication(sys.argv)
    main = EQMainWindow()
    main.show()
    sys.exit(app.exec_())
