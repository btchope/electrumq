# -*- coding: utf-8 -*-
import signal
import sys
import traceback


__author__ = 'zhouqi'


if __name__ == '__main__':
    #a
    try:
        aa
        print "hello world"
    except Exception:
        sys.exit(1)

