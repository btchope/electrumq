# -*- coding: utf-8 -*-
import os
from os import path

import logging

__author__ = 'zhouqi'

reged_logger = {}


class MyLogFormatter(LogFormatter):
    converter = datetime.fromtimestamp

    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        if datefmt:
            s = ct.strftime(datefmt)
        else:
            t = ct.strftime("%Y-%m-%d %H:%M:%S")
            s = "%s,%03d" % (t, record.msecs)
        return s


def getLogger(name):
    if not name in reged_logger:
        logpath = path.abspath(path.join('log', *name.split('.')))
        if not path.exists(path.dirname(logpath)):
            os.makedirs(path.dirname(logpath))
        from logging import handlers
        handler = handlers.RotatingFileHandler(logpath, maxBytes=10000000, backupCount=10)
        handler.setFormatter(MyLogFormatter(color=False, datefmt='%y-%m-%d %H:%M:%S.%f'))
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        reged_logger[name] = logger
        return logger
    else:
        return reged_logger[name]


network_logger = getLogger('network')
ioloop_logger = getLogger('ioloop')