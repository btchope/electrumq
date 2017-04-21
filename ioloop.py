# -*- coding: utf-8 -*-
import threading

import signal

import logging

import time
from tornado.ioloop import IOLoop as TornadoIOLoop, PeriodicCallback

__author__ = 'zhouqi'


logger = logging.getLogger('ioloop')

MAX_WAIT_SECONDS_BEFORE_SHUTDOWN = 1

class IOLoop(threading.Thread):

    _features = []

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        logger.debug('ioloop starting')
        def add_features():
            if not self._features:
                pass
            else:
                need_add = self._features[:]
                self._features = []
                for each in need_add:
                    TornadoIOLoop.instance().add_future(each[0], each[1])

        PeriodicCallback(add_features, 1000, TornadoIOLoop.instance()).start()
        TornadoIOLoop.instance().start()

    def add_feature(self, feature, callback=None):
        def nothing(**kwargs):
            pass
        if callback is None:
            callback = nothing
        self._features.append((feature, callback))


    def add_periodic(self, feature, interval=1000):
        PeriodicCallback(feature, interval, TornadoIOLoop.instance()).start()

    def quit(self):
        logger.info('begin to quit')
        TornadoIOLoop.instance().add_callback(self.shutdown)

    def shutdown(self):
        """

        :return:
        """
        logger.info('Will shutdown in %s seconds ...', MAX_WAIT_SECONDS_BEFORE_SHUTDOWN)
        io_loop = TornadoIOLoop.instance()

        deadline = time.time() + MAX_WAIT_SECONDS_BEFORE_SHUTDOWN

        def stop_loop():
            """

            :return:
            """
            now = time.time()
            if now < deadline and (io_loop._callbacks or len(io_loop._timeouts) > 1):
                io_loop.add_timeout(now + 1, stop_loop)
            else:
                io_loop.stop()
                logger.info('Shutdown')

        stop_loop()