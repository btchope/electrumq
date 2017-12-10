# -*- coding: utf-8 -*-
import threading
import time

from tornado.ioloop import IOLoop as TornadoIOLoop, PeriodicCallback

from electrumq.network import logger

__author__ = 'zhouqi'

MAX_WAIT_SECONDS_BEFORE_SHUTDOWN = 0.1

class IOLoop(threading.Thread):
    _futures = []
    loop_interval = 100  # ms
    loop_quit_wait = MAX_WAIT_SECONDS_BEFORE_SHUTDOWN  # second

    def __init__(self):
        threading.Thread.__init__(self)
        self.ioloop = TornadoIOLoop()

    def run(self):
        logger.debug('ioloop starting')

        def add_features():
            if not self._futures:
                pass
            else:
                need_add = self._futures[:]
                self._futures = []
                for each in need_add:
                    self.ioloop.add_future(each[0], each[1])

        PeriodicCallback(add_features, self.loop_interval, self.ioloop).start()
        self.ioloop.start()

    def add_future(self, future, callback=None):
        def nothing(future, **kwargs):
            pass

        if callback is None:
            callback = nothing
        # else:
        #     feature.add_done_callback(callback)
        self._futures.append((future, callback))

    def add_periodic(self, feature, interval=1000):
        if self.ioloop._timeouts is None:
            self.ioloop._timeouts = []
        PeriodicCallback(feature, interval, self.ioloop).start()

    def add_timeout(self, deadline, callback, *args, **kwargs):
        self.ioloop.add_timeout(deadline, callback, *args, **kwargs)

    def time(self):
        return self.ioloop.time()

    def quit(self):
        logger.info('begin to quit')
        self.ioloop.add_callback(self._quit)

    def _quit(self):
        """

        :return:
        """
        logger.info('Will shutdown in %s seconds ...', MAX_WAIT_SECONDS_BEFORE_SHUTDOWN)
        io_loop = self.ioloop

        deadline = time.time() + MAX_WAIT_SECONDS_BEFORE_SHUTDOWN

        def stop_loop():
            """

            :return:
            """
            now = time.time()
            step = 0.01
            if now < deadline and (io_loop._callbacks or len(io_loop._timeouts) > 1):
                io_loop.add_timeout(max(now + step, deadline), stop_loop)
            else:
                io_loop.stop()
                io_loop.close()
                io_loop.clear_current()
                io_loop.clear_instance()
                logger.info('Shutdown')

        stop_loop()