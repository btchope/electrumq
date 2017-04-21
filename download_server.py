# -*- coding: utf-8 -*-
import gzip
import sys

__author__ = 'zhouqi'

import logging
import os
import signal
import time

from tornado import ioloop
from tornado import web
from tornado.httpserver import HTTPServer

__author__ = 'zhouqi'

MAX_WAIT_SECONDS_BEFORE_SHUTDOWN = 3


class BaseApp(object):
    def __init__(self, port=8888, routings=None, debug=True, gzip=False):
        if routings is None:
            routings = []

        self.port = port
        self.debug = debug
        self.gzip = gzip
        self.server = None
        self.routings = routings

    def sig_handler(self, sig, frame):
        """

        :param sig:
        :param frame:
        :return:
        """
        logging.warning('Caught signal: %s', sig)
        ioloop.IOLoop.instance().add_callback(self.shutdown)

    def shutdown(self):
        """

        :return:
        """
        logging.info('Stopping http server')
        self.server.stop()

        logging.info('Will shutdown in %s seconds ...', MAX_WAIT_SECONDS_BEFORE_SHUTDOWN)
        io_loop = ioloop.IOLoop.instance()

        deadline = time.time() + MAX_WAIT_SECONDS_BEFORE_SHUTDOWN

        def stop_loop():
            """

            :return:
            """
            now = time.time()
            if now < deadline and (io_loop._callbacks or io_loop._timeouts):
                io_loop.add_timeout(now + 1, stop_loop)
            else:
                io_loop.stop()
                logging.info('Shutdown')

        stop_loop()

    def start(self):
        """

        :param port:
        :return:
        """
        pid_file = '%d.pid' % self.port

        if self.debug or not os.path.exists(pid_file):
            with open(pid_file, 'w') as f:
                f.write(str(os.getpid()))
            try:
                self.prepare()
                self.application = web.Application(self.routings, debug=self.debug, gzip=self.gzip)
                self.server = HTTPServer(self.application)
                self.server.listen(self.port)

                signal.signal(signal.SIGTERM, self.sig_handler)
                signal.signal(signal.SIGINT, self.sig_handler)

                ioloop.IOLoop.instance().start()
                print 'exit...'
            except Exception as ex:
                print ex, ex.message
            finally:
                os.remove(pid_file)
        else:
            print 'pid file exists'


    def prepare(self):
        pass


class Api(BaseApp):
    pass


routings = [
    (r"/files/(.*)", web.StaticFileHandler, {"path": "files"}),

]

print '\n'.join([e[0] for e in routings])

if __name__ == '__main__':
    if len(sys.argv) == 2:
        port = int(sys.argv[1])
    else:
        port = int(8866)
    app = Api(port=port, routings=routings, debug=True)
    app.start()