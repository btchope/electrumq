# -*- coding: utf-8 -*-
import unittest
from logging.config import fileConfig

import time

from tornado import gen
from tornado.concurrent import is_future
from tornado.testing import gen_test, AsyncTestCase

from electrumq.ioloop import IOLoop
from electrumq.network import NetWorkManager, RPCClient
from electrumq.utils.parameter import set_testnet

__author__ = 'zhouqi'


# def test_network():
#     set_testnet()
#     fileConfig('logging.conf')
#     network_manager = NetWorkManager()
#     network_manager.start_ioloop()
#     network_manager.start_client()


class MyTestCase(AsyncTestCase):
    @gen_test
    def test_http_fetch(self):
        set_testnet()
        rpclient = RPCClient(self.io_loop)
        response = yield rpclient.connect2()
        self.assertEqual(response, False)
        # client = AsyncHTTPClient(self.io_loop)
        # response = yield client.fetch("http://www.tornadoweb.org")
        # # Test contents of response
        # self.assertIn("FriendFeed", response.body)


# if __name__ == '__main__':
#     test_network()
#
#     time.sleep(10000000)

class TestIOLoopStartAndStop(unittest.TestCase):
    def test_ioloop(self):
        NetWorkManager().start_ioloop()
        self.assertIsNotNone(NetWorkManager().ioloop)
        NetWorkManager().quit()
        # time.sleep(2)
        NetWorkManager().start_ioloop()
        self.assertIsNotNone(NetWorkManager().ioloop)
        NetWorkManager().quit()


class TestIOLoop(unittest.TestCase):
    def setUp(self):
        self.ioloop = IOLoop()
        self.ioloop.start()
        self.ioloop_wait = self.ioloop.loop_interval / 1000.0 + 0.01

    def tearDown(self):
        self.ioloop.quit()
        time.sleep(self.ioloop.loop_quit_wait)

    def test_timeout(self):
        now = time.time()
        global is_done
        is_done = False
        delta = 1

        def timeout():
            global is_done
            is_done = True

        self.ioloop.add_timeout(now + delta, timeout)
        self.assertFalse(is_done)
        time.sleep(delta + self.ioloop_wait)
        self.assertTrue(is_done)

    def test_future(self):
        global is_done, cnt
        is_done = False
        cnt = 0

        def add():
            yield
            time.sleep(0.1)
            global cnt
            cnt += 1

        def callback(future):
            global is_done
            is_done = True

        self.ioloop.add_future(gen.coroutine(add)(), callback)
        self.assertEqual(cnt, 0)
        self.assertEqual(is_done, False)
        time.sleep(self.ioloop_wait)
        self.assertEqual(cnt, 1)
        self.assertEqual(is_done, True)

    def test_future_without_callback(self):
        global cnt
        cnt = 0

        def add():
            yield
            time.sleep(0.1)
            global cnt
            cnt += 1

        self.ioloop.add_future(gen.coroutine(add)())
        self.assertEqual(cnt, 0)
        time.sleep(self.ioloop_wait)
        self.assertEqual(cnt, 1)
