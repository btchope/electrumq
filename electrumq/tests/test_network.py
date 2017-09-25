# -*- coding: utf-8 -*-
import unittest
from logging.config import fileConfig

import time

from tornado import gen
from tornado.concurrent import is_future
from tornado.testing import gen_test, AsyncTestCase

from electrumq.ioloop import IOLoop
from electrumq.network import RPCClient
from electrumq.net.manager import NetWorkManager
from electrumq.utils.parameter import set_testnet

__author__ = 'zhouqi'


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


class TestIOLoopStartAndStop(unittest.TestCase):
    def test_ioloop(self):
        ioloop = IOLoop()
        ioloop.start()
        self.assertTrue(ioloop.isAlive())
        ioloop.quit()
        time.sleep(ioloop.loop_quit_wait)
        self.assertFalse(ioloop.isAlive())
        ioloop = IOLoop()
        ioloop.start()
        self.assertTrue(ioloop.isAlive())
        ioloop.quit()
        time.sleep(ioloop.loop_quit_wait)
        self.assertFalse(ioloop.isAlive())


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


class FakeTcpServer():
    pass