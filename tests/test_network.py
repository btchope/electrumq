# -*- coding: utf-8 -*-
import logging
import sys
import time
import unittest

from tornado import gen
from tornado.testing import gen_test, AsyncTestCase

from electrumq.message.all import *
from electrumq.net.client import RPCClient
from electrumq.net.ioloop import IOLoop
from electrumq.utils.parameter import set_testnet

__author__ = 'zhouqi'


class MyTestCase(AsyncTestCase):
    @gen_test
    def test_http_fetch(self):
        set_testnet()
        rpclient = RPCClient(self.io_loop)
        response = yield rpclient.connect_with_future()
        self.assertEqual(response, False)
        # client = AsyncHTTPClient(self.io_loop)
        # response = yield client.fetch("http://www.tornadoweb.org")
        # # Test contents of response
        # self.assertIn("FriendFeed", response.body)


class HowToUseNetwork(AsyncTestCase):
    @gen_test
    def test_normal(self):
        self.ioloop = IOLoop()
        self.ioloop.start()
        ip = '176.25.187.3'
        port = 51001
        self.client = RPCClient(ioloop=self.ioloop, ip=ip, port=port)
        result = yield self.client.connect_with_future()
        self.assertTrue(result)

        @gen.coroutine
        def version_callback(msg_id, msg, param):
            self.is_callback = True
            self.assertEqual(msg_id, 0)
            self.assertEqual(msg, {'params': {}, 'method': 'server.version'})

        self.client.add_message(Version({}), version_callback)
        yield gen.sleep(2)

        self.ioloop.quit()
        yield gen.sleep(self.ioloop.loop_quit_wait + 0.01)


class TestIOLoopStartAndStop(unittest.TestCase):
    def test_ioloop(self):
        ioloop = IOLoop()
        time.sleep(ioloop.loop_quit_wait)
        ioloop.start()
        time.sleep(ioloop.loop_quit_wait)
        self.assertTrue(ioloop.isAlive())
        ioloop.quit()
        time.sleep(ioloop.loop_quit_wait * 2)
        self.assertFalse(ioloop.isAlive())
        ioloop = IOLoop()
        ioloop.start()
        self.assertTrue(ioloop.isAlive())
        ioloop.quit()
        time.sleep(ioloop.loop_quit_wait * 2)
        self.assertFalse(ioloop.isAlive())


class TestIOLoop(AsyncTestCase):
    def setUp(self):
        super(TestIOLoop, self).setUp()
        open_logger('network')
        open_logger('rpcclient')
        self.ioloop = IOLoop()
        self.ioloop.start()
        self.ioloop_wait = self.ioloop.loop_interval / 1000.0 + 0.01

    def tearDown(self):
        self.quit_ioloop()
        super(TestIOLoop, self).tearDown()

    @gen_test()
    def quit_ioloop(self):
        self.ioloop.quit()
        yield gen.sleep(self.ioloop.loop_quit_wait + 0.01)

    @gen_test()
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
        yield gen.sleep(delta + self.ioloop_wait)
        self.assertTrue(is_done)

    @gen_test()
    def test_future(self):
        global is_done, cnt
        is_done = False
        cnt = 0

        def add():
            yield
            # time.sleep(0.1)
            global cnt
            cnt += 1

        def callback(future):
            global is_done
            is_done = True

        self.ioloop.add_future(gen.coroutine(add)(), callback)
        self.assertEqual(cnt, 0)
        self.assertEqual(is_done, False)
        yield gen.sleep(self.ioloop_wait * 5)
        self.assertEqual(cnt, 1)
        self.assertEqual(is_done, True)

    @gen_test()
    def test_future_without_callback(self):
        global cnt
        cnt = 0

        def add():
            yield
            global cnt
            cnt += 1

        self.ioloop.add_future(gen.coroutine(add)())
        self.assertEqual(cnt, 0)
        yield gen.sleep(self.ioloop_wait)
        self.assertEqual(cnt, 1)


class TestClientConnect(AsyncTestCase):
    def __init__(self, methodName='runTest'):
        # open_logger('network')
        super(TestClientConnect, self).__init__(methodName)

    def setUp(self):
        super(TestClientConnect, self).setUp()
        self.ioloop = IOLoop()
        self.ioloop.start()
        self.ioloop_wait = self.ioloop.loop_interval / 1000.0 + 0.01

    def tearDown(self):
        print 'begin quit_ioloop'
        self.quit_ioloop()
        print 'end quit_ioloop'
        super(TestClientConnect, self).tearDown()

    @gen_test
    def quit_ioloop(self):
        self.ioloop.quit()
        yield gen.sleep(self.ioloop.loop_quit_wait + 0.01)

    @gen_test()
    def test_connect(self):
        ip = '176.25.187.3'
        port = 51001
        self.client = RPCClient(ioloop=self.ioloop, ip=ip, port=port)

        def callback(*args, **kwargs):
            print args, kwargs

        self.ioloop.add_future(self.client.connect_with_future(), callback)

        yield gen.sleep(1)

    @gen_test(timeout=30)
    def test_yield_connect(self):
        ip = '176.25.187.3'
        port = 51001
        self.client = RPCClient(ioloop=self.ioloop, ip=ip, port=port)
        result = yield self.client.connect_with_future()
        self.assertEqual(result, True)

    @gen_test(timeout=30)
    def test_yield_connect_failed(self):
        ip = '176.25.187.3'
        port = 51011
        self.client = RPCClient(ioloop=self.ioloop, ip=ip, port=port)
        result = yield self.client.connect_with_future()
        self.assertEqual(result, False)


class TestClientMessage(AsyncTestCase):
    def setUp(self):
        super(TestClientMessage, self).setUp()
        open_logger('network')
        open_logger('rpcclient')
        self.ioloop = IOLoop()
        self.ioloop.start()
        self.ioloop_wait = self.ioloop.loop_interval / 1000.0 + 0.01

    def tearDown(self):
        self.quit_ioloop()
        close_logger('network')
        close_logger('rpcclient')
        super(TestClientMessage, self).tearDown()

    @gen_test
    def quit_ioloop(self):
        self.ioloop.quit()
        yield gen.sleep(self.ioloop.loop_quit_wait + 0.01)

    @gen_test()
    def test_message(self):
        ip = '176.25.187.3'
        port = 51001
        self.client = RPCClient(ioloop=self.ioloop, ip=ip, port=port)

        result = yield self.client.connect_with_future()

        self.assertTrue(result)
        self.assertTrue(self.client.is_connected)

        self.is_callback = False

        @gen.coroutine
        def version_callback(msg_id, msg, param):
            self.is_callback = True
            self.assertEqual(msg_id, 0)
            self.assertEqual(msg, {'params': {}, 'method': 'server.version'})

        self.client.add_message(Version({}), version_callback)
        yield gen.sleep(2)
        self.assertTrue(self.is_callback)

    @gen_test()
    def test_message2(self):
        ip = '176.25.187.3'
        port = 51001
        self.client = RPCClient(ioloop=self.ioloop, ip=ip, port=port)

        result = yield self.client.connect_with_future()

        self.assertTrue(result)
        self.assertTrue(self.client.is_connected)

        self.is_callback = False

        @gen.coroutine
        def version_callback(msg_id, msg, param):
            self.is_callback = True
            self.assertEqual(msg_id, 0)
            self.assertEqual(msg, {'params': {}, 'method': 'server.version'})

        self.client.add_message(Version({}), version_callback)
        yield gen.sleep(2)
        self.assertTrue(self.is_callback)


class FakeTcpServer():
    pass


def open_logger(logger_name):
    logger = logging.getLogger(logger_name)
    logger.level = logging.DEBUG
    stream_handler = logging.StreamHandler(sys.stdout)
    logger.addHandler(stream_handler)


def close_logger(logger_name):
    logger = logging.getLogger(logger_name)
    for e in logger.handlers:
        logger.removeHandler(e)
