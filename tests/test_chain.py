# -*- coding: utf-8 -*-
from unittest import TestCase

from tornado import gen
from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from electrumq.chain.chain import BlockChain, BLOCK_INTERVAL
from electrumq.db.sqlite.block import BlockStore
from electrumq.net.ioloop import MAX_WAIT_SECONDS_BEFORE_SHUTDOWN
from electrumq.net.manager import NetWorkManager
from electrumq.utils.parameter import set_testnet
from tests.test_network import open_logger

__author__ = 'zhouqi'


class HowToUseChain(AsyncTestCase):
    def setUp(self):
        super(HowToUseChain, self).setUp()
        self.manager = NetWorkManager()
        self.manager.start()

    def tearDown(self):
        self.manager.quit()
        self.wait_quit()
        super(HowToUseChain, self).tearDown()

    @gen_test()
    def wait_quit(self):
        yield gen.sleep(MAX_WAIT_SECONDS_BEFORE_SHUTDOWN + 0.01)

    def test_application(self):
        bc = BlockChain()
        future = Future()
        future.set_result(open('../files/testnet_headers').read())
        bc.init_header_callback(future)


open_logger('blockstore')


class TestBockStore(TestCase):
    def test_connect_chunk(self):
        set_testnet()
        data = open('../files/testnet_headers').read()
        idx = 0
        BlockStore().connect_chunk(idx,
                                   data[idx * 80 * BLOCK_INTERVAL: (idx + 1) * 80 * BLOCK_INTERVAL])

    def test_connect_raw_header(self):
        set_testnet()
        data = open('../files/testnet_headers').read()
        idx = 0
        BlockStore().connect_chunk(idx,
                                   data[idx * 80 * BLOCK_INTERVAL: (idx + 1) * 80 * BLOCK_INTERVAL])
        idx = 1
        for i in xrange(BLOCK_INTERVAL - 1):
            BlockStore().connect_raw_header(data[idx * 80 * BLOCK_INTERVAL + i * 80: (
                                                                                     idx + 1) * 80 * BLOCK_INTERVAL + i * 80 + 80],
                                            idx * BLOCK_INTERVAL + i)
