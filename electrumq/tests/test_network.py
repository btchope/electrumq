# -*- coding: utf-8 -*-
from logging.config import fileConfig

import time

from tornado.testing import gen_test, AsyncTestCase

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