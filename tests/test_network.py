# -*- coding: utf-8 -*-
from logging.config import fileConfig

import time

from tornado.testing import gen_test, AsyncTestCase

from network import NetWorkManager, RPCClient
from utils.parameter import set_testnet

__author__ = 'zhouqi'


def test_network():
    set_testnet()
    fileConfig('logging.conf')
    network_manager = NetWorkManager()
    network_manager.start_ioloop()
    network_manager.start_client()


if __name__ == '__main__':
    test_network()

    time.sleep(10000000)