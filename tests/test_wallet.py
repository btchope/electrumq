# -*- coding: utf-8 -*-
from unittest import TestCase

from tornado.testing import AsyncTestCase

from electrumq.net.manager import NetWorkManager
from electrumq.utils.configuration import dirs
from electrumq.wallet import BaseWallet, WalletConfig
from electrumq.wallet.single import SimpleWallet

__author__ = 'zhouqi'


class HowToUseWallet(AsyncTestCase):
    def setUp(self):
        super(HowToUseWallet, self).setUp()

    def tearDown(self):
        super(HowToUseWallet, self).tearDown()

class TestWalletSync(TestCase):
    def test_base_wallet(self):
        network = NetWorkManager()
        network.start()
        wallet = SimpleWallet(WalletConfig(store_path=dirs.user_data_dir + '/' + '00.json'))
        wallet.sync()

