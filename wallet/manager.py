# -*- coding: utf-8 -*-
from db.sqlite import init
from network import NetWorkManager
from utils import Singleton
from wallet import WalletConfig
from wallet.single import SimpleWallet

__author__ = 'zhouqi'


class Wallet(object):
    __metaclass__ = Singleton

    def __init__(self):
        init()
        network = NetWorkManager()
        network.start_ioloop()
        network.start_client()
        # hot_wallet = SimpleWallet(WalletConfig(store_path='watch_only_simple_wallet.json'))
        # hot_wallet.init()
        # todo: init from config
        self.current_wallet = SimpleWallet(WalletConfig(store_path='watch_only_simple_wallet.json'))
