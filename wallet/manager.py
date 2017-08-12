# -*- coding: utf-8 -*-
import logging

from blockchain import BlockChain
from db.sqlite import init
from network import NetWorkManager
from utils import Singleton
from utils.parameter import set_testnet
from wallet import WalletConfig
from wallet.single import SimpleWallet

__author__ = 'zhouqi'


class Wallet(object):
    __metaclass__ = Singleton

    def __init__(self):
        set_testnet()
        logging.config.fileConfig('logging.conf')
        init()
        network = NetWorkManager()
        # BlockChain().init_header()
        network.start_ioloop()
        network.start_client()

        # hot_wallet = SimpleWallet(WalletConfig(store_path='watch_only_simple_wallet.json'))
        # hot_wallet.init()
        # todo: init from config
        self.current_wallet = SimpleWallet(WalletConfig(store_path='watch_only_simple_wallet.json'))
        self.current_wallet.init()

    '''
    wallet need show
    1. wallet name
    2. display address
    3. balance 
    4. tx  (tx_hash, tx_time, tx_delta for hole wallet)
    '''

