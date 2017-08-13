# -*- coding: utf-8 -*-
import logging
import ConfigParser

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

        # todo: init from config
        self.conf = ConfigParser.ConfigParser()
        self.conf.read("electrumq.conf")
        self.wallet_dict = {}
        for k,v in self.conf.items('wallet'):
            if k.startswith('wallet_name_'):
                wallet_name = k[12:]
                wallet_type = self.conf.get('wallet','wallet_type_' + wallet_name)
                wallet_config_file = v#self.conf.get('wallet', k)
                self.wallet_dict[wallet_name] = self._init_wallet(wallet_type, wallet_config_file)
        self._current = self.conf.get('wallet','current')
        self.current_wallet = self.wallet_dict[self._current]
        self.current_wallet.init()

    def _init_wallet(self, wallet_type, wallet_config_file):
        if wallet_type == 'simple':
            return SimpleWallet(WalletConfig(store_path=wallet_config_file))
        return None
    '''
    wallet need show
    1. wallet name
    2. display address
    3. balance 
    4. tx  (tx_hash, tx_time, tx_delta for hole wallet)
    '''

