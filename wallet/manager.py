# -*- coding: utf-8 -*-
import logging
import ConfigParser
from functools import partial

from blockchain import BlockChain
from db.sqlite import init
from network import NetWorkManager
from utils import Singleton
from utils.parameter import set_testnet
from wallet import WalletConfig, EVENT_QUEUE
from wallet.single import SimpleWallet

__author__ = 'zhouqi'

conf_path = 'electrumq.conf'

class Wallet(object):
    __metaclass__ = Singleton

    def __init__(self):
        set_testnet()
        logging.config.fileConfig('logging.conf')
        init()
        network = NetWorkManager()
        network.start_ioloop()
        BlockChain().init_header()
        network.start_client()

        # todo: init from config
        self.conf = ConfigParser.ConfigParser()
        self.conf.read(conf_path)
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

    def new_wallet(self, wallet_name, wallet_type, wallet_config_file):
        self.wallet_dict[wallet_name] = self._init_wallet(wallet_type, wallet_config_file)
        self.conf.set("wallet", "wallet_name_" + wallet_name, wallet_config_file)
        self.conf.set("wallet", "wallet_type_" + wallet_name, wallet_type)
        self.conf.write(open(conf_path, "w"))
        if len(self.new_wallet_event) > 0:
            global EVENT_QUEUE
            for event in self.new_wallet_event:
                EVENT_QUEUE.put(partial(event, wallet_name))
        return self.wallet_dict[wallet_name]

    def change_current_wallet(self, idx):
        if idx < len(self.wallet_dict.keys()):
            self.current_wallet = self.wallet_dict[self.wallet_dict.keys()[idx]]
            global EVENT_QUEUE
            if len(self.current_wallet_changed_event) > 0:
                for event in self.current_wallet_changed_event:
                    EVENT_QUEUE.put(event)

    new_wallet_event = []
    current_wallet_changed_event = []

    '''
    wallet need show
    1. wallet name
    2. display address
    3. balance 
    4. tx  (tx_hash, tx_time, tx_delta for hole wallet)
    '''

