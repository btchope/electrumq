# -*- coding: utf-8 -*-
import logging
import os
from ConfigParser import RawConfigParser, NoOptionError
from functools import partial

import sys
from appdirs import AppDirs
from sortedcontainers import SortedDict

from electrumq.chain.chain import BlockChain
from electrumq.db.sqlite import init
from electrumq.net.manager import NetWorkManager
from electrumq.utils import Singleton
from electrumq.utils.configuration import log_conf_path, conf_path, dirs
from electrumq.utils.parameter import set_testnet
from electrumq.wallet import WalletConfig, EVENT_QUEUE
from electrumq.wallet.single import SimpleWallet

__author__ = 'zhouqi'


class MyConfigParser(RawConfigParser, object):
    file_path = None
    config_changed_event = []

    def get(self, section, option):
        try:
            return RawConfigParser.get(self, section, option)
        except NoOptionError:
            return None

    def read(self, filenames):
        super(MyConfigParser, self).read(filenames)
        self.file_path = filenames

    def save(self):
        self.write(open(conf_path, "w"))

    def set(self, section, option, value=None):
        old_value = self.get(section, option)
        super(MyConfigParser, self).set(section, option, value)
        self.save()
        global EVENT_QUEUE
        if len(self.config_changed_event) > 0:
            for event in set(self.config_changed_event):
                EVENT_QUEUE.put(partial(event, section=section, option=option, new_value=value, old_value=old_value))

    def event_handle(self, section, option, new_value, old_value):
        pass


class Wallet(object):
    __metaclass__ = Singleton

    def __init__(self):
        set_testnet()
        # logging.config.fileConfig(log_conf_path)
        init()
        network = NetWorkManager()
        network.start()
        BlockChain().init_header()

        # todo: init from config
        self.conf = MyConfigParser()
        self.conf.read(conf_path)
        self.wallet_dict = SortedDict()
        for k, v in self.conf.items('wallet'):
            if k.startswith('wallet_name_'):
                wallet_name = k[12:]
                wallet_type = self.conf.get('wallet', 'wallet_type_' + wallet_name)
                wallet_config_file = v  # self.conf.get('wallet', k)
                self.wallet_dict[wallet_name] = self.init_wallet(wallet_type, wallet_config_file)

        self._current = self.conf.get('wallet', 'current')
        if self._current is not None:
            self.current_wallet = self.wallet_dict[self._current]
            self.current_wallet.sync()
        else:
            self.current_wallet = None

    def init_wallet(self, wallet_type, wallet_config_file):
        if wallet_type == 'simple':
            return SimpleWallet(WalletConfig(store_path=dirs.user_data_dir + '/' + wallet_config_file))
        return None

    def new_wallet(self, wallet_name, wallet_type, wallet_config_file, wallet):
        self.wallet_dict[wallet_name] = wallet
        self.conf.set("wallet", "wallet_name_" + wallet_name, wallet_config_file)
        self.conf.set("wallet", "wallet_type_" + wallet_name, wallet_type)
        if self.current_wallet is None:
            self.conf.set('wallet', 'current', wallet_name)
        self.conf.set('wallet', 'next_wallet_id', self.get_next_wallet_id() + 1)
        if len(self.new_wallet_event) > 0:
            global EVENT_QUEUE
            for event in set(self.new_wallet_event):
                EVENT_QUEUE.put(partial(event, wallet_name))
        if self.current_wallet is None:
            self.change_current_wallet(0)
        return self.wallet_dict[wallet_name]

    def change_current_wallet(self, idx):
        if idx < len(self.wallet_dict.keys()):
            self.current_wallet = self.wallet_dict[self.wallet_dict.keys()[idx]]
            # todo: update current to conf
            self.conf.set('wallet', 'current', self.wallet_dict.keys()[idx])
            global EVENT_QUEUE
            if len(self.current_wallet_changed_event) > 0:
                for event in set(self.current_wallet_changed_event):
                    EVENT_QUEUE.put(partial(event, idx=idx))

    def get_next_wallet_id(self):
        try:
            next_wallet_id = self.conf.get('wallet', 'next_wallet_id')
            if next_wallet_id is None:
                self.conf.set('wallet', 'next_wallet_id', 1)
                return 1
            return next_wallet_id
        except NoOptionError as ex:
            return 1

    def get_current_wallet_idx(self):
        if self.current_wallet is None:
            return 0
        else:
            for idx, w in enumerate(self.wallet_dict.values()):
                if w == self.current_wallet:
                    return idx
            return 0


    new_wallet_event = []
    current_wallet_changed_event = []

    '''
    wallet need show
    1. wallet name
    2. display address
    3. balance 
    4. tx  (tx_hash, tx_time, tx_delta for hole wallet)
    '''
