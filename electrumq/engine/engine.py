# -*- coding: utf-8 -*-
import logging
import os
from ConfigParser import RawConfigParser, NoOptionError
from functools import partial

import sys
from logging.config import fileConfig

from appdirs import AppDirs
from sortedcontainers import SortedDict

from electrumq.blockchain.chain import BlockChain
from electrumq.db.sqlite import init
from electrumq.network.manager import NetWorkManager
from electrumq.utils import Singleton
from electrumq.utils.configuration import log_conf_path, conf_path, dirs
from electrumq.utils.parameter import set_testnet
from electrumq.wallet.base import EVENT_QUEUE, WalletConfig
from electrumq.wallet.single import SimpleWallet
from electrumq.secret.key import pw_encode, pw_decode, InvalidPassword

import json

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


class Engine(object):
    __metaclass__ = Singleton

    def __init__(self):
        set_testnet()
        fileConfig(log_conf_path)
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
                self.wallet_dict[wallet_name].sync()

        self._current = self.conf.get('wallet', 'current')
        if self._current is not None:
            self.current_wallet = self.wallet_dict[self._current]
            self.current_wallet.sync()
        else:
            self.current_wallet = None

        self._rate = 0.0
        self.refresh_rate()

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
            return int(next_wallet_id)
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

    def check_password(self, password):
        cmsg = self.conf.get('wallet', 'encrypt_msg')
        new_msg = pw_encode('This is a test Message.', password)
        if cmsg is None:
            self.conf.set('wallet', 'encrypt_msg', new_msg)
            return True
        else:
            try:
                msg = pw_decode(cmsg, password)
            except InvalidPassword:
                return False
            if msg == 'This is a test Message.':
                self.conf.set('wallet', 'encrypt_msg', new_msg)
                return True
            else:
                return False

    new_wallet_event = []
    current_wallet_changed_event = []

    def get_btc2rmb_rate(self):
        self.refresh_rate()
        return self._rate

    def set_btc2rmb_rate(self, future):
        try:
            response = future.result()
            msg = json.loads(response)
            if 'isSuc' in msg and msg['isSuc']:
                if 'datas' in msg and 'ticker' in msg['datas']:
                    if 'buy' in msg['datas']['ticker']:
                        self._rate = msg['datas']['ticker']['buy']
        except Exception as ex:
            print ex.message

    def refresh_rate(self):
        url = 'https://www.btc123.com/api/getTicker?symbol=okcoinbtcusd'
        NetWorkManager().http_request(url=url, method='GET', callback=self.set_btc2rmb_rate)

    '''
    wallet need show
    1. wallet name
    2. display address
    3. balance 
    4. tx  (tx_hash, tx_time, tx_delta for hole wallet)
    '''
