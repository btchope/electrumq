# -*- coding: utf-8 -*-
from tornado import gen

from blockchain import BlockChain
from db.sqlite.tx import TxStore
from message.blockchain.address import GetHistory
from message.blockchain.transaction import GetMerkle, Get
from network import NetWorkManager
from utils.key_store import load_keystore
from utils.tx import Transaction
from wallet import BaseWallet

__author__ = 'zhouqi'


class SimpleWallet(BaseWallet):
    def __init__(self, wallet_config):
        BaseWallet.__init__(self, wallet_config)
        if self.storage.get('keystore', None) is not None:
            self.keystore = load_keystore(self.storage, 'keystore')

    def init_key_store(self, key_store):
        if self.keystore is not None:
            raise Exception()
        if key_store is None:
            raise Exception()
        self.keystore = key_store
        self.storage.put('keystore', self.keystore.dump())
        self.storage.write()

    @property
    def address(self):
        return self.keystore.address

    @property
    def display_address(self):
        return self.address

    @property
    def balance(self):
        return TxStore().get_balance(self.address)



    def get_receiving_addresses(self):
        return [self.address, ]




class WatchOnlySimpleWallet(SimpleWallet):
    pass


class ColdSimpleWallet(SimpleWallet):
    pass


class WatchOnlyHDWallet(BaseWallet):
    pass
