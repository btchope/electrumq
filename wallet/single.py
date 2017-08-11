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

    def init(self):
        NetWorkManager().client.add_message(GetHistory([self.address]), self.history_callback)

    def get_receiving_addresses(self):
        return [self.address, ]

    @gen.coroutine
    def history_callback(self, msg_id, msg, param):
        for each in param:
            TxStore().add(msg['params'][0], each['tx_hash'], each['height'])
        for tx, height in TxStore().unverify_tx_list:
            NetWorkManager().client.add_message(GetMerkle([tx, height]), self.get_merkle_callback)
        for tx in TxStore().unfetch_tx:
            NetWorkManager().client.add_message(Get([tx]), self.get_tx_callback)

    @gen.coroutine
    def get_merkle_callback(self, msg_id, msg, param):
        tx_hash = msg['params'][0]
        height = msg['params'][1]
        block_root = BlockChain().get_block_root(height)
        if block_root is not None:
            result = TxStore().verify_merkle(tx_hash, param, block_root)
            if result:
                TxStore().verified_tx(tx_hash)

    @gen.coroutine
    def get_tx_callback(self, msg_id, msg, param):
        tx_hash = msg['params'][0]
        tx = Transaction(param)
        try:
            tx.deserialize()
            TxStore().add_tx_detail(tx_hash, tx)
            print self.address, 'balance', TxStore().get_balance(self.address)
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return


class WatchOnlySimpleWallet(SimpleWallet):
    pass


class ColdSimpleWallet(SimpleWallet):
    pass


class WatchOnlyHDWallet(BaseWallet):
    pass
