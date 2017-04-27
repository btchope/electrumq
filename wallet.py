# -*- coding: utf-8 -*-
from tornado import gen

from blockchain import BlockChain
from db.mem.tx import Transaction
from db.sqlite.tx import TxStore
from message.blockchain.address import GetHistory
from message.blockchain.transaction import GetMerkle, Get
from network import NetWorkManager

__author__ = 'zhouqi'


class BaseWallet():

    def __init__(self):
        pass


class SimpleWallet(BaseWallet):
    _address = None

    def __init__(self, address):
        BaseWallet.__init__(self)
        self._address = address

    def init(self):
        NetWorkManager().client.add_message(GetHistory([self._address]), self.history_callback)

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
            print self._address, 'balance', TxStore().get_balance(self._address)
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return



class HDWallet(BaseWallet):
    pass


class WatchOnlySimpleWallet(BaseWallet):
    pass


class WatchOnlyHDWallet(BaseWallet):
    pass
