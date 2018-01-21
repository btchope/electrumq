# -*- coding: utf-8 -*-

from electrumq.db.sqlite.tx import TxStore
from electrumq.secret.key_store import load_keystore
from electrumq.utils.base58 import public_key_to_p2pkh
from electrumq.wallet.base import BaseWallet

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

    def pubkeys_to_address(self, pubkey):
        return public_key_to_p2pkh(pubkey.decode('hex'))

    def get_public_key(self, address):
        return self.keystore.pub_key


class WatchOnlyHDWallet(BaseWallet):
    pass
