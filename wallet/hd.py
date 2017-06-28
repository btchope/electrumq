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


class HDWallet(BaseWallet):
    def __init__(self, wallet_config):
        BaseWallet.__init__(self, wallet_config)
        if self.storage.get('keystore', None) is not None:
            self.keystore = load_keystore(self.storage, 'keystore')
        self.gap_limit = self.storage.get('gap_limit', 20)

    def init_key_store(self, key_store):
        if self.keystore is not None:
            raise Exception()
        if key_store is None:
            raise Exception()
        self.keystore = key_store
        self.storage.put('keystore', self.keystore.dump())
        self.storage.write()

    def init(self):
        for address in (self.receiving_addresses + self.change_addresses):
            NetWorkManager().client.add_message(GetHistory([address]), self.history_callback)

    @gen.coroutine
    def history_callback(self, msg_id, msg, param):
        for each in param:
            TxStore().add(msg['params'][0], each['tx_hash'], each['height'])
        # for tx, height in TxStore().unverify_tx_list:
            NetWorkManager().client.add_message(GetMerkle([each['tx_hash'], each['height']]), self.get_merkle_callback)
        # for tx in TxStore().unfetch_tx:
            NetWorkManager().client.add_message(Get([each['tx_hash']]), self.get_tx_callback)

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
            # print self.address, 'balance', TxStore().get_balance(self.address)
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return

    def has_seed(self):
        return self.keystore.has_seed()

    def is_deterministic(self):
        return self.keystore.is_deterministic()

    def get_receiving_addresses(self):
        return self.receiving_addresses

    def get_change_addresses(self):
        return self.change_addresses

    def get_seed(self, password):
        return self.keystore.get_seed(password)

    def add_seed(self, seed, pw):
        self.keystore.add_seed(seed, pw)

    def change_gap_limit(self, value):
        """This method is not called in the code, it is kept for console use"""
        if value >= self.gap_limit:
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            return True
        elif value >= self.min_acceptable_gap():
            addresses = self.get_receiving_addresses()
            k = self.num_unused_trailing_addresses(addresses)
            n = len(addresses) - k + value
            self.receiving_addresses = self.receiving_addresses[0:n]
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            self.save_addresses()
            return True
        else:
            return False

    def num_unused_trailing_addresses(self, addresses):
        k = 0
        for a in addresses[::-1]:
            if self.history.get(a):
                break
            k += 1
        return k

    def min_acceptable_gap(self):
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0
        addresses = self.get_receiving_addresses()
        k = self.num_unused_trailing_addresses(addresses)
        for a in addresses[0:-k]:
            if self.history.get(a):
                n = 0
            else:
                n += 1
                if n > nmax: nmax = n
        return nmax + 1

    def create_new_address(self, for_change=False):
        assert type(for_change) is bool
        addr_list = self.change_addresses if for_change else self.receiving_addresses
        n = len(addr_list)
        x = self.derive_pubkeys(for_change, n)
        address = self.pubkeys_to_address(x)
        addr_list.append(address)
        self.save_addresses()
        self.add_address(address)
        return address

    def synchronize_sequence(self, for_change):
        limit = self.gap_limit_for_change if for_change else self.gap_limit
        while True:
            addresses = self.get_change_addresses() if for_change else self.get_receiving_addresses()
            if len(addresses) < limit:
                self.create_new_address(for_change)
                continue
            if map(lambda a: self.address_is_old(a), addresses[-limit:]) == limit * [False]:
                break
            else:
                self.create_new_address(for_change)

    def synchronize(self):
        # with self.lock:
        if self.is_deterministic():
            self.synchronize_sequence(False)
            self.synchronize_sequence(True)
        else:
            if len(self.receiving_addresses) != len(self.keystore.keypairs):
                pubkeys = self.keystore.keypairs.keys()
                self.receiving_addresses = map(self.pubkeys_to_address, pubkeys)
                self.save_addresses()
                for addr in self.receiving_addresses:
                    self.add_address(addr)

    def is_beyond_limit(self, address, is_change):
        addr_list = self.get_change_addresses() if is_change else self.get_receiving_addresses()
        i = addr_list.index(address)
        prev_addresses = addr_list[:max(0, i)]
        limit = self.gap_limit_for_change if is_change else self.gap_limit
        if len(prev_addresses) < limit:
            return False
        prev_addresses = prev_addresses[max(0, i - limit):]
        for addr in prev_addresses:
            if self.history.get(addr):
                return False
        return True

    def get_master_public_keys(self):
        return [self.get_master_public_key()]

    def get_fingerprint(self):
        return self.get_master_public_key()

    def derive_pubkeys(self, c, i):
        return self.keystore.derive_pubkey(c, i)