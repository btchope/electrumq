# -*- coding: utf-8 -*-
import logging
import time

from tornado import gen

from electrumq.blockchain.chain import BlockChain
from electrumq.db.sqlite import init
from electrumq.db.sqlite.tx import TxStore
from electrumq.message.all import *
from electrumq.network.manager import NetWorkManager
from electrumq.utils.base58 import public_key_to_p2pkh
from electrumq.utils.key import SecretToASecret, public_key_from_private_key
from electrumq.utils.key_store import SimpleKeyStore, WatchOnlySimpleKeyStore, \
    ImportedKeyStore, from_seed, BIP32KeyHotStore
from electrumq.utils.parameter import set_testnet, TYPE_ADDRESS
from electrumq.utils.tx import Output
from electrumq.wallet.base_wallet import WalletConfig
from electrumq.wallet.hd import HDWallet, HDWatchOnlyWallet
from electrumq.wallet.single import ColdSimpleWallet, WatchOnlySimpleWallet, SimpleWallet

__author__ = 'zhouqi'


def test_simple_wallet():
    global network, hot_wallet
    set_testnet()
    keystore = ImportedKeyStore({})
    keystore = ImportedKeyStore(keystore.dump())
    pubkey = keystore.import_key(SecretToASecret('\x20\x12\x10\x09' + '\x09' * 28, True), None)
    address = public_key_to_p2pkh(pubkey.decode('hex'))
    pubkey2 = ImportedKeyStore({}).import_key(
        SecretToASecret('\x20\x14\x12\x05' + '\x09' * 28, True), None)
    address2 = public_key_to_p2pkh(pubkey2.decode('hex'))
    logging.config.fileConfig('logging.conf')
    # drop()
    init()
    network = NetWorkManager()
    network.start_ioloop()
    network.start_client()

    @gen.coroutine
    def prt1(msg_id, msg, result):
        print msg_id, msg, result
        print 'hahahaha'
        print 'hahahaha'
        print 'hahahaha'
        print 'hahahaha'

    @gen.coroutine
    def prt2(params):
        print params
        print 'hehehehe'
        print 'hehehehe'
        print 'hehehehe'
        print 'hehehehe'

    network.add_message(Version(["2.8.2", "0.10"]))
    # network.client.add_message(Banner([]))
    # network.client.add_message(DonationAddress([]))
    # network.client.add_message(peer_subscribe([]))
    #
    # network.client.add_message(address_subscribe(["1ZhouQKMethPQLYaQYcSsqqMNCgbNTYVm"]))
    # network.client.add_message(GetHistory(["1ZhouQKMethPQLYaQYcSsqqMNCgbNTYVm"]))
    # network.client.add_message(GetMempool(["1ZhouQKMethPQLYaQYcSsqqMNCgbNTYVm"]))
    # network.client.add_message(GetBalance(["1ZhouQKMethPQLYaQYcSsqqMNCgbNTYVm"]))
    # # network.client.add_message(GetProof(["1ZhouQKMethPQLYaQYcSsqqMNCgbNTYVm"])) # not implemented
    # network.client.add_message(Listunspent(["1ZhouQKMethPQLYaQYcSsqqMNCgbNTYVm"]))
    # network.client.add_message(GetAddress(["50d958904e0ab7bac04cbc7f81e27d14143306ba2ad04f3770bf36dfa388e059", 0]))
    # network.client.add_message(GetHeader([461358]))
    # network.client.add_message(GetChunk([461358 / 2016]))
    # # network.client.add_message(broadcast([]))
    # network.client.add_message(GetMerkle(["50d958904e0ab7bac04cbc7f81e27d14143306ba2ad04f3770bf36dfa388e059", 461358]))
    # network.client.add_message(Get(["50d958904e0ab7bac04cbc7f81e27d14143306ba2ad04f3770bf36dfa388e059"]))
    # # network.client.add_message({ "id": 6, "method":"blockchain.address.subscribe", "params": ["1ZhouQKMethPQLYaQYcSsqqMNCgbNTYVm"] })
    #
    # network.client.add_subscribe(numblocks_subscribe([]), callback=prt1, subscribe=prt2)  # do not have id
    # network.client.add_subscribe(headers_subscribe([]), callback=prt1, subscribe=prt2)  # do not have id
    #
    # BlockChain().init_header()
    # SimpleWallet('1ZhouQKMethPQLYaQYcSsqqMNCgbNTYVm').init()
    # network.init_header(BlockChain().init_header_callback)
    # network.client.add_message(GetChunk([0,]), Block().connect_chunk2)
    # print Block().headers[200 * 2016]
    network.add_message(GetHistory(['mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj']))
    network.add_message(GetMempool(['mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj']))
    network.add_message(GetBalance(['mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj']))
    # network.client.add_message(GetProof(['mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj'])) # not implemented
    network.add_message(Listunspent(['mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj']))
    network.add_message(address_subscribe(
        ['mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj']))  # 'mmXqJTLjjyD6Xp2tJ7syCeZTcwvRjcojLz'
    hot_wallet = SimpleWallet(WalletConfig(store_path='wallet.json'))
    # wallet.add_address('mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj')
    # wallet.add_key_store(SimpleKeyStore.create(SecretToASecret('\x20\x12\x10\x09' + '\x09'*28, True), None))
    hot_wallet.sync()
    outputs = [(TYPE_ADDRESS, 'mkp8FGgySzhh5mmmHDcxRxmeS3X5fXm68i', 100000)]
    tx = hot_wallet.make_unsigned_transaction(hot_wallet.get_utxo(), outputs, {})
    hot_wallet.sign_transaction(tx, None)
    # SecretToASecret('\x11'*16, True)
    # print tx


def test_cold_hot_wallet():
    global network, hot_wallet
    set_testnet()
    logging.config.fileConfig('logging.conf')
    # drop()
    init()
    network = NetWorkManager()
    network.start_ioloop()
    network.start_client()
    BlockChain().init_header()

    network.add_message(Version(["2.8.2", "0.10"]))

    network.add_message(GetHistory(['mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj']))
    network.add_message(GetMempool(['mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj']))
    network.add_message(GetBalance(['mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj']))
    network.add_message(Listunspent(['mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj']))
    network.add_message(address_subscribe(
        ['mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj']))  # 'mmXqJTLjjyD6Xp2tJ7syCeZTcwvRjcojLz'
    hot_wallet = WatchOnlySimpleWallet(WalletConfig(store_path='watch_only_simple_wallet.json'))
    secret = '\x20\x12\x10\x09' + '\x09' * 28
    if hot_wallet.keystore is None:
        hot_wallet.init_key_store(
            WatchOnlySimpleKeyStore.create(public_key_from_private_key(secret)))
    # hot_wallet.sync()
    inputs = [
        {'prevout_hash': e[0], 'prevout_n': e[1], 'scriptSig': e[2], 'value': e[3], 'address': e[4],
         'coinbase': False,
         'height': 10000} for e in TxStore().get_unspend_outs('mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj')]
    outputs = []
    outputs.append(Output((TYPE_ADDRESS, 'mkp8FGgySzhh5mmmHDcxRxmeS3X5fXm68i', 100000)))
    tx = hot_wallet.make_unsigned_transaction(inputs, outputs, {})
    print tx
    cold_wallet = ColdSimpleWallet(WalletConfig(store_path='cold_simple_wallet.json'))
    if cold_wallet.keystore is None:
        cold_wallet.init_key_store(SimpleKeyStore.create(SecretToASecret(secret, True), None))
    cold_wallet.sign_transaction(tx, None)
    # SecretToASecret('\x11'*16, True)
    print tx


def test_hd_wallet():
    global network, hot_wallet
    set_testnet()
    logging.config.fileConfig('logging.conf')
    # drop()
    init()
    network = NetWorkManager()
    network.start_ioloop()
    network.start_client()
    network.add_message(Version(["2.8.2", "0.10"]))
    hot_wallet = HDWallet(WalletConfig(store_path='hd_wallet.json'))
    if hot_wallet.keystore is None:
        hot_wallet.init_key_store(from_seed(u'reopen panel title aerobic wheat fury blame cement swarm wheel ball where', None))
    hot_wallet.sync()
    hot_wallet.synchronize()
    print hot_wallet.get_change_addresses()
    print hot_wallet.get_receiving_addresses()
    inputs = [
        {'prevout_hash': e[0], 'prevout_n': e[1], 'scriptSig': e[2], 'value': e[3], 'address': e[4],
         'coinbase': False,
         'height': 10000} for e in TxStore().get_unspend_outs('mipTN4UeM9Ab9PH5dU9XA5MjwAJnzkwCpX')]
    outputs = []
    outputs.append((TYPE_ADDRESS, 'mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj', 100000))
    # tx = wallet.make_unsigned_transaction(inputs, outputs, {})
    # print tx
    # cold_wallet = ColdSimpleWallet(WalletConfig(store_path='cold_simple_wallet.json'))
    # if cold_wallet.keystore is None:
    #     cold_wallet.init_key_store(SimpleKeyStore.create(SecretToASecret('\x20\x12\x10\x09' + '\x09' * 28, True), None))
    # wallet.sign_transaction(tx, None)
    # print tx

def test_hd_cold_hot_wallet():
    global network, hot_wallet
    set_testnet()
    logging.config.fileConfig('logging.conf')
    # drop()
    init()
    network = NetWorkManager()
    network.start_ioloop()
    network.start_client()
    # BlockChain().init_header()
    network.add_message(Version(["2.8.2", "0.10"]))
    hot_wallet = HDWatchOnlyWallet(WalletConfig(store_path='hd_hot_wallet.json'))
    seed = from_seed(u'reopen panel title aerobic wheat fury blame cement swarm wheel ball where', None)
    hot_wallet.xpub = seed.xpub
    hot_wallet.keystore = BIP32KeyHotStore({})
    hot_wallet.keystore.xpub = seed.xpub
    hot_wallet.sync()
    hot_wallet.synchronize()
    print hot_wallet.get_change_addresses()
    print hot_wallet.get_receiving_addresses()
    outputs = [Output((TYPE_ADDRESS, 'mzSwHcXhWF8bgLtxF7NXE8FF1w8BZhQwSj', 100000))]
    tx = hot_wallet.make_unsigned_transaction(hot_wallet.get_utxo(), outputs, {})
    print tx
    cold_wallet = HDWallet(WalletConfig(store_path='hd_cold_wallet.json'))
    if cold_wallet.keystore is None:
        cold_wallet.init_key_store(seed)
    cold_wallet.sign_transaction(tx, None)
    print tx

if __name__ == '__main__':
    test_hd_cold_hot_wallet()
    # test_hd_wallet()
    # test_simple_wallet()
    time.sleep(10000000)
