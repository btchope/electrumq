# -*- coding: utf-8 -*-
import time

import logging
from tornado import gen

from blockchain import BlockChain
from db.mem.blockstore import BlockStore
from db.sqlite import init, drop
from db.sqlite.tx import TxStore
from network import NetWorkManager
from utils import SecretToASecret, public_key_to_p2pkh
from utils.key import Imported_KeyStore
from utils.parameter import set_testnet, TYPE_ADDRESS
from wallet import SimpleWallet

__author__ = 'zhouqi'


from message.all import *

if __name__ == '__main__':
    set_testnet()

    keystore = Imported_KeyStore({})
    pubkey = keystore.import_key(SecretToASecret('\x09'*32, True), None)
    address = public_key_to_p2pkh(pubkey.decode('hex'))

    # pubkey = keystore.import_key(SecretToASecret('\x08' * 32, True), None)
    # address = public_key_to_p2pkh(pubkey.decode('hex'))

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

    network.client.add_message(Version(["2.8.2", "0.10"]))
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

    network.client.add_message(GetHistory(["mpuq4rcmKJdEFbiFTHwe4GnroJZHEWf8Fq"]))
    network.client.add_message(GetMempool(["mpuq4rcmKJdEFbiFTHwe4GnroJZHEWf8Fq"]))
    network.client.add_message(GetBalance(["mpuq4rcmKJdEFbiFTHwe4GnroJZHEWf8Fq"]))
    # network.client.add_message(GetProof(["mpuq4rcmKJdEFbiFTHwe4GnroJZHEWf8Fq"])) # not implemented
    network.client.add_message(Listunspent(["mpuq4rcmKJdEFbiFTHwe4GnroJZHEWf8Fq"]))
    network.client.add_message(address_subscribe(["mpuq4rcmKJdEFbiFTHwe4GnroJZHEWf8Fq"])) # 'mmXqJTLjjyD6Xp2tJ7syCeZTcwvRjcojLz'
    wallet = SimpleWallet('mpuq4rcmKJdEFbiFTHwe4GnroJZHEWf8Fq')
    wallet.init()

    inputs = [
        {'prevout_hash': e[0], 'prevout_n': e[1], 'scriptSig': e[2], 'value': e[3], 'address': e[4], 'coinbase': False,
         'height': 10000} for e in TxStore().get_unspend_outs('mpuq4rcmKJdEFbiFTHwe4GnroJZHEWf8Fq')]
    outputs = []
    outputs.append((TYPE_ADDRESS, 'miAGdhYgZd4dR1P5bRE4PtvsZpMp199is4', 100000))
    tx = wallet.make_unsigned_transaction(inputs, outputs, {})
    wallet.sign_transaction(tx, None)
    # SecretToASecret('\x11'*16, True)
    print tx
    time.sleep(10000000)
