# -*- coding: utf-8 -*-
import json
import unittest

from electrumq.utils.base58 import b58decode_check, public_key_to_p2pkh
from electrumq.utils.key import EC_KEY, regenerate_key
from electrumq.utils.key_store import SimpleKeyStore
from electrumq.utils.parameter import TYPE_ADDRESS, set_testnet
from electrumq.utils.tx import Transaction, Input, Output

__author__ = 'zhouqi'


class TestData(unittest.TestCase):
    bitcoin_test_case = json.loads(open('./data/bitcoin-util-test.json').read())

    def test_create_empty_transaction(self):
        case = self.bitcoin_test_case[0]
        self.assertEqual(str(Transaction.from_io([], [])), self.read_hex(case['output_cmp']))

    def test_del_in(self):
        case = self.bitcoin_test_case[5]
        tx = Transaction(self.read_hex(case['input']))
        # do no support del in

    def test_del_out(self):
        pass

    def test_change_locktime(self):
        case = self.bitcoin_test_case[11]
        tx = Transaction(self.read_hex(case['input']))
        tx.deserialize()
        tx.locktime = 317000
        tx.raw = None
        self.assertEqual(str(tx), self.read_hex(case['output_cmp']))

    def test_create_unsign_tx(self):
        case = self.bitcoin_test_case[17]
        tx = Transaction(None)
        # bitcoin test data default tx version is 2
        tx.tx_ver = 2
        in1 = Input(None)
        in1.prev_tx_hash = '5897de6bd6027a475eadd57019d4e6872c396d0716c4875a5f1a6fcfdf385c1f'
        in1.prev_out_sn = 0
        in1.in_dict = {'type': 'p2pkh', 'x_pubkeys': [], 'pubkeys': [], 'signatures': []}
        in2 = Input(None)
        in2.prev_tx_hash = 'bf829c6bcf84579331337659d31f89dfd138f7f7785802d5501c92333145ca7c'
        in2.prev_out_sn = 18
        in2.in_dict = {'type': 'p2pkh', 'x_pubkeys': [], 'pubkeys': [], 'signatures': []}
        in3 = Input(None)
        in3.prev_tx_hash = '22a6f904655d53ae2ff70e701a0bbd90aa3975c0f40bfc6cc996a9049e31cdfc'
        in3.prev_out_sn = 1
        in3.in_dict = {'type': 'p2pkh', 'x_pubkeys': [], 'pubkeys': [], 'signatures': []}
        out1 = Output(None)
        out1.out_address = '13tuJJDR2RgArmgfv6JScSdreahzgc4T6o'
        out1.out_value = 18000000
        out1.address_type = TYPE_ADDRESS
        out2 = Output(None)
        out2.out_address = '1P8yWvZW8jVihP1bzHeqfE4aoXNX8AVa46'
        out2.out_value = 400000000
        out2.address_type = TYPE_ADDRESS
        tx.add_input_list([in1, in2, in3])
        tx._output_list = [out1, out2]

        self.assertEqual(str(tx), self.read_hex(case['output_cmp']))

    def test_create_sign_tx(self):
        case = self.bitcoin_test_case[31]
        tx = Transaction(None)
        # bitcoin test data default tx version is 2
        tx.tx_ver = 1
        in1 = Input(None)
        in1.prev_tx_hash = '4d49a71ec9da436f71ec4ee231d04f292a29cd316f598bb7068feccabdc59485'
        in1.prev_out_sn = 0
        in1.in_address = '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm'
        in1.in_dict = {'type': 'p2pkh', 'x_pubkeys': ['0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'], 'pubkeys': None, 'signatures': [None], 'num_sig': 1}
        out1 = Output(None)
        out1.out_address = '193P6LtvS4nCnkDvM9uXn1gsSRqh4aDAz7'
        out1.out_value = 100000
        out1.address_type = TYPE_ADDRESS
        tx.add_input_list([in1, ])
        tx._output_list = [out1, ]

        secret = '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf'

        key = regenerate_key(secret)
        keypair = {key.get_public_key(compressed=False): secret}
        address = public_key_to_p2pkh(key.get_public_key(compressed=False).decode('hex'))
        tx.sign(keypair)
        print str(tx)
        # test case is not use rfc6979
        self.assertEqual(str(tx), '01000000018594c5bdcaec8f06b78b596f31cd292a294fd031e24eec716f43dac91ea7494d000000008a473044022024a1d4c691ee739cb430e0bbc92192af9e85090cfadfc3d9c5fdf3292187c37c02200ba62aeff058bb2185e9357ff51c06874c45192d5fcac6d546a6739c9aaf1a7901410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ffffffff01a0860100000000001976a9145834479edbbe0539b31ffd3a8f8ebadc2165ed0188ac00000000')


    def read_hex(self, file_name):
        return open('./data/%s' % (file_name,)).read().replace('\n', '')

    def read_json(self, file_name):
        return json.loads(open('./data/%s' % (file_name,)).read())

if __name__ =='__main__':
    unittest.main()