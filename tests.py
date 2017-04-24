# -*- coding: utf-8 -*-
import unittest

import utils
from db.sqlite import Connection, init, drop
from utils import base58
from utils import parser

__author__ = 'zhouqi'

class TestWallet(unittest.TestCase):
    def setUp(self):
        pass

    def test_balance(self):
        pass


class TestBlockchain(unittest.TestCase):
    def test_height(self):
        pass

    def test_header(self):
        pass


class TestUtil(unittest.TestCase):

    def test_hash_160(self):
        pub_key = '0404b421302b8b782d3c3ce425bbe30178e4ed5d4f51e6ce9ca1799888fbfbf42595d6a252fbd108e35db38ff58ba52c8e10b733a0f4f38bb799dccfe11460772d'.decode('hex')
        print base58.public_key_to_bc_address(pub_key)
        self.assertEqual(utils.hash_160_to_bc_address(utils.hash_160(pub_key), 0), base58.public_key_to_bc_address(pub_key))

    def test_int_to_hex(self):
        num = 250
        print parser.int_to_hex(num)
        self.assertEqual(utils.int_to_hex(num), parser.int_to_hex(num))

    def test_rev_hex(self):
        h = '0100'
        print base58.reverse_hex_str(h)
        self.assertEqual(utils.rev_hex(h), base58.reverse_hex_str(h))

    def test_Hash(self):
        s = 'abc'
        print base58.Hash(s)
        self.assertEqual(base58.Hash(s), utils.Hash(s))
        s = u'周琪'
        print base58.Hash(s)
        self.assertEqual(base58.Hash(s), utils.Hash(s))

class TestConnection(unittest.TestCase):
    def setUp(self):
        init()

    def tearDown(self):
        drop()

    def test_normal(self):
        with Connection.gen_db() as conn:
            c = conn.cursor()
            c.execute('create table test( id INTEGER not null primary key);')
            c.execute('insert into test(id) VALUES (1);')
        with Connection.gen_db() as conn:
            c = conn.cursor()
            res = c.execute('select * from test;')
            self.assertEqual(res.fetchall(), [(1, )])

    def test_error(self):
        try:
            with Connection.gen_db() as conn:
                c = conn.cursor()
                c.execute('create table test( id INTEGER not null primary key);')
                c.execute('insert into test(id) VALUES (1);')
                raise Exception()
        except:
            pass
        with Connection.gen_db() as conn:
            c = conn.cursor()
            res = c.execute('select * from test;')
            self.assertEqual(res.fetchall(), [])
