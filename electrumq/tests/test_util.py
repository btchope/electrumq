# -*- coding: utf-8 -*-
import unittest

from sqlite3 import Connection

import utils
from electrumq.db.sqlite import drop, init
from electrumq.utils import base58

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
            self.assertEqual(res.fetchall(), [(1,)])

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
