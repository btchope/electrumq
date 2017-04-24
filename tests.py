# -*- coding: utf-8 -*-
import unittest

import utils
from utils import base58

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

