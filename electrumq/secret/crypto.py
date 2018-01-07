# -*- coding: utf-8 -*-
# module : crypto
# @Time  : 2018/1/7 16:36
# @author: Novice

""" doc """

import base64
import pyaes
import os


class Crypto(object):
    pass


class AES(Crypto):

    def __init__(self):
        pass

    def _encrypt_with_iv(self, key, iv, data):
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Encrypter(aes_cbc)
        e = aes.feed(data) + aes.feed()  # empty aes.feed() appends pkcs padding
        return e

    def _decrypt_with_iv(self, key, iv, data):
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Decrypter(aes_cbc)
        s = aes.feed(data) + aes.feed()  # empty aes.feed() strips pkcs padding
        return s

    @classmethod
    def encode(cls, key, msg):

        assert cls == AES
        ins = cls()
        iv = bytes(os.urandom(16))
        ct = ins._encrypt_with_iv(key, iv, msg)
        e = iv + ct
        return base64.b64encode(e)

    @classmethod
    def decode(cls, key, e):
        assert cls == AES
        ins = cls()
        e = bytes(base64.b64decode(e))
        iv, e = e[:16], e[16:]
        s = ins._decrypt_with_iv(key, iv, e)
        return s
