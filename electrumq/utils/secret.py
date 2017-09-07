# -*- coding: utf-8 -*-
from electrumq.utils.base58 import b58encode_check, b58decode_check
from electrumq.utils.key import is_minikey, minikey_to_private_key
from electrumq.utils.parameter import Parameter

__author__ = 'zhouqi'


def SecretToASecret(secret, compressed=False):
    addrtype = Parameter().ADDRTYPE_P2PKH
    vchIn = chr((addrtype + 128) & 255) + secret
    if compressed: vchIn += '\01'
    return b58encode_check(vchIn)


def ASecretToSecret(key):
    addrtype = Parameter().ADDRTYPE_P2PKH
    vch = b58decode_check(key)
    if vch and vch[0] == chr((addrtype + 128) & 255):
        return vch[1:]
    elif is_minikey(key):
        return minikey_to_private_key(key)
    else:
        return False


class Secret(object):
    compressed = None
    secret = None

    def from_bitcoin(self, secret):
        self.secret = secret
        self.compressed = len(b58decode_check(secret)) == 34

    def from_hex(self, hex_data, compressed=True):
        self.compressed = compressed
        self.secret = SecretToASecret(hex_data, compressed)

    def from_hex_str(self, hex_str, compressed=True):
        self.compressed = compressed
        self.secret = SecretToASecret(hex_str.decode('hex'), compressed)
