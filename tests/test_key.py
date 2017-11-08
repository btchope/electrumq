# -*- coding: utf-8 -*-
import hashlib
from unittest import TestCase

from ecdsa import SECP256k1, SigningKey, rfc6979
from ecdsa.ecdsa import generator_secp256k1
from ecdsa.util import string_to_number

# from electrumq.utils.crypto import sign, verify_sign, EC_KEY, i2d_ECPrivateKey, i2o_ECPublicKey
from electrumq.utils.base58 import double_sha256
from electrumq.utils.crypto import secp256k1
from electrumq.utils.key import ASecretToSecret, is_compressed, EC_KEY, MySigningKey
from ecdsa import util

__author__ = 'zhouqi'


class HowToUseKey(TestCase):
    def test_sign(self):
        secret = '5HvofFG7K1e2aeWESm5pbCzRHtCSiZNbfLYXBvxyA57DhKHV4U3'
        private_key = '0ecd20654c2e2be708495853e8da35c664247040c00bd10b9b13e5e86e6a808d'
        public_key = '042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9'
        msg = '0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000001976a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88acffffffff0123ce0100000000001976a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac0000000001000000'
        sig = '30440220587ce0cf0252e2db3a7c3c91b355aa8f3385e128227cd8727c5f7777877ad7720220123af7483eb76e12ea54c73978fe627fffb91bbda6797e938147790e43ee57e5'

        key = EC_KEY(ASecretToSecret(secret))
        private_key = MySigningKey.from_secret_exponent(key.secret, curve=SECP256k1, hashfunc=hashlib.sha256)
        public_key = private_key.get_verifying_key()
        pre_hash = double_sha256(msg.decode('hex'))
        sign_result = private_key.sign_digest_deterministic(pre_hash, hashfunc=hashlib.sha256, sigencode=util.sigencode_der)
        self.assertEqual(sign_result.encode('hex'), sig)
        self.assertTrue(
            public_key.verify_digest(sign_result, pre_hash, sigdecode=util.sigdecode_der))


    def test_secret(self):
        secret = '5HvofFG7K1e2aeWESm5pbCzRHtCSiZNbfLYXBvxyA57DhKHV4U3'
        private_key = '0ecd20654c2e2be708495853e8da35c664247040c00bd10b9b13e5e86e6a808d'
        public_key = '042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9'




