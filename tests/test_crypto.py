# -*- coding: utf-8 -*-
from unittest import TestCase

from ecdsa.util import string_to_number

from electrumq.utils.crypto import sign, verify_sign, EC_KEY, i2d_ECPrivateKey, i2o_ECPublicKey
from electrumq.utils.key import ASecretToSecret, is_compressed

__author__ = 'zhouqi'


class HowToUseKey(TestCase):
    def test_sign(self):
        secret = '5HvofFG7K1e2aeWESm5pbCzRHtCSiZNbfLYXBvxyA57DhKHV4U3'
        private_key = '0ecd20654c2e2be708495853e8da35c664247040c00bd10b9b13e5e86e6a808d'
        public_key = '042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9'
        msg = '0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000001976a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88acffffffff0123ce0100000000001976a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac0000000001000000'
        sig = '30450220587ce0cf0252e2db3a7c3c91b355aa8f3385e128227cd8727c5f7777877ad772022100edc508b7c14891ed15ab38c687019d7ebaf5c12908cf21a83e8ae57e8c47e95c'
        sign_result = sign(string_to_number(private_key.decode('hex')), msg)
        self.assertEqual(sign_result, sig)
        self.assertTrue(verify_sign(public_key, sign_result, msg))

    def test_secret(self):
        secret = '5HvofFG7K1e2aeWESm5pbCzRHtCSiZNbfLYXBvxyA57DhKHV4U3'
        private_key = '0ecd20654c2e2be708495853e8da35c664247040c00bd10b9b13e5e86e6a808d'
        public_key = '042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9'

        key = EC_KEY(string_to_number(ASecretToSecret(secret)))
        self.assertEqual(ASecretToSecret(secret).encode('hex'), private_key)
        self.assertEqual(i2o_ECPublicKey(key, is_compressed(secret)).encode('hex'), public_key)
        # self.assertEqual(i2d_ECPrivateKey(key), is_compressed(secret), private_key)
