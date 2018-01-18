# -*- coding: utf-8 -*-
import  unittest

from electrumq.utils.base58 import double_sha256
from electrumq.secret.key import EC_KEY

__author__ = 'zhouqi'


class HowToUseKey(unittest.TestCase):
    def test_sign(self):
        secret = '5HvofFG7K1e2aeWESm5pbCzRHtCSiZNbfLYXBvxyA57DhKHV4U3'
        private_key = '0ecd20654c2e2be708495853e8da35c664247040c00bd10b9b13e5e86e6a808d'
        public_key = '042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9'
        msg = '0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000001976a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88acffffffff0123ce0100000000001976a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac0000000001000000'
        msg = double_sha256(msg.decode('hex'))
        sig = '30440220587ce0cf0252e2db3a7c3c91b355aa8f3385e128227cd8727c5f7777877ad7720220123af7483eb76e12ea54c73978fe627fffb91bbda6797e938147790e43ee57e5'

        key = EC_KEY.init_from_secret(secret)
        sign_result = key.sign(msg)
        self.assertEqual(sign_result.encode('hex'), sig)
        self.assertTrue(key.verify_sign(sign_result, msg))


    def test_secret(self):
        secret = '5HvofFG7K1e2aeWESm5pbCzRHtCSiZNbfLYXBvxyA57DhKHV4U3'
        private_key = '0ecd20654c2e2be708495853e8da35c664247040c00bd10b9b13e5e86e6a808d'
        public_key = '042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9'

if __name__ =='__main__':
    unittest.main()
