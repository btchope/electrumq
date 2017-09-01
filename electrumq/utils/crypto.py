# -*- coding: utf-8 -*-

import base64
from ecdsa import rfc6979, util, SigningKey, VerifyingKey, numbertheory
from ecdsa.curves import Curve
from ecdsa.ecdsa import Public_key, curve_secp256k1, Private_key, generator_secp256k1
from ecdsa.ellipticcurve import CurveFp, Point
from electrumq.utils.base58 import double_sha256, public_key_to_bc_address
from hashlib import sha256

__author__ = 'zhouqi'

_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
secp256k1 = Curve("secp256k1", curve_secp256k1, generator_secp256k1, (1, 3, 132, 0, 10))


class EC_KEY(object):
    def __init__(self, secret):
        curve = CurveFp(_p, _a, _b)
        generator = Point(curve, _Gx, _Gy, _r)
        self.pubkey = Public_key(generator, generator * secret)
        self.privkey = Private_key(self.pubkey, secret)
        self.secret = secret


def i2d_ECPrivateKey(pkey, compressed=False):  # , crypted=True):
    part3 = 'a081a53081a2020101302c06072a8648ce3d0101022100'  # for uncompressed keys
    if compressed:
        if True:  # not crypted:  ## Bitcoin accepts both part3's for crypted wallets...
            part3 = 'a08185308182020101302c06072a8648ce3d0101022100'  # for compressed keys
        key = '3081d30201010420' + \
              '%064x' % pkey.secret + \
              part3 + \
              '%064x' % _p + \
              '3006040100040107042102' + \
              '%064x' % _Gx + \
              '022100' + \
              '%064x' % _r + \
              '020101a124032200'
    else:
        key = '308201130201010420' + \
              '%064x' % pkey.secret + \
              part3 + \
              '%064x' % _p + \
              '3006040100040107044104' + \
              '%064x' % _Gx + \
              '%064x' % _Gy + \
              '022100' + \
              '%064x' % _r + \
              '020101a144034200'
    return key.decode('hex') + i2o_ECPublicKey(pkey, compressed)


def i2o_ECPublicKey(pkey, compressed=False):
    # public keys are 65 bytes long (520 bits)
    # 0x04 + 32-byte X-coordinate + 32-byte Y-coordinate
    # 0x00 = point at infinity, 0x02 and 0x03 = compressed, 0x04 = uncompressed
    # compressed keys: <sign> <x> where <sign> is 0x02 if y is even and 0x03 if y is odd
    if compressed:
        if pkey.pubkey.point.y() & 1:
            key = '03' + '%064x' % pkey.pubkey.point.x()
        else:
            key = '02' + '%064x' % pkey.pubkey.point.x()
    else:
        key = '04' + \
              '%064x' % pkey.pubkey.point.x() + \
              '%064x' % pkey.pubkey.point.y()
    return key.decode('hex')


def sign(secret, msg):
    priv_key = SigningKey.from_secret_exponent(secret, curve=secp256k1, hashfunc=sha256)
    msg_hash = double_sha256(msg.decode('hex'))
    k = rfc6979.generate_k(generator_secp256k1, secret, sha256, msg_hash) % generator_secp256k1.order()
    return priv_key.sign_digest(msg_hash, sigencode=util.sigencode_der_canonize, k=k).encode('hex')


def sign_hash(secret, msg_hash):
    priv_key = SigningKey.from_secret_exponent(secret, curve=secp256k1, hashfunc=sha256)
    k = rfc6979.generate_k(generator_secp256k1, secret, sha256, msg_hash) % generator_secp256k1.order()
    return priv_key.sign_digest(msg_hash, sigencode=util.sigencode_der_canonize, k=k).encode('hex')


def verify_sign(pub_key, sign, msg):
    key = VerifyingKey.from_string(pub_key.decode('hex')[1:], curve=secp256k1)
    return key.verify_digest(sign.decode('hex'), double_sha256(msg.decode('hex')), sigdecode=util.sigdecode_der)


def bitcoin_message(message):
    return "\x18Bitcoin Signed Message:\n" + chr(len(message)) + message


def encode_point(pubkey, compressed=False):
    order = generator_secp256k1.order()
    p = pubkey.pubkey.point
    x_str = util.number_to_string(p.x(), order)
    y_str = util.number_to_string(p.y(), order)
    if compressed:
        return chr(2 + (p.y() & 1)) + x_str
    else:
        return chr(4) + x_str + y_str


def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
    must be an odd prime.

    Solve the congruence of the form:
    x^2 = a (mod p)
    And returns x. Note that p - x is also a root.

    0 is returned is no square root exists for
    these a and p.

    The Tonelli-Shanks algorithm is used (except
    for some simple cases in which the solution
    is known from an identity). This algorithm
    runs in polynomial time (unless the
    generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) / 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) / 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
    Euler's criterion. p is a prime, a is
    relatively prime to p (if p divides
    a, then a|p = 0)

    Returns 1 if a has a square root modulo
    p, -1 otherwise.
    """
    ls = pow(a, (p - 1) / 2, p)
    return -1 if ls == p - 1 else ls


def sign_bitcoin_message_with_secret(secret, message, compressed=True):
    msg = bitcoin_message(message)
    return sign_message(secret, msg, compressed)
    # private_key = ecdsa.SigningKey.from_secret_exponent(secret, curve=secp256k1)
    # public_key = private_key.get_verifying_key()
    # msg_hash = double_sha256(msg)
    # k = rfc6979.generate_k(generator_secp256k1, secret, hashlib.sha256, msg_hash) % generator_secp256k1.order()
    # signature = private_key.sign_digest(msg_hash, sigencode=ecdsa.util.sigencode_string_canonize, k=k)
    # address = public_key_to_bc_address(encode_point(public_key, compressed))
    # assert public_key.verify_digest(signature, msg_hash, sigdecode=ecdsa.util.sigdecode_string)
    # for i in range(4):
    # nV = 27 + i
    #     if compressed:
    #         nV += 4
    #     sig = base64.b64encode(chr(nV) + signature)
    #     try:
    #         if verify_bitcoin_message(address, sig, message):
    #             return sig
    #     except:
    #         continue
    # else:
    #     raise BaseException("error: cannot sign message")


def sign_message(secret, message, compressed=True):
    private_key = SigningKey.from_secret_exponent(secret, curve=secp256k1)
    public_key = private_key.get_verifying_key()
    msg_hash = double_sha256(message)
    k = rfc6979.generate_k(generator_secp256k1, secret, sha256, msg_hash) % generator_secp256k1.order()
    signature = private_key.sign_digest(msg_hash, sigencode=util.sigencode_string_canonize, k=k)
    address = public_key_to_bc_address(encode_point(public_key, compressed))
    assert public_key.verify_digest(signature, msg_hash, sigdecode=util.sigdecode_string)
    for i in range(4):
        nV = 27 + i
        if compressed:
            nV += 4
        sig = base64.b64encode(chr(nV) + signature)
        try:
            if verify_message(address, sig, message):
                return sig
        except:
            continue
    else:
        raise BaseException("error: cannot sign message")


def verify_message(address, signature, message):
    curve = curve_secp256k1
    G = generator_secp256k1
    order = G.order()
    # extract r,s from signature
    sig = base64.b64decode(signature)
    if len(sig) != 65: raise BaseException("Wrong encoding")
    r, s = util.sigdecode_string(sig[1:], order)
    nV = ord(sig[0])
    if nV < 27 or nV >= 35:
        return False
    if nV >= 31:
        compressed = True
        nV -= 4
    else:
        compressed = False
    recid = nV - 27
    # 1.1
    x = r + (recid / 2) * order
    # 1.3
    alpha = ( x * x * x + curve.a() * x + curve.b() ) % curve.p()
    beta = modular_sqrt(alpha, curve.p())
    y = beta if (beta - recid) % 2 == 0 else curve.p() - beta
    # 1.4 the constructor checks that nR is at infinity
    R = Point(curve, x, y, order)
    # 1.5 compute e from message:
    h = double_sha256(message)
    e = int(h.encode('hex'), 16)
    minus_e = -e % order
    # 1.6 compute Q = r^-1 (sR - eG)
    inv_r = numbertheory.inverse_mod(r, order)
    Q = inv_r * ( s * R + minus_e * G )
    public_key = VerifyingKey.from_public_point(Q, curve=secp256k1)
    # check that Q is the public key
    public_key.verify_digest(sig[1:], h, sigdecode=util.sigdecode_string)
    # check that we get the original signing address
    addr = public_key_to_bc_address(encode_point(public_key, compressed))
    if address == addr:
        return True
    else:
        # print addr
        return False


def sign_bitcoin_message(private_key, message, compressed=False):
    public_key = private_key.get_verifying_key()
    signature = private_key.sign_digest(double_sha256(bitcoin_message(message)), sigencode=util.sigencode_string)
    address = public_key_to_bc_address(encode_point(public_key, compressed))
    assert public_key.verify_digest(signature, double_sha256(bitcoin_message(message)), sigdecode=util.sigdecode_string)
    for i in range(4):
        nV = 27 + i
        if compressed:
            nV += 4
        sig = base64.b64encode(chr(nV) + signature)
        try:
            if verify_bitcoin_message(address, sig, message):
                return sig
        except:
            continue
    else:
        raise BaseException("error: cannot sign message")


def verify_bitcoin_message(address, signature, message):
    message = bitcoin_message(message)
    return verify_message(address, signature, message)
    # """ See http://www.secg.org/download/aid-780/sec1-v2.pdf for the math """
    # message = bitcoin_message(message)
    # curve = curve_secp256k1
    # G = generator_secp256k1
    # order = G.order()
    # # extract r,s from signature
    # sig = base64.b64decode(signature)
    # if len(sig) != 65: raise BaseException("Wrong encoding")
    # r, s = ecdsa.util.sigdecode_string(sig[1:], order)
    # nV = ord(sig[0])
    # if nV < 27 or nV >= 35:
    # return False
    # if nV >= 31:
    #     compressed = True
    #     nV -= 4
    # else:
    #     compressed = False
    # recid = nV - 27
    # # 1.1
    # x = r + (recid / 2) * order
    # # 1.3
    # alpha = ( x * x * x + curve.a() * x + curve.b() ) % curve.p()
    # beta = modular_sqrt(alpha, curve.p())
    # y = beta if (beta - recid) % 2 == 0 else curve.p() - beta
    # # 1.4 the constructor checks that nR is at infinity
    # R = ecdsa.ellipticcurve.Point(curve, x, y, order)
    # # 1.5 compute e from message:
    # h = double_sha256(message)
    # e = int(h.encode('hex'), 16)
    # minus_e = -e % order
    # # 1.6 compute Q = r^-1 (sR - eG)
    # inv_r = ecdsa.numbertheory.inverse_mod(r, order)
    # Q = inv_r * ( s * R + minus_e * G )
    # public_key = ecdsa.VerifyingKey.from_public_point(Q, curve=secp256k1)
    # # check that Q is the public key
    # public_key.verify_digest(sig[1:], h, sigdecode=ecdsa.util.sigdecode_string)
    # # check that we get the original signing address
    # addr = public_key_to_bc_address(encode_point(public_key, compressed))
    # if address == addr:
    #     return True
    # else:
    #     # print addr
    #     return False
