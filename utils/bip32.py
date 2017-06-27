# -*- coding: utf-8 -*-
import hashlib
import hmac

from ecdsa import SECP256k1, ecdsa
from ecdsa import SigningKey
from ecdsa import VerifyingKey
from ecdsa.ecdsa import generator_secp256k1
from ecdsa.util import string_to_number, number_to_string

from utils import Parameter
from utils.base58 import hash_160, b58encode_check, b58decode_check
from utils.key import SecretToASecret, GetPubKey, EC_KEY, ser_to_point
from utils.mnemonic import Mnemonic
from utils.parser import write_uint32

__author__ = 'zhouqi'

###################################### BIP32 ##############################

random_seed = lambda n: "%032x"%ecdsa.util.randrange( pow(2,n) )
BIP32_PRIME = 0x80000000


def get_pubkeys_from_secret(secret):
    # public key
    private_key = SigningKey.from_string( secret, curve = SECP256k1 )
    public_key = private_key.get_verifying_key()
    K = public_key.to_string()
    K_compressed = GetPubKey(public_key.pubkey,True)
    return K, K_compressed


# Child private key derivation function (from master private key)
# k = master private key (32 bytes)
# c = master chain code (extra entropy for key derivation) (32 bytes)
# n = the index of the key we want to derive. (only 32 bits will be used)
# If n is negative (i.e. the 32nd bit is set), the resulting private key's
#  corresponding public key can NOT be determined without the master private key.
# However, if n is positive, the resulting private key's corresponding
#  public key can be determined without the master private key.
def CKD_priv(k, c, n):
    is_prime = n & BIP32_PRIME
    return _CKD_priv(k, c, write_uint32(n)[::-1], is_prime)

def _CKD_priv(k, c, s, is_prime):
    order = generator_secp256k1.order()
    keypair = EC_KEY(k)
    cK = GetPubKey(keypair.pubkey,True)
    data = chr(0) + k + s if is_prime else cK + s
    I = hmac.new(c, data, hashlib.sha512).digest()
    k_n = number_to_string( (string_to_number(I[0:32]) + string_to_number(k)) % order , order )
    c_n = I[32:]
    return k_n, c_n

# Child public key derivation function (from public key only)
# K = master public key
# c = master chain code
# n = index of key we want to derive
# This function allows us to find the nth public key, as long as n is
#  non-negative. If n is negative, we need the master private key to find it.
def CKD_pub(cK, c, n):
    if n & BIP32_PRIME: raise
    return _CKD_pub(cK, c, write_uint32(n)[::-1])

# helper function, callable with arbitrary string
def _CKD_pub(cK, c, s):
    order = generator_secp256k1.order()
    I = hmac.new(c, cK + s, hashlib.sha512).digest()
    curve = SECP256k1
    pubkey_point = string_to_number(I[0:32])*curve.generator + ser_to_point(cK)
    public_key = VerifyingKey.from_public_point( pubkey_point, curve = SECP256k1 )
    c_n = I[32:]
    cK_n = GetPubKey(public_key.pubkey,True)
    return cK_n, c_n


def xprv_header(xtype):
    return ("%08x"%(Parameter().XPRV_HEADER + xtype)).decode('hex')

def xpub_header(xtype):
    return ("%08x"%(Parameter().XPUB_HEADER + xtype)).decode('hex')

def serialize_xprv(xtype, c, k, depth=0, fingerprint=chr(0)*4, child_number=chr(0)*4):
    xprv = xprv_header(xtype) + chr(depth) + fingerprint + child_number + c + chr(0) + k
    return b58encode_check(xprv)

def serialize_xpub(xtype, c, cK, depth=0, fingerprint=chr(0)*4, child_number=chr(0)*4):
    xpub = xpub_header(xtype) + chr(depth) + fingerprint + child_number + c + cK
    return b58encode_check(xpub)

def deserialize_xkey(xkey, prv):
    xkey = b58decode_check(xkey)
    if len(xkey) != 78:
        raise BaseException('Invalid length')
    depth = ord(xkey[4])
    fingerprint = xkey[5:9]
    child_number = xkey[9:13]
    c = xkey[13:13+32]
    header = Parameter().XPRV_HEADER if prv else Parameter().XPUB_HEADER
    xtype = int('0x' + xkey[0:4].encode('hex'), 16) - header
    if xtype not in ([0, 1] if Parameter().TESTNET else [0]):
        raise BaseException('Invalid header')
    n = 33 if prv else 32
    K_or_k = xkey[13+n:]
    return xtype, depth, fingerprint, child_number, c, K_or_k

def deserialize_xpub(xkey):
    return deserialize_xkey(xkey, False)

def deserialize_xprv(xkey):
    return deserialize_xkey(xkey, True)

def is_xpub(text):
    try:
        deserialize_xpub(text)
        return True
    except:
        return False

def is_xprv(text):
    try:
        deserialize_xprv(text)
        return True
    except:
        return False


def xpub_from_xprv(xprv):
    xtype, depth, fingerprint, child_number, c, k = deserialize_xprv(xprv)
    K, cK = get_pubkeys_from_secret(k)
    return serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)


def bip32_root(seed, xtype):
    I = hmac.new("Bitcoin seed", seed, hashlib.sha512).digest()
    master_k = I[0:32]
    master_c = I[32:]
    K, cK = get_pubkeys_from_secret(master_k)
    xprv = serialize_xprv(xtype, master_c, master_k)
    xpub = serialize_xpub(xtype, master_c, cK)
    return xprv, xpub

def xpub_from_pubkey(xtype, cK):
    assert cK[0] in ['\x02','\x03']
    return serialize_xpub(xtype, chr(0)*32, cK)


def bip32_private_derivation(xprv, branch, sequence):
    assert sequence.startswith(branch)
    if branch == sequence:
        return xprv, xpub_from_xprv(xprv)
    xtype, depth, fingerprint, child_number, c, k = deserialize_xprv(xprv)
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        if n == '': continue
        i = int(n[:-1]) + BIP32_PRIME if n[-1] == "'" else int(n)
        parent_k = k
        k, c = CKD_priv(k, c, i)
        depth += 1
    _, parent_cK = get_pubkeys_from_secret(parent_k)
    fingerprint = hash_160(parent_cK)[0:4]
    child_number = ("%08X"%i).decode('hex')
    K, cK = get_pubkeys_from_secret(k)
    xpub = serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)
    xprv = serialize_xprv(xtype, c, k, depth, fingerprint, child_number)
    return xprv, xpub


def bip32_public_derivation(xpub, branch, sequence):
    xtype, depth, fingerprint, child_number, c, cK = deserialize_xpub(xpub)
    assert sequence.startswith(branch)
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        if n == '': continue
        i = int(n)
        parent_cK = cK
        cK, c = CKD_pub(cK, c, i)
        depth += 1
    fingerprint = hash_160(parent_cK)[0:4]
    child_number = ("%08X"%i).decode('hex')
    return serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)


def bip32_private_key(sequence, k, chain):
    for i in sequence:
        k, chain = CKD_priv(k, chain, i)
    return SecretToASecret(k, True)


def xkeys_from_seed(seed, passphrase, derivation):
    xprv, xpub = bip32_root(Mnemonic.mnemonic_to_seed(seed, passphrase), 0)
    xprv, xpub = bip32_private_derivation(xprv, "m/", derivation)
    return xprv, xpub
