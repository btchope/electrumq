# -*- coding: utf-8 -*-

from hashlib import sha256

import Crypto.Hash.SHA256 as SHA256
import Crypto.Hash.RIPEMD as RIPEMD160

from utils import Parameter

__author__ = 'zhouqi'

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)


def b58encode(v):
    """ encode v, which is a string of bytes, to base58.
    """

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += ord(c) << (8 * i)  # 2x speedup vs. exponentiation

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0':
            nPad += 1
        else:
            break

    return (__b58chars[0] * nPad) + result


def b58decode(v, length=None):
    """ decode v into a string of len bytes
    """
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base ** i)

    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]:
            nPad += 1
        else:
            break

    result = chr(0) * nPad + result
    if length is not None and len(result) != length:
        return None

    return result


def hash_160(public_key):
    h1 = SHA256.new(public_key).digest()
    h2 = RIPEMD160.new(h1).digest()
    return h2


def public_key_to_bc_address(public_key, version='\x00'):
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160, version)


# def hash_160_to_bc_address(h160, version='\x00'):
#     vh160 = version + h160  # \x00 is version 0
#     h3 = SHA256.new(SHA256.new(vh160).digest()).digest()
#     addr = vh160 + h3[0:4]
#     return b58encode(addr)


def double_hash(x):
    if type(x) is unicode: x = x.encode('utf-8')
    return SHA256.new(SHA256.new(x).digest()).digest()

def hash256(x):
    if type(x) is unicode: x = x.encode('utf-8')
    return SHA256.new(x).digest()


def hash_160_to_bc_address(h160, version='\x00', witness_program_version=1):
    if version.__class__ is int:
        version = chr(version)
    if version == chr(Parameter().ADDRTYPE_P2WPKH):
        vh160 = version + chr(witness_program_version) + chr(0)
    else:
        vh160 = version + h160
    h3 = SHA256.new(SHA256.new(vh160).digest()).digest()
    addr = vh160 + h3[0:4]
    return b58encode(addr)


def hash160_to_p2pkh(h160):
    return hash_160_to_bc_address(h160, Parameter().ADDRTYPE_P2PKH)


def hash160_to_p2sh(h160):
    return hash_160_to_bc_address(h160, Parameter().ADDRTYPE_P2SH)


def public_key_to_p2pkh(public_key):
    return hash160_to_p2pkh(hash_160(public_key))


def public_key_to_p2wpkh(public_key):
    return hash_160_to_bc_address(hash_160(public_key), Parameter().ADDRTYPE_P2WPKH)


def is_valid(addr):
    return is_address(addr)


def is_address(addr):
    try:
        addrtype, h = bc_address_to_type_and_hash_160(addr)
    except Exception:
        return False
    if addrtype not in [Parameter().ADDRTYPE_P2PKH, Parameter().ADDRTYPE_P2SH]:
        return False
    return addr == hash_160_to_bc_address(h, addrtype)


def is_p2pkh(addr):
    if is_address(addr):
        addrtype, h = bc_address_to_type_and_hash_160(addr)
        return addrtype == Parameter().ADDRTYPE_P2PKH


def is_p2sh(addr):
    if is_address(addr):
        addrtype, h = bc_address_to_type_and_hash_160(addr)
        return addrtype == Parameter().ADDRTYPE_P2SH


def bc_address_to_hash_160(addr):
    bytes = b58decode(addr, 25)
    return bytes[1:21]


def bc_address_to_type_and_hash_160(addr):
    bytes = b58decode(addr, 25)
    return ord(bytes[0]), bytes[1:21]


def hash_to_integer(hash_str=''):
    v = hash_str.decode('hex')
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += ord(c) << (8 * i)  # 2x speedup vs. exponentiation
    return long_value


def double_sha256(s):
    return SHA256.new(SHA256.new(s).digest()).digest()

def Hash(x):
    if type(x) is unicode: x=x.encode('utf-8')
    return double_sha256(x)

def reverse_hex_str(hex_str):
    return hex_str.decode('hex')[::-1].encode('hex')


def b58encode_check(raw):
    "Encode raw string into Bitcoin base58 with checksum"
    chk = sha256(sha256(raw).digest()).digest()[:4]
    return b58encode(raw + chk)


def b58decode_check(enc):
    """Decode string from Bitcoin base58 and test checksum"""
    dec = b58decode(enc)
    raw, chk = dec[:-4], dec[-4:]
    if chk != sha256(sha256(raw).digest()).digest()[:4]:
        raise ValueError("base58 decoding checksum error")
    else:
        return raw


def connect_hex(hex_list):
    result = ''
    for s in hex_list:
        b = s.decode('hex')
        result += chr(len(b))
        result += b
    return result.encode('hex')


def split_hex(hex_content):
    byte_content = hex_content.decode('hex')
    result = []
    idx = 0
    while idx < len(byte_content):
        l = ord(byte_content[idx])
        idx += 1
        result.append(byte_content[idx:idx + l].encode('hex'))
        idx += l
    return result


def base36encode(number, alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    """Converts an integer to a base36 string."""
    if not isinstance(number, (int, long)):
        raise TypeError('number must be an integer')

    base36 = ''
    sign = ''

    if number < 0:
        sign = '-'
        number = -number

    if 0 <= number < len(alphabet):
        return sign + alphabet[number]

    while number != 0:
        number, i = divmod(number, len(alphabet))
        base36 = alphabet[i] + base36

    return sign + base36


def base36decode(number):
    return int(number, 36)


if __name__ == '__main__':
    x = '005cc87f4a3fdfe3a2346b6953267ca867282630d3f9b78e64'.decode('hex_codec')
    encoded = b58encode(x)
    print encoded, '19TbMSWwHvnxAKy12iNm3KdbGfzfaMFViT'
    print b58decode(encoded, len(x)).encode('hex_codec'), x.encode('hex_codec')