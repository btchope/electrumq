# -*- coding: utf-8 -*-
import base64
import hashlib
import hmac
import os

import sys

import ecdsa
import pyaes

from utils.parameter import Parameter
import version

__author__ = 'zhouqi'


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


# hash_encode = lambda x: x[::-1].encode('hex')
# hash_decode = lambda x: x.decode('hex')[::-1]
# hmac_sha_512 = lambda x, y: hmac.new(x, y, hashlib.sha512).digest()
# TESTNET = False
# NOLNET = False
# ADDRTYPE_P2PKH = 0
# ADDRTYPE_P2SH = 5
# ADDRTYPE_P2WPKH = 6
# XPRV_HEADER = 0x0488ade4
# XPUB_HEADER = 0x0488b21e
# HEADERS_URL = "https://headers.electrum.org/blockchain_headers"


# def sha256(x):
#     return hashlib.sha256(x).digest()
#
#
# def Hash(x):
#     if type(x) is unicode: x = x.encode('utf-8')
#     return sha256(sha256(x))
#
# def rev_hex(s):
#     return s.decode('hex')[::-1].encode('hex')


# def int_to_hex(i, length=1):
#     s = hex(i)[2:].rstrip('L')
#     s = "0"*(2*length - len(s)) + s
#     return rev_hex(s)


# def hash_160(public_key):
#     # if 'ANDROID_DATA' in os.environ:
#     #     from Crypto.Hash import RIPEMD
#     #     md = RIPEMD.new()
#     # else:
#     md = hashlib.new('ripemd')
#     md.update(sha256(public_key))
#     return md.digest()

# def hash_160_to_bc_address(h160, addrtype, witness_program_version=1):
#     s = chr(addrtype)
#     if addrtype == Parameter().ADDRTYPE_P2WPKH:
#         s += chr(witness_program_version) + chr(0)
#     s += h160
#     return base_encode(s+Hash(s)[0:4], base=58)



# def hash160_to_p2pkh(h160):
#     return hash_160_to_bc_address(h160, Parameter().ADDRTYPE_P2PKH)
#
# def hash160_to_p2sh(h160):
#     return hash_160_to_bc_address(h160, Parameter().ADDRTYPE_P2SH)
#
# def public_key_to_p2pkh(public_key):
#     return hash160_to_p2pkh(hash_160(public_key))
#
# def public_key_to_p2wpkh(public_key):
#     return hash_160_to_bc_address(hash_160(public_key), Parameter().ADDRTYPE_P2WPKH)


# __b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
# assert len(__b58chars) == 58
#
# __b43chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
# assert len(__b43chars) == 43
#
#
# def base_encode(v, base):
#     """ encode v, which is a string of bytes, to base58."""
#     if base == 58:
#         chars = __b58chars
#     elif base == 43:
#         chars = __b43chars
#     long_value = 0L
#     for (i, c) in enumerate(v[::-1]):
#         long_value += (256**i) * ord(c)
#     result = ''
#     while long_value >= base:
#         div, mod = divmod(long_value, base)
#         result = chars[mod] + result
#         long_value = div
#     result = chars[long_value] + result
#     # Bitcoin does a little leading-zero-compression:
#     # leading 0-bytes in the input become leading-1s
#     nPad = 0
#     for c in v:
#         if c == '\0': nPad += 1
#         else: break
#     return (chars[0]*nPad) + result
#
#
# def base_decode(v, length, base):
#     """ decode v into a string of len bytes."""
#     if base == 58:
#         chars = __b58chars
#     elif base == 43:
#         chars = __b43chars
#     long_value = 0L
#     for (i, c) in enumerate(v[::-1]):
#         long_value += chars.find(c) * (base**i)
#     result = ''
#     while long_value >= 256:
#         div, mod = divmod(long_value, 256)
#         result = chr(mod) + result
#         long_value = div
#     result = chr(long_value) + result
#     nPad = 0
#     for c in v:
#         if c == chars[0]: nPad += 1
#         else: break
#     result = chr(0)*nPad + result
#     if length is not None and len(result) != length:
#         return None
#     return result
#
#
# def EncodeBase58Check(vchIn):
#     hash = Hash(vchIn)
#     return base_encode(vchIn + hash[0:4], base=58)
#
#
# def DecodeBase58Check(psz):
#     vchRet = base_decode(psz, None, base=58)
#     key = vchRet[0:-4]
#     csum = vchRet[-4:]
#     hash = Hash(key)
#     cs32 = hash[0:4]
#     if cs32 != csum:
#         return None
#     else:
#         return key


# def var_int(i):
#     pass
    # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    # if i<0xfd:
    #     return int_to_hex(i)
    # elif i<=0xffff:
    #     return "fd"+int_to_hex(i,2)
    # elif i<=0xffffffff:
    #     return "fe"+int_to_hex(i,4)
    # else:
    #     return "ff"+int_to_hex(i,8)


# def op_push(i):
#     if i<0x4c:
#         return int_to_hex(i)
#     elif i<0xff:
#         return '4c' + int_to_hex(i)
#     elif i<0xffff:
#         return '4d' + int_to_hex(i,2)
#     else:
#         return '4e' + int_to_hex(i,4)

#
# TYPE_ADDRESS = 0
# TYPE_PUBKEY  = 1
# TYPE_SCRIPT  = 2


is_verbose = False
def set_verbosity(b):
    global is_verbose
    is_verbose = b

def print_error(*args):
    if not is_verbose: return
    print_stderr(*args)

def print_stderr(*args):
    args = [str(item) for item in args]
    sys.stderr.write(" ".join(args) + "\n")
    sys.stderr.flush()

def print_msg(*args):
    # Stringify args
    args = [str(item) for item in args]
    sys.stdout.write(" ".join(args) + "\n")
    sys.stdout.flush()


# def point_to_ser(P, comp=True ):
#     if comp:
#         return ( ('%02x'%(2+(P.y()&1)))+('%064x'%P.x()) ).decode('hex')
#     return ( '04'+('%064x'%P.x())+('%064x'%P.y()) ).decode('hex')







# Bitcoin network constants
# TESTNET = False
# NOLNET = False
# ADDRTYPE_P2PKH = 0
# ADDRTYPE_P2SH = 5
# ADDRTYPE_P2WPKH = 6
# XPRV_HEADER = 0x0488ade4
# XPUB_HEADER = 0x0488b21e
# HEADERS_URL = "https://headers.electrum.org/blockchain_headers"

# def set_testnet():
#     global ADDRTYPE_P2PKH, ADDRTYPE_P2SH, ADDRTYPE_P2WPKH
#     global XPRV_HEADER, XPUB_HEADER
#     global TESTNET, HEADERS_URL
#     TESTNET = True
#     ADDRTYPE_P2PKH = 111
#     ADDRTYPE_P2SH = 196
#     ADDRTYPE_P2WPKH = 3
#     XPRV_HEADER = 0x04358394
#     XPUB_HEADER = 0x043587cf
#     HEADERS_URL = "https://headers.electrum.org/testnet_headers"
#
# def set_nolnet():
#     global ADDRTYPE_P2PKH, ADDRTYPE_P2SH, ADDRTYPE_P2WPKH
#     global XPRV_HEADER, XPUB_HEADER
#     global NOLNET, HEADERS_URL
#     NOLNET = True
#     ADDRTYPE_P2PKH = 0
#     ADDRTYPE_P2SH = 5
#     ADDRTYPE_P2WPKH = 6
#     XPRV_HEADER = 0x0488ade4
#     XPUB_HEADER = 0x0488b21e
#     HEADERS_URL = "https://headers.electrum.org/nolnet_headers"



################################## transactions
#
# FEE_STEP = 10000
# MAX_FEE_RATE = 300000
# FEE_TARGETS = [25, 10, 5, 2]
#
# COINBASE_MATURITY = 100
# COIN = 100000000

# # supported types of transction outputs
# TYPE_ADDRESS = 0
# TYPE_PUBKEY  = 1
# TYPE_SCRIPT  = 2

# AES encryption
# try:
#     from Cryptodome.Cipher import AES
# except:
# AES = None

# def aes_encrypt_with_iv(key, iv, data):
#     if AES:
#         padlen = 16 - (len(data) % 16)
#         if padlen == 0:
#             padlen = 16
#         data += chr(padlen) * padlen
#         e = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
#         return e
#     else:
#         aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
#         aes = pyaes.Encrypter(aes_cbc)
#         e = aes.feed(data) + aes.feed()  # empty aes.feed() appends pkcs padding
#         return e
#
# def aes_decrypt_with_iv(key, iv, data):
#     if AES:
#         cipher = AES.new(key, AES.MODE_CBC, iv)
#         data = cipher.decrypt(data)
#         padlen = ord(data[-1])
#         for i in data[-padlen:]:
#             if ord(i) != padlen:
#                 raise Exception()
#                 # raise InvalidPassword()
#         return data[0:-padlen]
#     else:
#         aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
#         aes = pyaes.Decrypter(aes_cbc)
#         s = aes.feed(data) + aes.feed()  # empty aes.feed() strips pkcs padding
#         return s
#
# def EncodeAES(secret, s):
#     iv = bytes(os.urandom(16))
#     ct = aes_encrypt_with_iv(secret, iv, s)
#     e = iv + ct
#     return base64.b64encode(e)
#
# def DecodeAES(secret, e):
#     e = bytes(base64.b64decode(e))
#     iv, e = e[:16], e[16:]
#     s = aes_decrypt_with_iv(secret, iv, e)
#     return s
#
# def pw_encode(s, password):
#     if password:
#         secret = Hash(password)
#         return EncodeAES(secret, s.encode("utf8"))
#     else:
#         return s
#
# def pw_decode(s, password):
#     if password is not None:
#         secret = Hash(password)
#         try:
#             d = DecodeAES(secret, s).decode("utf8")
#         except Exception:
#             raise InvalidPassword()
#         return d
#     else:
#         return s


# def rev_hex(s):
#     return s.decode('hex')[::-1].encode('hex')


# def int_to_hex(i, length=1):
#     s = hex(i)[2:].rstrip('L')
#     s = "0"*(2*length - len(s)) + s
#     return rev_hex(s)


# def var_int(i):
#     # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
#     if i<0xfd:
#         return int_to_hex(i)
#     elif i<=0xffff:
#         return "fd"+int_to_hex(i,2)
#     elif i<=0xffffffff:
#         return "fe"+int_to_hex(i,4)
#     else:
#         return "ff"+int_to_hex(i,8)


# def op_push(i):
#     if i<0x4c:
#         return int_to_hex(i)
#     elif i<0xff:
#         return '4c' + int_to_hex(i)
#     elif i<0xffff:
#         return '4d' + int_to_hex(i,2)
#     else:
#         return '4e' + int_to_hex(i,4)


# def sha256(x):
#     return hashlib.sha256(x).digest()
#
#
# def Hash(x):
#     if type(x) is unicode: x=x.encode('utf-8')
#     return sha256(sha256(x))

# hash_encode = lambda x: x[::-1].encode('hex')
# hash_decode = lambda x: x.decode('hex')[::-1]
# hmac_sha_512 = lambda x,y: hmac.new(x, y, hashlib.sha512).digest()

# def is_new_seed(x, prefix=None):
#     if prefix is None: prefix = version.SEED_PREFIX
#     import mnemonic
#     x = mnemonic.normalize_text(x)
#     s = hmac_sha_512("Seed version", x.encode('utf8')).encode('hex')
#     return s.startswith(prefix)


# def is_old_seed(seed):
#     pass
#     # import old_mnemonic
#     # words = seed.strip().split()
#     # try:
#     #     old_mnemonic.mn_decode(words)
#     #     uses_electrum_words = True
#     # except Exception:
#     #     uses_electrum_words = False
#     # try:
#     #     seed.decode('hex')
#     #     is_hex = (len(seed) == 32 or len(seed) == 64)
#     # except Exception:
#     #     is_hex = False
#     # return is_hex or (uses_electrum_words and (len(words) == 12 or len(words) == 24))


# def seed_type(x):
#     if is_old_seed(x):
#         return 'old'
#     elif is_new_seed(x):
#         return 'standard'
#     elif Parameter().TESTNET and is_new_seed(x, version.SEED_PREFIX_SW):
#         return 'segwit'
#     elif is_new_seed(x, version.SEED_PREFIX_2FA):
#         return '2fa'
#     # return ''
#
# is_seed = lambda x: bool(seed_type(x))

# pywallet openssl private key implementation

# def i2o_ECPublicKey(pubkey, compressed=False):
#     # public keys are 65 bytes long (520 bits)
#     # 0x04 + 32-byte X-coordinate + 32-byte Y-coordinate
#     # 0x00 = point at infinity, 0x02 and 0x03 = compressed, 0x04 = uncompressed
#     # compressed keys: <sign> <x> where <sign> is 0x02 if y is even and 0x03 if y is odd
#     if compressed:
#         if pubkey.point.y() & 1:
#             key = '03' + '%064x' % pubkey.point.x()
#         else:
#             key = '02' + '%064x' % pubkey.point.x()
#     else:
#         key = '04' + \
#               '%064x' % pubkey.point.x() + \
#               '%064x' % pubkey.point.y()
#
#     return key.decode('hex')

# end pywallet openssl private key implementation



############ functions from pywallet #####################

# def hash_160(public_key):
    # if 'ANDROID_DATA' in os.environ:
    #     pass
    #     # from Crypto.Hash import RIPEMD
    #     # md = RIPEMD.new()
    # else:
    #     md = hashlib.new('ripemd')
    # md.update(sha256(public_key))
    # return md.digest()

# def hash_160_to_bc_address(h160, addrtype, witness_program_version=1):
#     s = chr(addrtype)
#     if addrtype == Parameter().ADDRTYPE_P2WPKH:
#         s += chr(witness_program_version) + chr(0)
#     s += h160
#     return base_encode(s+Hash(s)[0:4], base=58)

# def bc_address_to_hash_160(addr):
#     bytes = base_decode(addr, 25, base=58)
#     return ord(bytes[0]), bytes[1:21]

# def hash160_to_p2pkh(h160):
#     return hash_160_to_bc_address(h160, Parameter().ADDRTYPE_P2PKH)
#
# def hash160_to_p2sh(h160):
#     return hash_160_to_bc_address(h160, Parameter().ADDRTYPE_P2SH)
#
# def public_key_to_p2pkh(public_key):
#     return hash160_to_p2pkh(hash_160(public_key))
#
# def public_key_to_p2wpkh(public_key):
#     return hash_160_to_bc_address(hash_160(public_key), Parameter().ADDRTYPE_P2WPKH)




# __b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
# assert len(__b58chars) == 58
#
# __b43chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
# assert len(__b43chars) == 43
#
#
# def base_encode(v, base):
#     """ encode v, which is a string of bytes, to base58."""
#     if base == 58:
#         chars = __b58chars
#     elif base == 43:
#         chars = __b43chars
#     long_value = 0L
#     for (i, c) in enumerate(v[::-1]):
#         long_value += (256**i) * ord(c)
#     result = ''
#     while long_value >= base:
#         div, mod = divmod(long_value, base)
#         result = chars[mod] + result
#         long_value = div
#     result = chars[long_value] + result
#     # Bitcoin does a little leading-zero-compression:
#     # leading 0-bytes in the input become leading-1s
#     nPad = 0
#     for c in v:
#         if c == '\0': nPad += 1
#         else: break
#     return (chars[0]*nPad) + result
#
#
# def base_decode(v, length, base):
#     """ decode v into a string of len bytes."""
#     if base == 58:
#         chars = __b58chars
#     elif base == 43:
#         chars = __b43chars
#     long_value = 0L
#     for (i, c) in enumerate(v[::-1]):
#         long_value += chars.find(c) * (base**i)
#     result = ''
#     while long_value >= 256:
#         div, mod = divmod(long_value, 256)
#         result = chr(mod) + result
#         long_value = div
#     result = chr(long_value) + result
#     nPad = 0
#     for c in v:
#         if c == chars[0]: nPad += 1
#         else: break
#     result = chr(0)*nPad + result
#     if length is not None and len(result) != length:
#         return None
#     return result
#
#
# def EncodeBase58Check(vchIn):
#     hash = Hash(vchIn)
#     return base_encode(vchIn + hash[0:4], base=58)
#
#
# def DecodeBase58Check(psz):
#     vchRet = base_decode(psz, None, base=58)
#     key = vchRet[0:-4]
#     csum = vchRet[-4:]
#     hash = Hash(key)
#     cs32 = hash[0:4]
#     if cs32 != csum:
#         return None
#     else:
#         return key


# def PrivKeyToSecret(privkey):
#     return privkey[9:9+32]
#
#
# def SecretToASecret(secret, compressed=False):
#     addrtype = Parameter().ADDRTYPE_P2PKH
#     vchIn = chr((addrtype+128)&255) + secret
#     if compressed: vchIn += '\01'
#     return EncodeBase58Check(vchIn)
#
# def ASecretToSecret(key):
#     addrtype = Parameter().ADDRTYPE_P2PKH
#     vch = DecodeBase58Check(key)
#     if vch and vch[0] == chr((addrtype+128)&255):
#         return vch[1:]
#     elif is_minikey(key):
#         return minikey_to_private_key(key)
#     else:
#         return False
#
# def regenerate_key(sec):
#     b = ASecretToSecret(sec)
#     if not b:
#         return False
#     b = b[0:32]
#     return EC_KEY(b)
#
#
# def GetPubKey(pubkey, compressed=False):
#     return i2o_ECPublicKey(pubkey, compressed)
#
#
# def GetSecret(pkey):
#     return ('%064x' % pkey.secret).decode('hex')
#
#
# def is_compressed(sec):
#     b = ASecretToSecret(sec)
#     return len(b) == 33
#
#
# def public_key_from_private_key(sec):
#     # rebuild public key from private key, compressed or uncompressed
#     pkey = regenerate_key(sec)
#     assert pkey
#     compressed = is_compressed(sec)
#     public_key = GetPubKey(pkey.pubkey, compressed)
#     return public_key.encode('hex')
#
#
# def address_from_private_key(sec):
#     public_key = public_key_from_private_key(sec)
#     address = public_key_to_p2pkh(public_key.decode('hex'))
#     return address


# def is_valid(addr):
#     return is_address(addr)
#
#
# def is_address(addr):
#     try:
#         addrtype, h = bc_address_to_type_and_hash_160(addr)
#     except Exception:
#         return False
#     if addrtype not in [Parameter().ADDRTYPE_P2PKH, Parameter().ADDRTYPE_P2SH]:
#         return False
#     return addr == hash_160_to_bc_address(h, addrtype)
#
# def is_p2pkh(addr):
#     if is_address(addr):
#         addrtype, h = bc_address_to_type_and_hash_160(addr)
#         return addrtype == Parameter().ADDRTYPE_P2PKH
#
# def is_p2sh(addr):
#     if is_address(addr):
#         addrtype, h = bc_address_to_type_and_hash_160(addr)
#         return addrtype == Parameter().ADDRTYPE_P2SH

# def is_private_key(key):
#     try:
#         k = ASecretToSecret(key)
#         return k is not False
#     except:
#         return False


########### end pywallet functions #######################

# def is_minikey(text):
#     # Minikeys are typically 22 or 30 characters, but this routine
#     # permits any length of 20 or more provided the minikey is valid.
#     # A valid minikey must begin with an 'S', be in base58, and when
#     # suffixed with '?' have its SHA256 hash begin with a zero byte.
#     # They are widely used in Casascius physical bitoins.
#     return (len(text) >= 20 and text[0] == 'S'
#             and all(c in __b58chars for c in text)
#             and ord(sha256(text + '?')[0]) == 0)
#
# def minikey_to_private_key(text):
#     return sha256(text)

# from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1
# from ecdsa.curves import SECP256k1
# from ecdsa.ellipticcurve import Point
# from ecdsa.util import string_to_number, number_to_string

# def msg_magic(message):
#     varint = var_int(len(message))
#     encoded_varint = "".join([chr(int(varint[i:i+2], 16)) for i in xrange(0, len(varint), 2)])
#     return "\x18Bitcoin Signed Message:\n" + encoded_varint + message
#
#
# def verify_message(address, sig, message):
#     try:
#         public_key, compressed = pubkey_from_signature(sig, message)
#         # check public key using the address
#         pubkey = point_to_ser(public_key.pubkey.point, compressed)
#         addr = public_key_to_p2pkh(pubkey)
#         if address != addr:
#             raise Exception("Bad signature")
#         # check message
#         h = Hash(msg_magic(message))
#         public_key.verify_digest(sig[1:], h, sigdecode = ecdsa.util.sigdecode_string)
#         return True
#     except Exception as e:
#         print_error("Verification error: {0}".format(e))
#         return False
#
#
# def encrypt_message(message, pubkey):
#     return EC_KEY.encrypt_message(message, pubkey.decode('hex'))


# def chunks(l, n):
#     return [l[i:i+n] for i in xrange(0, len(l), n)]


# def ECC_YfromX(x,curved=curve_secp256k1, odd=True):
#     _p = curved.p()
#     _a = curved.a()
#     _b = curved.b()
#     for offset in range(128):
#         Mx = x + offset
#         My2 = pow(Mx, 3, _p) + _a * pow(Mx, 2, _p) + _b % _p
#         My = pow(My2, (_p+1)/4, _p )
#
#         if curved.contains_point(Mx,My):
#             if odd == bool(My&1):
#                 return [My,offset]
#             return [_p-My,offset]
#     raise Exception('ECC_YfromX: No Y found')


# def negative_point(P):
#     return Point( P.curve(), P.x(), -P.y(), P.order() )


# def point_to_ser(P, comp=True ):
#     if comp:
#         return ( ('%02x'%(2+(P.y()&1)))+('%064x'%P.x()) ).decode('hex')
#     return ( '04'+('%064x'%P.x())+('%064x'%P.y()) ).decode('hex')


# def ser_to_point(Aser):
#     curve = curve_secp256k1
#     generator = generator_secp256k1
#     _r  = generator.order()
#     assert Aser[0] in ['\x02','\x03','\x04']
#     if Aser[0] == '\x04':
#         return Point( curve, string_to_number(Aser[1:33]), string_to_number(Aser[33:]), _r )
#     Mx = string_to_number(Aser[1:])
#     return Point( curve, Mx, ECC_YfromX(Mx, curve, Aser[0]=='\x03')[0], _r )



# class MyVerifyingKey(ecdsa.VerifyingKey):
#     @classmethod
#     def from_signature(klass, sig, recid, h, curve):
#         """ See http://www.secg.org/download/aid-780/sec1-v2.pdf, chapter 4.1.6 """
#         from ecdsa import util, numbertheory
#         import msqr
#         curveFp = curve.curve
#         G = curve.generator
#         order = G.order()
#         # extract r,s from signature
#         r, s = util.sigdecode_string(sig, order)
#         # 1.1
#         x = r + (recid/2) * order
#         # 1.3
#         alpha = ( x * x * x  + curveFp.a() * x + curveFp.b() ) % curveFp.p()
#         beta = msqr.modular_sqrt(alpha, curveFp.p())
#         y = beta if (beta - recid) % 2 == 0 else curveFp.p() - beta
#         # 1.4 the constructor checks that nR is at infinity
#         R = Point(curveFp, x, y, order)
#         # 1.5 compute e from message:
#         e = string_to_number(h)
#         minus_e = -e % order
#         # 1.6 compute Q = r^-1 (sR - eG)
#         inv_r = numbertheory.inverse_mod(r,order)
#         Q = inv_r * ( s * R + minus_e * G )
#         return klass.from_public_point( Q, curve )


# def pubkey_from_signature(sig, message):
#     if len(sig) != 65:
#         raise Exception("Wrong encoding")
#     nV = ord(sig[0])
#     if nV < 27 or nV >= 35:
#         raise Exception("Bad encoding")
#     if nV >= 31:
#         compressed = True
#         nV -= 4
#     else:
#         compressed = False
#     recid = nV - 27
#     h = Hash(msg_magic(message))
#     return MyVerifyingKey.from_signature(sig[1:], recid, h, curve = SECP256k1), compressed


# class MySigningKey(ecdsa.SigningKey):
#     """Enforce low S values in signatures"""
#
#     def sign_number(self, number, entropy=None, k=None):
#         curve = SECP256k1
#         G = curve.generator
#         order = G.order()
#         r, s = ecdsa.SigningKey.sign_number(self, number, entropy, k)
#         if s > order/2:
#             s = order - s
#         return r, s


# class EC_KEY(object):
#
#     def __init__( self, k ):
#         secret = string_to_number(k)
#         self.pubkey = ecdsa.ecdsa.Public_key( generator_secp256k1, generator_secp256k1 * secret )
#         self.privkey = ecdsa.ecdsa.Private_key( self.pubkey, secret )
#         self.secret = secret
#
#     def get_public_key(self, compressed=True):
#         return point_to_ser(self.pubkey.point, compressed).encode('hex')
#
#     def sign(self, msg_hash):
#         private_key = MySigningKey.from_secret_exponent(self.secret, curve = SECP256k1)
#         public_key = private_key.get_verifying_key()
#         signature = private_key.sign_digest_deterministic(msg_hash, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_string)
#         assert public_key.verify_digest(signature, msg_hash, sigdecode = ecdsa.util.sigdecode_string)
#         return signature
#
#     def sign_message(self, message, is_compressed):
#         signature = self.sign(Hash(msg_magic(message)))
#         for i in range(4):
#             sig = chr(27 + i + (4 if is_compressed else 0)) + signature
#             try:
#                 self.verify_message(sig, message)
#                 return sig
#             except Exception:
#                 continue
#         else:
#             raise Exception("error: cannot sign message")
#
#
#     def verify_message(self, sig, message):
#         public_key, compressed = pubkey_from_signature(sig, message)
#         # check public key
#         if point_to_ser(public_key.pubkey.point, compressed) != point_to_ser(self.pubkey.point, compressed):
#             raise Exception("Bad signature")
#         # check message
#         h = Hash(msg_magic(message))
#         public_key.verify_digest(sig[1:], h, sigdecode = ecdsa.util.sigdecode_string)
#
#
#     # ECIES encryption/decryption methods; AES-128-CBC with PKCS7 is used as the cipher; hmac-sha256 is used as the mac
#
#     @classmethod
#     def encrypt_message(self, message, pubkey):
#
#         pk = ser_to_point(pubkey)
#         if not ecdsa.ecdsa.point_is_valid(generator_secp256k1, pk.x(), pk.y()):
#             raise Exception('invalid pubkey')
#
#         ephemeral_exponent = number_to_string(ecdsa.util.randrange(pow(2,256)), generator_secp256k1.order())
#         ephemeral = EC_KEY(ephemeral_exponent)
#         ecdh_key = point_to_ser(pk * ephemeral.privkey.secret_multiplier)
#         key = hashlib.sha512(ecdh_key).digest()
#         iv, key_e, key_m = key[0:16], key[16:32], key[32:]
#         ciphertext = aes_encrypt_with_iv(key_e, iv, message)
#         ephemeral_pubkey = ephemeral.get_public_key(compressed=True).decode('hex')
#         encrypted = 'BIE1' + ephemeral_pubkey + ciphertext
#         mac = hmac.new(key_m, encrypted, hashlib.sha256).digest()
#
#         return base64.b64encode(encrypted + mac)
#
#
#     def decrypt_message(self, encrypted):
#         encrypted = base64.b64decode(encrypted)
#         if len(encrypted) < 85:
#             raise Exception('invalid ciphertext: length')
#         magic = encrypted[:4]
#         ephemeral_pubkey = encrypted[4:37]
#         ciphertext = encrypted[37:-32]
#         mac = encrypted[-32:]
#         if magic != 'BIE1':
#             raise Exception('invalid ciphertext: invalid magic bytes')
#         try:
#             ephemeral_pubkey = ser_to_point(ephemeral_pubkey)
#         except AssertionError, e:
#             raise Exception('invalid ciphertext: invalid ephemeral pubkey')
#         if not ecdsa.ecdsa.point_is_valid(generator_secp256k1, ephemeral_pubkey.x(), ephemeral_pubkey.y()):
#             raise Exception('invalid ciphertext: invalid ephemeral pubkey')
#         ecdh_key = point_to_ser(ephemeral_pubkey * self.privkey.secret_multiplier)
#         key = hashlib.sha512(ecdh_key).digest()
#         iv, key_e, key_m = key[0:16], key[16:32], key[32:]
#         if mac != hmac.new(key_m, encrypted[:-32], hashlib.sha256).digest():
#             raise InvalidPassword()
#         return aes_decrypt_with_iv(key_e, iv, ciphertext)




# class InvalidPassword(Exception):
#     def __str__(self):
#         return ''
#         # return _("Incorrect password")
