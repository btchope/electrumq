# -*- coding: utf-8 -*-
import traceback

import ecdsa
from ecdsa import SECP256k1
from ecdsa.util import string_to_number

from utils.base58 import Hash, public_key_to_p2pkh, b58decode_check, b58encode_check, \
    hash_160_to_bc_address
from utils.bip32 import bip32_public_derivation, deserialize_xpub, CKD_pub, deserialize_xprv, \
    xpub_from_xprv, bip32_root, bip32_private_derivation, bip32_private_key
from utils.key import is_compressed, public_key_from_private_key, pw_encode, InvalidPassword, \
    pw_decode
from utils.key import regenerate_key
from utils.mnemonic import Mnemonic, is_new_seed, is_old_seed
from utils.parameter import Parameter
from utils.parser import write_uint16, read_uint16

__author__ = 'zhouqi'


class KeyStore(object):
    def has_seed(self):
        return False

    def is_watching_only(self):
        return False

    def can_import(self):
        return False

    def get_tx_derivations(self, tx):
        keypairs = {}
        for txin in tx.inputs():
            num_sig = txin.get('num_sig')
            if num_sig is None:
                continue
            x_signatures = txin['signatures']
            signatures = filter(None, x_signatures)
            if len(signatures) == num_sig:
                # input is complete
                continue
            for k, x_pubkey in enumerate(txin['x_pubkeys']):
                if x_signatures[k] is not None:
                    # this pubkey already signed
                    continue
                derivation = self.get_pubkey_derivation(x_pubkey)
                if not derivation:
                    continue
                keypairs[x_pubkey] = derivation
        return keypairs

    def can_sign(self, tx):
        if self.is_watching_only():
            return False
        return bool(self.get_tx_derivations(tx))

    def get_pubkey_derivation(self, x_pubkey):
        pass

    def is_segwit(self):
        return False

    def get_private_key(self, pubkey, password):
        pass

    def may_have_password(self):
        return not self.is_watching_only()

    def sign_message(self, sequence, message, password):
        sec = self.get_private_key(sequence, password)
        key = regenerate_key(sec)
        compressed = is_compressed(sec)
        return key.sign_message(message, compressed)

    def decrypt_message(self, sequence, message, password):
        sec = self.get_private_key(sequence, password)
        ec = regenerate_key(sec)
        decrypted = ec.decrypt_message(message)
        return decrypted

    def sign_transaction(self, tx, password):
        if self.is_watching_only():
            return
        # Raise if password is not correct.
        self.check_password(password)
        # Add private keys
        keypairs = self.get_tx_derivations(tx)
        for k, v in keypairs.items():
            keypairs[k] = self.get_private_key(v, password)
        # Sign
        if keypairs:
            tx.sign(keypairs)

    def check_password(self, password):
        pass


class SoftwareKeyStore(KeyStore):
    pass


class ImportedKeyStore(SoftwareKeyStore):
    # keystore for imported private keys

    def __init__(self, d):
        SoftwareKeyStore.__init__(self)
        self.keypairs = d.get('keypairs', {})

    def is_deterministic(self):
        return False

    def can_change_password(self):
        return True

    def get_master_public_key(self):
        return None

    def dump(self):
        return {
            'type': 'imported',
            'keypairs': self.keypairs,
        }

    def can_import(self):
        return True

    def check_password(self, password):
        pubkey = self.keypairs.keys()[0]
        self.get_private_key(pubkey, password)

    def import_key(self, sec, password):
        try:
            pubkey = public_key_from_private_key(sec)
        except Exception:
            traceback.print_exc()
            raise BaseException('Invalid private key')
        # allow overwrite
        self.keypairs[pubkey] = pw_encode(sec, password)
        return pubkey

    def delete_imported_key(self, key):
        self.keypairs.pop(key)

    def get_private_key(self, pubkey, password):
        pk = pw_decode(self.keypairs[pubkey], password)
        # this checks the password
        if pubkey != public_key_from_private_key(pk):
            raise InvalidPassword()
        return pk

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey[0:2] in ['02', '03', '04']:
            if x_pubkey in self.keypairs.keys():
                return x_pubkey
        elif x_pubkey[0:2] == 'fd':
            # fixme: this assumes p2pkh
            _, addr = xpubkey_to_address(x_pubkey)
            for pubkey in self.keypairs.keys():
                if public_key_to_p2pkh(pubkey.decode('hex')) == addr:
                    return pubkey

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        for k, v in self.keypairs.items():
            b = pw_decode(v, old_password)
            c = pw_encode(b, new_password)
            self.keypairs[k] = c


class SimpleKeyStore(SoftwareKeyStore):
    def __init__(self, d):
        SoftwareKeyStore.__init__(self)
        self.pub_key = d.get('pub_key', None)
        self.encrypt_priv_key = d.get('encrypt_priv_key', None)
        self.address = d.get('address', None)

    @property
    def keypairs(self):
        return {self.pub_key: self.encrypt_priv_key}

    def is_deterministic(self):
        return False

    def can_change_password(self):
        return True

    def get_master_public_key(self):
        return None

    def dump(self):
        return {
            'type': 'simple',
            'pub_key': self.pub_key,
            'encrypt_priv_key': self.encrypt_priv_key,
            'address': self.address
        }

    def can_import(self):
        return True

    def check_password(self, password):
        pubkey = self.pub_key
        self.get_private_key(pubkey, password)

    @classmethod
    def create(cls, sec, password):
        try:
            pubkey = public_key_from_private_key(sec)
        except Exception:
            traceback.print_exc()
            raise BaseException('Invalid private key')
        return SimpleKeyStore(
            {'type': 'simple', 'pub_key': pubkey, 'encrypt_priv_key': pw_encode(sec, password),
             'address': public_key_to_p2pkh(pubkey.decode('hex'))})

    def get_private_key(self, pubkey, password):
        pk = pw_decode(self.encrypt_priv_key, password)
        # this checks the password
        if pubkey != public_key_from_private_key(pk):
            raise InvalidPassword()
        return pk

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey[0:2] in ['02', '03', '04']:
            if x_pubkey == self.pub_key:
                return x_pubkey
        elif x_pubkey[0:2] == 'fd':
            # fixme: this assumes p2pkh
            _, addr = xpubkey_to_address(x_pubkey)
            if public_key_to_p2pkh(self.pub_key.decode('hex')) == addr:
                return self.pub_key

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        # for k, v in self.keypairs.items():
        b = pw_decode(self.encrypt_priv_key, old_password)
        self.encrypt_priv_key = pw_encode(b, new_password)


class WatchOnlySimpleKeyStore(SimpleKeyStore):
    def __init__(self, d):
        SoftwareKeyStore.__init__(self)
        self.pub_key = d.get('pub_key', None)
        self.address = d.get('address', None)

    @property
    def keypairs(self):
        return {self.pub_key: self}

    def is_deterministic(self):
        return False

    def can_change_password(self):
        return True

    def get_master_public_key(self):
        return None

    def dump(self):
        return {
            'type': 'watchonly',
            'pub_key': self.pub_key,
            'address': self.address,
        }

    def can_import(self):
        return True

    def check_password(self, password):
        return True

    @classmethod
    def create(cls, sec, password):
        try:
            pubkey = public_key_from_private_key(sec)
        except Exception:
            traceback.print_exc()
            raise BaseException('Invalid private key')
        return WatchOnlySimpleKeyStore({'type': 'simple', 'pub_key': pubkey,
                                        'address': public_key_to_p2pkh(pubkey.decode('hex'))})

    def get_private_key(self, pubkey, password):
        return None

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey[0:2] in ['02', '03', '04']:
            if x_pubkey == self.pub_key:
                return x_pubkey
        elif x_pubkey[0:2] == 'fd':
            # fixme: this assumes p2pkh
            _, addr = xpubkey_to_address(x_pubkey)
            if public_key_to_p2pkh(self.pub_key.decode('hex')) == addr:
                return self.pub_key

    def update_password(self, old_password, new_password):
        pass


class Deterministic_KeyStore(SoftwareKeyStore):
    def __init__(self, d):
        SoftwareKeyStore.__init__(self)
        self.seed = d.get('seed', '')
        self.passphrase = d.get('passphrase', '')

    def is_deterministic(self):
        return True

    def dump(self):
        d = {}
        if self.seed:
            d['seed'] = self.seed
        if self.passphrase:
            d['passphrase'] = self.passphrase
        return d

    def has_seed(self):
        return bool(self.seed)

    def is_watching_only(self):
        return not self.has_seed()

    def can_change_password(self):
        return not self.is_watching_only()

    def add_seed(self, seed):
        if self.seed:
            raise Exception("a seed exists")
        self.seed = self.format_seed(seed)

    def format_seed(self, seed):
        return ' '.join(seed.split())

    def get_seed(self, password):
        return pw_decode(self.seed, password)

    def get_passphrase(self, password):
        return pw_decode(self.passphrase, password) if self.passphrase else ''


class Xpub:
    def __init__(self):
        self.xpub = None
        self.xpub_receive = None
        self.xpub_change = None

    def get_master_public_key(self):
        return self.xpub

    def derive_pubkey(self, for_change, n):
        xpub = self.xpub_change if for_change else self.xpub_receive
        if xpub is None:
            xpub = bip32_public_derivation(self.xpub, "", "/%d" % for_change)
            if for_change:
                self.xpub_change = xpub
            else:
                self.xpub_receive = xpub
        return self.get_pubkey_from_xpub(xpub, (n,))

    @classmethod
    def get_pubkey_from_xpub(self, xpub, sequence):
        _, _, _, _, c, cK = deserialize_xpub(xpub)
        for i in sequence:
            cK, c = CKD_pub(cK, c, i)
        return cK.encode('hex')

    def get_xpubkey(self, c, i):
        s = write_uint16(c) + write_uint16(i)
        return 'ff' + b58decode_check(self.xpub).encode('hex') + s.encode('hex')

    @classmethod
    def parse_xpubkey(self, pubkey):
        assert pubkey[0:2] == 'ff'
        pk = pubkey.decode('hex')
        pk = pk[1:]
        xkey = b58encode_check(pk[0:78])
        dd = pk[78:]
        s = []
        while dd:
            n = read_uint16(dd[:2])
            dd = dd[2:]
            s.append(n)
        assert len(s) == 2
        return xkey, s

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey[0:2] != 'ff':
            return
        xpub, derivation = self.parse_xpubkey(x_pubkey)
        if self.xpub != xpub:
            return
        return derivation


class BIP32_KeyStore(Deterministic_KeyStore, Xpub):
    def __init__(self, d):
        Deterministic_KeyStore.__init__(self, d)
        Xpub.__init__(self)

    def dump(self):
        d = Deterministic_KeyStore.dump(self)
        d['type'] = 'bip32'
        d['xpub'] = self.xpub
        d['xprv'] = self.xprv
        return d

    def get_master_private_key(self, password):
        return pw_decode(self.xprv, password)

    def check_password(self, password):
        xprv = pw_decode(self.xprv, password)
        if deserialize_xprv(xprv)[4] != deserialize_xpub(self.xpub)[4]:
            raise InvalidPassword()

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        if self.has_seed():
            decoded = self.get_seed(old_password)
            self.seed = pw_encode(decoded, new_password)
        if self.passphrase:
            decoded = self.get_passphrase(old_password)
            self.passphrase = pw_encode(decoded, new_password)
        if self.xprv is not None:
            b = pw_decode(self.xprv, old_password)
            self.xprv = pw_encode(b, new_password)

    def is_watching_only(self):
        return self.xprv is None

    def add_xprv(self, xprv):
        self.xprv = xprv
        self.xpub = xpub_from_xprv(xprv)

    def add_xprv_from_seed(self, bip32_seed, xtype, derivation):
        xprv, xpub = bip32_root(bip32_seed, xtype)
        xprv, xpub = bip32_private_derivation(xprv, "m/", derivation)
        self.add_xprv(xprv)

    def get_private_key(self, sequence, password):
        xprv = self.get_master_private_key(password)
        _, _, _, _, c, k = deserialize_xprv(xprv)
        pk = bip32_private_key(sequence, k, c)
        return pk

    def is_segwit(self):
        return bool(deserialize_xpub(self.xpub)[0])

    def get_pubkey_derivation(self, x_pubkey):
        return Xpub.get_pubkey_derivation(self, x_pubkey)


class Old_KeyStore(Deterministic_KeyStore):
    def __init__(self, d):
        super(Old_KeyStore, self).__init__(d)

    @classmethod
    def get_sequence(cls, mpk, for_change, n):
        return string_to_number(Hash("%d:%d:" % (n, for_change) + mpk.decode('hex')))

    @classmethod
    def parse_xpubkey(cls, x_pubkey):
        assert x_pubkey[0:2] == 'fe'
        pk = x_pubkey[2:]
        mpk = pk[0:128]
        dd = pk[128:]
        s = []
        while dd:
            n = read_uint16(dd[:4].decode('hex'))
            dd = dd[4:]
            s.append(n)
        assert len(s) == 2
        return mpk, s

    @classmethod
    def get_pubkey_from_mpk(cls, mpk, for_change, n):
        z = cls.get_sequence(mpk, for_change, n)
        master_public_key = ecdsa.VerifyingKey.from_string(mpk.decode('hex'), curve=SECP256k1)
        pubkey_point = master_public_key.pubkey.point + z * SECP256k1.generator
        public_key2 = ecdsa.VerifyingKey.from_public_point(pubkey_point, curve=SECP256k1)
        return '04' + public_key2.to_string().encode('hex')


class Hardware_KeyStore(KeyStore, Xpub):
    pass


def xpubkey_to_address(x_pubkey):
    address = None
    if x_pubkey[0:2] == 'fd':
        addrtype = ord(x_pubkey[2:4].decode('hex'))
        hash160 = x_pubkey[4:].decode('hex')
        address = hash_160_to_bc_address(hash160, addrtype)
        return x_pubkey, address
    if x_pubkey[0:2] in ['02', '03', '04']:
        pubkey = x_pubkey
    elif x_pubkey[0:2] == 'ff':
        xpub, s = BIP32_KeyStore.parse_xpubkey(x_pubkey)
        pubkey = BIP32_KeyStore.get_pubkey_from_xpub(xpub, s)
    elif x_pubkey[0:2] == 'fe':
        mpk, s = Old_KeyStore.parse_xpubkey(x_pubkey)
        pubkey = Old_KeyStore.get_pubkey_from_mpk(mpk, s[0], s[1])
    else:
        raise BaseException("Cannot parse pubkey")
    if pubkey:
        address = public_key_to_p2pkh(pubkey.decode('hex'))
    return pubkey, address


def xpubkey_to_pubkey(x_pubkey):
    pubkey, address = xpubkey_to_address(x_pubkey)
    return pubkey


def bip44_derivation(account_id):
    if Parameter().TESTNET:
        return "m/44'/1'/%d'" % int(account_id)
    else:
        return "m/44'/0'/%d'" % int(account_id)


hw_keystores = {}


def register_keystore(hw_type, constructor):
    hw_keystores[hw_type] = constructor


def hardware_keystore(d):
    hw_type = d['hw_type']
    if hw_type in hw_keystores:
        constructor = hw_keystores[hw_type]
        return constructor(d)
    raise BaseException('unknown hardware type', hw_type)


def load_keystore(storage, name):
    w = storage.get('wallet_type', 'standard')
    d = storage.get(name, {})
    t = d.get('type')
    if not t:
        raise BaseException('wallet format requires update')
    if t == 'old':
        k = Old_KeyStore(d)
    elif t == 'imported':
        k = ImportedKeyStore(d)
    elif t == 'simple':
        k = SimpleKeyStore(d)
    elif t == 'watchonly':
        k = WatchOnlySimpleKeyStore(d)
    elif t == 'bip32':
        k = from_seed(d['seed'], d.get('passphrase', None))#BIP32_KeyStore(d)
    elif t == 'hardware':
        k = hardware_keystore(d)
    else:
        raise BaseException('unknown wallet type', t)
    return k


def from_seed(seed, passphrase):
    t = seed_type(seed)
    keystore = None
    if t == 'old':
        keystore = Old_KeyStore({})
        keystore.add_seed(seed)
    elif t in ['standard', 'segwit']:
        keystore = BIP32_KeyStore({})
        keystore.add_seed(seed)
        keystore.passphrase = passphrase
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, passphrase)
        xtype = 0 if t == 'standard' else 1
        keystore.add_xprv_from_seed(bip32_seed, xtype, "m/")
    return keystore


def seed_type(x):
    if is_old_seed(x):
        return 'old'
    elif is_new_seed(x):
        return 'standard'
    elif Parameter().TESTNET and is_new_seed(x, Parameter().SEED_PREFIX_SW):
        return 'segwit'
    elif is_new_seed(x, Parameter().SEED_PREFIX_2FA):
        return '2fa'
    return ''


def is_seed(x):
    return bool(seed_type(x))
