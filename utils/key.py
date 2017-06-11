# -*- coding: utf-8 -*-
import traceback

from utils import InvalidPassword, public_key_from_private_key, pw_decode, pw_encode, \
    public_key_to_p2pkh, regenerate_key, is_compressed, bip32_public_derivation, \
    hash_160_to_bc_address, rev_hex, EncodeBase58Check, DecodeBase58Check, int_to_hex, CKD_pub, \
    deserialize_xpub
from utils import Parameter

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
        # self.keypairs = d.get('keypairs', {})

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
            'pub_key':self.pub_key,
            'encrypt_priv_key': self.encrypt_priv_key,
            # 'keypairs': self.keypairs,
        }

    def can_import(self):
        return True

    def check_password(self, password):
        pubkey = self.pub_key
        self.get_private_key(pubkey, password)

    # def import_key(self, sec, password):
    #     try:
    #         pubkey = public_key_from_private_key(sec)
    #     except Exception:
    #         traceback.print_exc()
    #         raise BaseException('Invalid private key')
    #     # allow overwrite
    #     self.keypairs[pubkey] = pw_encode(sec, password)
    #     return pubkey

    @classmethod
    def create(cls, sec, password):
        try:
            pubkey = public_key_from_private_key(sec)
        except Exception:
            traceback.print_exc()
            raise BaseException('Invalid private key')
        # allow overwrite
        # self.keypairs[pubkey] = pw_encode(sec, password)
        return SimpleKeyStore({'type': 'simple', 'pub_key': pubkey, 'encrypt_priv_key': pw_encode(sec, password)})

    # def delete_imported_key(self, key):
    #     self.keypairs.pop(key)

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
            # self.keypairs[k] = c

class Deterministic_KeyStore(SoftwareKeyStore):
    pass


class Xpub:
    pass

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
        s = ''.join(map(lambda x: int_to_hex(x, 2), (c, i)))
        return 'ff' + DecodeBase58Check(self.xpub).encode('hex') + s

    @classmethod
    def parse_xpubkey(self, pubkey):
        assert pubkey[0:2] == 'ff'
        pk = pubkey.decode('hex')
        pk = pk[1:]
        xkey = EncodeBase58Check(pk[0:78])
        dd = pk[78:]
        s = []
        while dd:
            n = int(rev_hex(dd[0:2].encode('hex')), 16)
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
    pass


class Old_KeyStore(Deterministic_KeyStore):
    pass


class Hardware_KeyStore(KeyStore, Xpub):
    pass


def xpubkey_to_address(x_pubkey):
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
        return "m/44'/1'/%d'"% int(account_id)
    else:
        return "m/44'/0'/%d'"% int(account_id)


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
    elif t == 'bip32':
        k = BIP32_KeyStore(d)
    elif t == 'hardware':
        k = hardware_keystore(d)
    else:
        raise BaseException('unknown wallet type', t)
    return k
