# -*- coding: utf-8 -*-
import traceback

from electrumq.secret.key import regenerate_key, is_compressed, public_key_from_private_key, \
    InvalidPassword, pw_decode, pw_encode
from electrumq.tx.script import xpubkey_to_address
from electrumq.utils.base58 import public_key_to_p2pkh, hash_160_to_bc_address

__author__ = 'zhouqi'


class KeyStore(object):
    def __init__(self):
        self._has_seed = False
        self._is_watching_only = False
        self._can_import = False
        self._is_segwit = False
        self._is_deterministic = False
        self._can_change_password = True

    def has_seed(self):
        return self._has_seed

    def is_watching_only(self):
        return self._is_watching_only

    def may_have_password(self):
        return not self.is_watching_only()

    def can_import(self):
        return self._can_import

    def is_segwit(self):
        return self._is_segwit

    def is_deterministic(self):
        return self._is_deterministic

    def dump(self):
        pass

    def can_change_password(self):
        return self._can_change_password

    def check_password(self, password):
        pass

    def update_password(self, old_password, new_password):
        pass

    def sign_transaction(self, tx, password):
        if self.is_watching_only():
            return
        # Raise if password is not correct.
        self.check_password(password)
        # Add private keys
        keypairs = self._get_tx_derivations(tx)
        for k, v in keypairs.items():
            keypairs[k] = self._get_private_key(v, password)
        # Sign
        if keypairs:
            tx.sign(keypairs)

    def can_sign(self, tx):
        if self.is_watching_only():
            return False
        return bool(self._get_tx_derivations(tx))

    def _get_tx_derivations(self, tx):
        keypairs = {}
        for txin in tx.input_list():
            num_sig = txin.in_dict.get('num_sig')
            if num_sig is None:
                continue
            x_signatures = txin.in_dict['signatures']
            signatures = filter(None, x_signatures)
            if len(signatures) == num_sig:
                # input is complete
                continue
            for k, x_pubkey in enumerate(txin.in_dict['x_pubkeys']):
                if x_signatures[k] is not None:
                    # this pubkey already signed
                    continue
                derivation = self._get_pubkey_derivation(x_pubkey)
                if not derivation:
                    continue
                keypairs[x_pubkey] = derivation
        return keypairs

    def _get_pubkey_derivation(self, x_pubkey):
        pass

    def _get_private_key(self, pubkey, password):
        pass

    def sign_message(self, sequence, message, password):
        sec = self._get_private_key(sequence, password)
        key = regenerate_key(sec)
        compressed = is_compressed(sec)
        return key.sign_message(message, compressed)

    def decrypt_message(self, sequence, message, password):
        sec = self._get_private_key(sequence, password)
        ec = regenerate_key(sec)
        decrypted = ec.decrypt_message(message)
        return decrypted

class SimpleKeyStore(KeyStore):
    def __init__(self, d):
        KeyStore.__init__(self)
        self._can_import = True
        self.pub_key = d.get('pub_key', None)
        self.encrypt_priv_key = d.get('encrypt_priv_key', None)
        self.address = d.get('address', None)

    @property
    def keypairs(self):
        return {self.pub_key: self.encrypt_priv_key}

    def get_master_public_key(self):
        return None

    def dump(self):
        return {
            'type': 'simple',
            'pub_key': self.pub_key,
            'encrypt_priv_key': self.encrypt_priv_key,
            'address': self.address
        }

    def check_password(self, password):
        pubkey = self.pub_key
        self._get_private_key(pubkey, password)

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

    def _get_private_key(self, pubkey, password):
        pk = pw_decode(self.encrypt_priv_key, password)
        # this checks the password
        if pubkey != public_key_from_private_key(pk):
            raise InvalidPassword()
        return pk

    def _get_pubkey_derivation(self, x_pubkey):
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



def load_keystore(storage, name):
    w = storage.get('wallet_type', 'standard')
    d = storage.get(name, {})
    t = d.get('type')
    if not t:
        raise BaseException('wallet format requires update')
    # if t == 'old':
    #     k = OldKeyStore(d)
    # elif t == 'imported':
    #     k = ImportedKeyStore(d)
    elif t == 'simple':
        k = SimpleKeyStore(d)
    # elif t == 'watchonly':
    #     k = WatchOnlySimpleKeyStore(d)
    # elif t == 'bip32':
    #     k = from_seed(d['seed'], d.get('passphrase', None))  # BIP32_KeyStore(d)
    # elif t == 'bip32watchonly':
    #     k = BIP32KeyHotStore(d)#from_seed(d['seed'], d.get('passphrase', None))  # BIP32_KeyStore(d)
    # elif t == 'hardware':
    #     k = hardware_keystore(d)
    else:
        raise BaseException('unknown wallet type', t)
    return k