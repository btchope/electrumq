# -*- coding: utf-8 -*-
import traceback

from db.mem.tx import xpubkey_to_address, SecretToASecret
from utils import InvalidPassword, public_key_from_private_key, pw_decode, pw_encode, \
    public_key_to_p2pkh, regenerate_key, is_compressed, ASecretToSecret

__author__ = 'zhouqi'

class KeyStore():

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
        if x_pubkey[0:2] in ['02', '03', '04']:
            return x_pubkey
            # if x_pubkey in self.keypairs.keys():
            #     return x_pubkey
        elif x_pubkey[0:2] == 'fd':
            # fixme: this assumes p2pkh
            pubkey, addr = xpubkey_to_address(x_pubkey)
            return pubkey
            # for pubkey in self.keypairs.keys():
            #     if public_key_to_p2pkh(pubkey.decode('hex')) == addr:
            #         return pubkey

    def is_segwit(self):
        return False

    def sign_transaction(self, tx, password):
        if self.is_watching_only():
            return
        # Raise if password is not correct.
        # self.check_password(password)
        # Add private keys
        keypairs = self.get_tx_derivations(tx)
        for k, v in keypairs.items():
            # todo:
            keypairs[k] = SecretToASecret('\x09'*32, True)  #self.get_private_key(v, password)
        # Sign
        if keypairs:
            tx.sign(keypairs)


class Software_KeyStore(KeyStore):

    def __init__(self):
        KeyStore.__init__(self)

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

class Imported_KeyStore(Software_KeyStore):
    # keystore for imported private keys

    def __init__(self, d):
        # Software_KeyStore.__init__(self)
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