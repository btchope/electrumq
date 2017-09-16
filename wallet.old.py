# -*- coding: utf-8 -*-
import random
import traceback
from functools import partial

from tornado import gen

from electrumq.blockchain import BlockChain
from electrumq.db.sqlite.block import BlockStore
from electrumq.utils.storage import AbstractStorage, WalletStorage, multisig_type
from electrumq.utils.tx import Transaction, segwit_script, multisig_script
from electrumq.db.sqlite.tx import TxStore
from electrumq.message.blockchain.address import GetHistory
from electrumq.message.blockchain.transaction import GetMerkle, Get
from electrumq.network import NetWorkManager
from electrumq.utils import coinchooser, public_key_to_p2pkh, hash160_to_p2sh, hash_160, InvalidPassword, \
    bc_address_to_type_and_hash_160
from electrumq.utils import is_address
from electrumq.utils.key import KeyStore, SimpleKeyStore, load_keystore, from_seed, from_seed2
from electrumq.utils.parameter import TYPE_ADDRESS, COINBASE_MATURITY, Parameter

__author__ = 'zhouqi'

'''
wallet is the interface to other module
'''


class WalletConfig(object):
    use_change = True
    multiple_change = False
    store_path = ''

    def __init__(self, **kwargs):
        fields = ['use_change', 'multiple_change', 'store_path']
        for k in fields:
            if k in kwargs:
                self.__setattr__(k, kwargs[k])


class AbstractWallet(object):
    def __init__(self, wallet_config):
        self.wallet_confg = wallet_config
        pass

    # tx logic
    def make_unsigned_transaction(self, inputs, outputs, config, fixed_fee=None, change_addr=None):
        pass

    def sign_transaction(self, tx, password):
        pass

    def print_error(self, **kwargs):
        pass

    def print_msg(self, **kwargs):
        pass




class BaseWallet(AbstractWallet):
    max_change_outputs = 3

    def __init__(self, wallet_config):
        super(BaseWallet, self).__init__(wallet_config)
        self.storage = WalletStorage(self.wallet_confg.store_path)
        self.gap_limit_for_change = 6
        self.use_change = True  # storage.get('use_change', True)
        self.multiple_change = False  # storage.get('multiple_change', False)
        self.frozen_addresses = []
        self.keystore = None
        self.load_addresses()

    def can_import(self):
        if self.keystore is None:
            return True
        else:
            return self.keystore.can_import()

    @property
    def is_segwit(self):
        if self.keystore is not None:
            return self.keystore.is_segwit()
        else:
            return False

    def get_keystores(self):
        return [self.keystore]

    def save_addresses(self):
        self.storage.put('addresses', {'receiving':self.receiving_addresses, 'change':self.change_addresses})
        self.storage.write()

    def load_addresses(self):
        d = self.storage.get('addresses', {})
        if type(d) != dict: d={}
        self.receiving_addresses = d.get('receiving', [])
        self.change_addresses = d.get('change', [])

    def make_unsigned_transaction(self, inputs, outputs, config, fixed_fee=None, change_addr=None):
        # check outputs
        i_max = None
        for i, o in enumerate(outputs):
            _type, data, value = o
            if _type == TYPE_ADDRESS:
                if not is_address(data):
                    raise BaseException("Invalid bitcoin address:" + data)
            if value == '!':
                if i_max is not None:
                    raise BaseException("More than one output set to spend max")
                i_max = i

        # Avoid index-out-of-range with inputs[0] below
        if not inputs:
            raise Exception()  # NotEnoughFunds()

        if fixed_fee is None and False:  # config.fee_per_kb() is None:
            raise BaseException('Dynamic fee estimates not available')

        for item in inputs:
            self.add_input_info(item)

        # change address
        if change_addr:
            change_addrs = [change_addr]
        else:
            addrs = self.get_change_addresses()[-self.gap_limit_for_change:]
            if self.use_change and addrs:
                # New change addresses are created only after a few
                # confirmations.  Select the unused addresses within the
                # gap limit; if none take one at random
                change_addrs = [addr for addr in addrs if
                                self.get_num_tx(addr) == 0]
                if not change_addrs:
                    change_addrs = [random.choice(addrs)]
            else:
                change_addrs = [inputs[0]['address']]

        # Fee estimator
        if fixed_fee is None:
            fee_estimator = partial(self.estimate_fee, config)
        else:
            fee_estimator = lambda size: fixed_fee

        if i_max is None:
            # Let the coin chooser select the coins to spend
            max_change = self.max_change_outputs if self.multiple_change else 1
            coin_chooser = coinchooser.get_coin_chooser(config)
            tx = coin_chooser.make_tx(inputs, outputs, change_addrs[:max_change],
                                      fee_estimator, self.dust_threshold())
        else:
            sendable = sum(map(lambda x: x['value'], inputs))
            _type, data, value = outputs[i_max]
            outputs[i_max] = (_type, data, 0)
            tx = Transaction.from_io(inputs, outputs[:])
            fee = fee_estimator(tx.estimated_size())
            amount = max(0, sendable - tx.output_value() - fee)
            outputs[i_max] = (_type, data, amount)
            tx = Transaction.from_io(inputs, outputs[:])

        # Sort the inputs and outputs deterministically
        tx.bip_li01_sort()
        # Timelock tx to current height.
        tx.locktime = self.get_local_height()
        # run_hook('make_unsigned_transaction', self, tx)
        return tx

    def sign_transaction(self, tx, password):
        # if self.is_watching_only():
        #     return
        # hardware wallets require extra info
        # if any([(isinstance(k, Hardware_KeyStore) and k.can_sign(tx)) for k in self.get_keystores()]):
        #     self.add_hw_info(tx)
        # sign
        for k in self.get_keystores():
            try:
                if k.can_sign(tx):
                    k.sign_transaction(tx, password)
            except Exception as ex:
                traceback.print_stack()
                continue

    def get_num_tx(self, address):
        # todo:
        return 0
        # """ return number of transactions where address is involved """
        # return len(self.history.get(address, []))

    def estimate_fee(self, config, size):
        fee = int(10000 * size / 1000.)
        return fee

    def add_input_info(self, txin):
        txin['type'] = 'p2pkh'  # self.txin_type
        # Add address for utxo that are in wallet
        if txin.get('scriptSig') == '':
            coins = self.get_spendable_coins()
            for item in coins:
                if txin.get('prevout_hash') == item.get('prevout_hash') and txin.get(
                        'prevout_n') == item.get('prevout_n'):
                    txin['address'] = item.get('address')
        address = txin['address']
        if self.is_mine(address):
            self.add_input_sig_info(txin, address)

    def add_input_sig_info(self, txin, address):
        if not self.can_import():
            derivation = self.get_address_index(address)
            x_pubkey = self.keystore.get_xpubkey(*derivation)
        else:
            x_pubkey = self.get_public_key(address)
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]
        txin['num_sig'] = 1

    def get_address_index(self, address):
        if self.can_import():
            for pubkey in self.keystore.keypairs.keys():
                if self.pubkeys_to_address(pubkey) == address:
                    return pubkey
        elif address in self.receiving_addresses:
            return False, self.receiving_addresses.index(address)
        if address in self.change_addresses:
            return True, self.change_addresses.index(address)
        raise Exception("Address not found", address)

    def get_public_key(self, address):
        if self.can_import():
            pubkey = self.get_address_index(address)
        else:
            sequence = self.get_address_index(address)
            pubkey = self.get_pubkey(*sequence)
        return pubkey

    def pubkeys_to_address(self, pubkey):
        if not self.is_segwit:
            return public_key_to_p2pkh(pubkey.decode('hex'))
        elif Parameter().TESTNET:
            redeem_script = self.pubkeys_to_redeem_script(pubkey)
            return hash160_to_p2sh(hash_160(redeem_script.decode('hex')))
        else:
            raise NotImplementedError()

    def is_mine(self, address):
        return address in self.get_addresses()

    def get_addresses(self):
        out = []
        out += self.get_receiving_addresses()
        out += self.get_change_addresses()
        return out

    def add_address(self, address):
        pass

    def dummy_address(self):
        return self.get_receiving_addresses()[0]

    def get_receiving_addresses(self):
        return []

    def get_change_addresses(self):
        return []

    def get_local_height(self):
        """ return last known height if we are offline """
        return 0  # self.network.get_local_height() if self.network else self.stored_height

    def get_spendable_coins(self, domain=None):
        return self.get_utxos(domain, exclude_frozen=True, mature=True)

    def get_utxos(self, domain=None, exclude_frozen=False, mature=False):
        coins = []
        if domain is None:
            domain = self.get_addresses()
        if exclude_frozen:
            domain = set(domain) - self.frozen_addresses
        for addr in domain:
            utxos = self.get_addr_utxo(addr)
            for x in utxos:
                if mature and x['coinbase'] and x[
                    'height'] + COINBASE_MATURITY > self.get_local_height():
                    continue
                coins.append(x)
                continue
        return coins

    def dust_threshold(self):
        # Change <= dust threshold is added to the tx fee
        return 182 * 3 * self.relayfee() / 1000

    def relayfee(self):
        RELAY_FEE = 5000
        MAX_RELAY_FEE = 50000
        f = RELAY_FEE  # self.network.relay_fee if self.network and self.network.relay_fee else RELAY_FEE
        return min(f, MAX_RELAY_FEE)

    def get_addr_utxo(self, address):
        coins, spent = self.get_addr_io(address)
        for txi in spent:
            coins.pop(txi)
        out = []
        for txo, v in coins.items():
            tx_height, value, is_cb = v
            prevout_hash, prevout_n = txo.split(':')
            x = {
                'address': address,
                'value': value,
                'prevout_n': int(prevout_n),
                'prevout_hash': prevout_hash,
                'height': tx_height,
                'coinbase': is_cb
            }
            out.append(x)
        return out

    def get_addr_io(self, address):
        h = self.history.get(address, [])
        received = {}
        sent = {}
        for tx_hash, height in h:
            l = self.txo.get(tx_hash, {}).get(address, [])
            for n, v, is_cb in l:
                received[tx_hash + ':%d' % n] = (height, v, is_cb)
        for tx_hash, height in h:
            l = self.txi.get(tx_hash, {}).get(address, [])
            for txi, v in l:
                sent[txi] = height
        return received, sent


    def address_is_old(self, address, age_limit=2):
        tx_age = TxStore().get_max_tx_block(address)
        if tx_age > 0:
            return BlockStore().height - tx_age > age_limit
        else:
            return False


class SimpleWallet(BaseWallet):
    def __init__(self, wallet_config):
        BaseWallet.__init__(self, wallet_config)
        if self.storage.get('keystore', None) is not None:
            self.keystore = load_keystore(self.storage, 'keystore')

    def init_key_store(self, key_store):
        if self.keystore is not None:
            raise Exception()
        if key_store is None:
            raise Exception()
        self.keystore = key_store
        self.storage.put('keystore', self.keystore.dump())
        self.storage.write()

    @property
    def address(self):
        return self.keystore.address

    def init(self):
        NetWorkManager().client.add_message(GetHistory([self.address]), self.history_callback)

    def get_receiving_addresses(self):
        return [self.address, ]

    @gen.coroutine
    def history_callback(self, msg_id, msg, param):
        for each in param:
            TxStore().add(msg['params'][0], each['tx_hash'], each['height'])
        for tx, height in TxStore().unverify_tx_list:
            NetWorkManager().client.add_message(GetMerkle([tx, height]), self.get_merkle_callback)
        for tx in TxStore().unfetch_tx:
            NetWorkManager().client.add_message(Get([tx]), self.get_tx_callback)

    @gen.coroutine
    def get_merkle_callback(self, msg_id, msg, param):
        tx_hash = msg['params'][0]
        height = msg['params'][1]
        block_root = BlockChain().get_block_root(height)
        if block_root is not None:
            result = TxStore().verify_merkle(tx_hash, param, block_root)
            if result:
                TxStore().verified_tx(tx_hash)

    @gen.coroutine
    def get_tx_callback(self, msg_id, msg, param):
        tx_hash = msg['params'][0]
        tx = Transaction(param)
        try:
            tx.deserialize()
            TxStore().add_tx_detail(tx_hash, tx)
            print self.address, 'balance', TxStore().get_balance(self.address)
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return


class HDWallet(BaseWallet):
    def __init__(self, wallet_config):
        BaseWallet.__init__(self, wallet_config)
        if self.storage.get('keystore', None) is not None:
            self.keystore = from_seed2(self.storage, 'keystore') #load_keystore(self.storage, 'keystore')
        self.gap_limit = self.storage.get('gap_limit', 20)

    def init_key_store(self, key_store):
        if self.keystore is not None:
            raise Exception()
        if key_store is None:
            raise Exception()
        self.keystore = key_store
        self.storage.put('keystore', self.keystore.dump())
        self.storage.write()

    def init(self):
        for address in (self.receiving_addresses + self.change_addresses):
            NetWorkManager().client.add_message(GetHistory([address]), self.history_callback)

    @gen.coroutine
    def history_callback(self, msg_id, msg, param):
        for each in param:
            TxStore().add(msg['params'][0], each['tx_hash'], each['height'])
        # for tx, height in TxStore().unverify_tx_list:
            NetWorkManager().client.add_message(GetMerkle([each['tx_hash'], each['height']]), self.get_merkle_callback)
        # for tx in TxStore().unfetch_tx:
            NetWorkManager().client.add_message(Get([each['tx_hash']]), self.get_tx_callback)

    @gen.coroutine
    def get_merkle_callback(self, msg_id, msg, param):
        tx_hash = msg['params'][0]
        height = msg['params'][1]
        block_root = BlockChain().get_block_root(height)
        if block_root is not None:
            result = TxStore().verify_merkle(tx_hash, param, block_root)
            if result:
                TxStore().verified_tx(tx_hash)

    @gen.coroutine
    def get_tx_callback(self, msg_id, msg, param):
        tx_hash = msg['params'][0]
        tx = Transaction(param)
        try:
            tx.deserialize()
            TxStore().add_tx_detail(tx_hash, tx)
            # print self.address, 'balance', TxStore().get_balance(self.address)
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return

    def has_seed(self):
        return self.keystore.has_seed()

    def is_deterministic(self):
        return self.keystore.is_deterministic()

    def get_receiving_addresses(self):
        return self.receiving_addresses

    def get_change_addresses(self):
        return self.change_addresses

    def get_seed(self, password):
        return self.keystore.get_seed(password)

    def add_seed(self, seed, pw):
        self.keystore.add_seed(seed, pw)

    def change_gap_limit(self, value):
        '''This method is not called in the code, it is kept for console use'''
        if value >= self.gap_limit:
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            return True
        elif value >= self.min_acceptable_gap():
            addresses = self.get_receiving_addresses()
            k = self.num_unused_trailing_addresses(addresses)
            n = len(addresses) - k + value
            self.receiving_addresses = self.receiving_addresses[0:n]
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            self.save_addresses()
            return True
        else:
            return False

    def num_unused_trailing_addresses(self, addresses):
        k = 0
        for a in addresses[::-1]:
            if self.history.get(a): break
            k = k + 1
        return k

    def min_acceptable_gap(self):
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0
        addresses = self.get_receiving_addresses()
        k = self.num_unused_trailing_addresses(addresses)
        for a in addresses[0:-k]:
            if self.history.get(a):
                n = 0
            else:
                n += 1
                if n > nmax: nmax = n
        return nmax + 1

    def create_new_address(self, for_change=False):
        assert type(for_change) is bool
        addr_list = self.change_addresses if for_change else self.receiving_addresses
        n = len(addr_list)
        x = self.derive_pubkeys(for_change, n)
        address = self.pubkeys_to_address(x)
        addr_list.append(address)
        self.save_addresses()
        self.add_address(address)
        return address

    def synchronize_sequence(self, for_change):
        limit = self.gap_limit_for_change if for_change else self.gap_limit
        while True:
            addresses = self.get_change_addresses() if for_change else self.get_receiving_addresses()
            if len(addresses) < limit:
                self.create_new_address(for_change)
                continue
            if map(lambda a: self.address_is_old(a), addresses[-limit:]) == limit * [False]:
                break
            else:
                self.create_new_address(for_change)

    def synchronize(self):
        # with self.lock:
        if self.is_deterministic():
            self.synchronize_sequence(False)
            self.synchronize_sequence(True)
        else:
            if len(self.receiving_addresses) != len(self.keystore.keypairs):
                pubkeys = self.keystore.keypairs.keys()
                self.receiving_addresses = map(self.pubkeys_to_address, pubkeys)
                self.save_addresses()
                for addr in self.receiving_addresses:
                    self.add_address(addr)

    def is_beyond_limit(self, address, is_change):
        addr_list = self.get_change_addresses() if is_change else self.get_receiving_addresses()
        i = addr_list.index(address)
        prev_addresses = addr_list[:max(0, i)]
        limit = self.gap_limit_for_change if is_change else self.gap_limit
        if len(prev_addresses) < limit:
            return False
        prev_addresses = prev_addresses[max(0, i - limit):]
        for addr in prev_addresses:
            if self.history.get(addr):
                return False
        return True

    def get_master_public_keys(self):
        return [self.get_master_public_key()]

    def get_fingerprint(self):
        return self.get_master_public_key()

    def derive_pubkeys(self, c, i):
        return self.keystore.derive_pubkey(c, i)



class WatchOnlySimpleWallet(SimpleWallet):
    pass


class ColdSimpleWallet(SimpleWallet):
    pass


class WatchOnlyHDWallet(BaseWallet):
    pass


class Imported_Wallet(BaseWallet):
    # wallet made of imported addresses

    wallet_type = 'imported'
    txin_type = 'address'

    def __init__(self, wallet_config):
        BaseWallet.__init__(self, wallet_config)

    def load_keystore(self):
        pass

    def load_addresses(self):
        self.addresses = self.storage.get('addresses', [])
        self.receiving_addresses = self.addresses
        self.change_addresses = []

    def get_keystores(self):
        return []

    def has_password(self):
        return False

    def can_change_password(self):
        return False

    def can_import_address(self):
        return True

    def is_watching_only(self):
        return True

    def has_seed(self):
        return False

    def is_deterministic(self):
        return False

    def is_used(self, address):
        return False

    def get_master_public_keys(self):
        return []

    def is_beyond_limit(self, address, is_change):
        return False

    def get_fingerprint(self):
        return ''

    def get_addresses(self, include_change=False):
        return self.addresses

    def import_address(self, address):
        if address in self.addresses:
            return
        self.addresses.append(address)
        self.storage.put('addresses', self.addresses)
        self.storage.write()
        self.add_address(address)
        return address

    def can_delete_address(self):
        return True

    def delete_address(self, address):
        if address not in self.addresses:
            return
        self.addresses.remove(address)
        self.storage.put('addresses', self.addresses)
        self.storage.write()

    def get_receiving_addresses(self):
        return self.addresses[:]

    def get_change_addresses(self):
        return []

    def add_input_sig_info(self, txin, address):
        addrtype, hash160 = bc_address_to_type_and_hash_160(address)
        x_pubkey = 'fd' + (chr(addrtype) + hash160).encode('hex')
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]


class Deterministic_Wallet(BaseWallet):
    def __init__(self, storage):
        BaseWallet.__init__(self, storage)
        self.gap_limit = storage.get('gap_limit', 20)

    def has_seed(self):
        return self.keystore.has_seed()

    def is_deterministic(self):
        return self.keystore.is_deterministic()

    def get_receiving_addresses(self):
        return self.receiving_addresses

    def get_change_addresses(self):
        return self.change_addresses

    def get_seed(self, password):
        return self.keystore.get_seed(password)

    def add_seed(self, seed, pw):
        self.keystore.add_seed(seed, pw)

    def change_gap_limit(self, value):
        '''This method is not called in the code, it is kept for console use'''
        if value >= self.gap_limit:
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            return True
        elif value >= self.min_acceptable_gap():
            addresses = self.get_receiving_addresses()
            k = self.num_unused_trailing_addresses(addresses)
            n = len(addresses) - k + value
            self.receiving_addresses = self.receiving_addresses[0:n]
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            self.save_addresses()
            return True
        else:
            return False

    def num_unused_trailing_addresses(self, addresses):
        k = 0
        for a in addresses[::-1]:
            if self.history.get(a): break
            k = k + 1
        return k

    def min_acceptable_gap(self):
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0
        addresses = self.get_receiving_addresses()
        k = self.num_unused_trailing_addresses(addresses)
        for a in addresses[0:-k]:
            if self.history.get(a):
                n = 0
            else:
                n += 1
                if n > nmax: nmax = n
        return nmax + 1

    def create_new_address(self, for_change=False):
        assert type(for_change) is bool
        addr_list = self.change_addresses if for_change else self.receiving_addresses
        n = len(addr_list)
        x = self.derive_pubkeys(for_change, n)
        address = self.pubkeys_to_address(x)
        addr_list.append(address)
        self.save_addresses()
        self.add_address(address)
        return address

    def synchronize_sequence(self, for_change):
        limit = self.gap_limit_for_change if for_change else self.gap_limit
        while True:
            addresses = self.get_change_addresses() if for_change else self.get_receiving_addresses()
            if len(addresses) < limit:
                self.create_new_address(for_change)
                continue
            if map(lambda a: self.address_is_old(a), addresses[-limit:]) == limit * [False]:
                break
            else:
                self.create_new_address(for_change)

    def synchronize(self):
        with self.lock:
            if self.is_deterministic():
                self.synchronize_sequence(False)
                self.synchronize_sequence(True)
            else:
                if len(self.receiving_addresses) != len(self.keystore.keypairs):
                    pubkeys = self.keystore.keypairs.keys()
                    self.receiving_addresses = map(self.pubkeys_to_address, pubkeys)
                    self.save_addresses()
                    for addr in self.receiving_addresses:
                        self.add_address(addr)

    def is_beyond_limit(self, address, is_change):
        addr_list = self.get_change_addresses() if is_change else self.get_receiving_addresses()
        i = addr_list.index(address)
        prev_addresses = addr_list[:max(0, i)]
        limit = self.gap_limit_for_change if is_change else self.gap_limit
        if len(prev_addresses) < limit:
            return False
        prev_addresses = prev_addresses[max(0, i - limit):]
        for addr in prev_addresses:
            if self.history.get(addr):
                return False
        return True

    def get_master_public_keys(self):
        return [self.get_master_public_key()]

    def get_fingerprint(self):
        return self.get_master_public_key()


class Simple_Wallet(BaseWallet):
    """ Wallet with a single pubkey per address """

    def load_keystore(self):
        self.keystore = load_keystore(self.storage, 'keystore')
        self.is_segwit = self.keystore.is_segwit()
        self.txin_type = 'p2wpkh-p2sh' if self.is_segwit else 'p2pkh'

    def get_pubkey(self, c, i):
        return self.derive_pubkeys(c, i)

    def get_public_keys(self, address):
        return [self.get_public_key(address)]

    def add_input_sig_info(self, txin, address):
        if not self.keystore.can_import():
            derivation = self.get_address_index(address)
            x_pubkey = self.keystore.get_xpubkey(*derivation)
        else:
            x_pubkey = self.get_public_key(address)
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]
        txin['num_sig'] = 1

    def sign_message(self, address, message, password):
        index = self.get_address_index(address)
        return self.keystore.sign_message(index, message, password)

    def decrypt_message(self, pubkey, message, password):
        addr = self.pubkeys_to_address(pubkey)
        index = self.get_address_index(addr)
        return self.keystore.decrypt_message(index, message, password)


class Simple_Deterministic_Wallet(Deterministic_Wallet, Simple_Wallet):
    def __init__(self, storage):
        Deterministic_Wallet.__init__(self, storage)

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def derive_pubkeys(self, c, i):
        return self.keystore.derive_pubkey(c, i)

    def get_keystore(self):
        return self.keystore

    def get_keystores(self):
        return [self.keystore]

    def is_watching_only(self):
        return self.keystore.is_watching_only()

    def can_change_password(self):
        return self.keystore.can_change_password()

    def check_password(self, password):
        self.keystore.check_password(password)

    def update_password(self, old_pw, new_pw, encrypt=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        self.keystore.update_password(old_pw, new_pw)
        self.save_keystore()
        self.storage.set_password(new_pw, encrypt)
        self.storage.write()

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())

    def can_delete_address(self):
        return self.keystore.can_import()

    def delete_address(self, address):
        pubkey = self.get_public_key(address)
        self.keystore.delete_imported_key(pubkey)
        self.save_keystore()
        self.receiving_addresses.remove(address)
        self.save_addresses()
        self.storage.write()

    def can_import_privkey(self):
        return self.keystore.can_import()

    def import_key(self, pk, pw):
        pubkey = self.keystore.import_key(pk, pw)
        self.save_keystore()
        addr = self.pubkeys_to_address(pubkey)
        self.receiving_addresses.append(addr)
        self.save_addresses()
        self.storage.write()
        self.add_address(addr)
        return addr


class P2SH:
    def pubkeys_to_redeem_script(self, pubkeys):
        raise NotImplementedError()

    def pubkeys_to_address(self, pubkey):
        redeem_script = self.pubkeys_to_redeem_script(pubkey)
        return hash160_to_p2sh(hash_160(redeem_script.decode('hex')))


class Standard_Wallet(Simple_Deterministic_Wallet):
    wallet_type = 'standard'

    def pubkeys_to_redeem_script(self, pubkey):
        if self.is_segwit:
            return segwit_script(pubkey)

    def pubkeys_to_address(self, pubkey):
        if not self.is_segwit:
            return public_key_to_p2pkh(pubkey.decode('hex'))
        elif Parameter().TESTNET:
            redeem_script = self.pubkeys_to_redeem_script(pubkey)
            return hash160_to_p2sh(hash_160(redeem_script.decode('hex')))
        else:
            raise NotImplementedError()


class Multisig_Wallet(Deterministic_Wallet, P2SH):
    # generic m of n
    gap_limit = 20
    txin_type = 'p2sh'

    def __init__(self, storage):
        self.wallet_type = storage.get('wallet_type')
        self.m, self.n = multisig_type(self.wallet_type)
        Deterministic_Wallet.__init__(self, storage)

    def get_pubkeys(self, c, i):
        return self.derive_pubkeys(c, i)

    def redeem_script(self, c, i):
        pubkeys = self.get_pubkeys(c, i)
        return multisig_script(sorted(pubkeys), self.m)

    def pubkeys_to_redeem_script(self, pubkeys):
        return multisig_script(sorted(pubkeys), self.m)

    def derive_pubkeys(self, c, i):
        return [k.derive_pubkey(c, i) for k in self.get_keystores()]

    def load_keystore(self):
        self.keystores = {}
        for i in range(self.n):
            name = 'x%d/' % (i + 1)
            self.keystores[name] = load_keystore(self.storage, name)
        self.keystore = self.keystores['x1/']

    def save_keystore(self):
        for name, k in self.keystores.items():
            self.storage.put(name, k.dump())

    def get_keystore(self):
        return self.keystores.get('x1/')

    def get_keystores(self):
        return [self.keystores[i] for i in sorted(self.keystores.keys())]

    def update_password(self, old_pw, new_pw, encrypt=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        for name, keystore in self.keystores.items():
            if keystore.can_change_password():
                keystore.update_password(old_pw, new_pw)
                self.storage.put(name, keystore.dump())
        self.storage.set_password(new_pw, encrypt)
        self.storage.write()

    def check_password(self, password):
        self.keystore.check_password(password)

    def has_seed(self):
        return self.keystore.has_seed()

    def can_change_password(self):
        return self.keystore.can_change_password()

    def is_watching_only(self):
        return not any([not k.is_watching_only() for k in self.get_keystores()])

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def get_master_public_keys(self):
        return [k.get_master_public_key() for k in self.get_keystores()]

    def get_fingerprint(self):
        return ''.join(sorted(self.get_master_public_keys()))

    def add_input_sig_info(self, txin, address):
        derivation = self.get_address_index(address)
        # extended pubkeys
        txin['x_pubkeys'] = [k.get_xpubkey(*derivation) for k in self.get_keystores()]
        # we need n place holders
        txin['signatures'] = [None] * self.n
        txin['num_sig'] = self.m
