# -*- coding: utf-8 -*-
import random
import traceback
from functools import partial

from db.sqlite.block import BlockStore
from db.sqlite.tx import TxStore
from utils import coinchooser, hash160_to_p2sh, public_key_to_p2pkh, hash_160
from utils import is_address
from utils.parameter import TYPE_ADDRESS, COINBASE_MATURITY, Parameter
from utils.storage import WalletStorage
from utils.tx import Transaction

__author__ = 'zhouqi'


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

    def print_msg(self, *args, **kwargs):
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
        self.storage.put('addresses',
                         {'receiving': self.receiving_addresses, 'change': self.change_addresses})
        self.storage.write()

    def load_addresses(self):
        d = self.storage.get('addresses', {})
        if type(d) != dict: d = {}
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
        tx.BIP_LI01_sort()
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