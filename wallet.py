# -*- coding: utf-8 -*-
import random
import traceback
from functools import partial

from tornado import gen

from blockchain import BlockChain
from db.mem.tx import Transaction
from db.sqlite.tx import TxStore
from message.blockchain.address import GetHistory
from message.blockchain.transaction import GetMerkle, Get
from network import NetWorkManager
from utils import coinchooser
from utils import is_address
from utils.key import KeyStore
from utils.parameter import TYPE_ADDRESS, COINBASE_MATURITY

__author__ = 'zhouqi'


class BaseWallet():
    max_change_outputs = 3

    def __init__(self):
        self.gap_limit_for_change = 6
        self.use_change = True#storage.get('use_change', True)
        self.multiple_change = False #storage.get('multiple_change', False)
        self.frozen_addresses = []
        pass

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
            raise Exception() #NotEnoughFunds()

        if fixed_fee is None and False:#config.fee_per_kb() is None:
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
            sendable = sum(map(lambda x:x['value'], inputs))
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
        for k in [KeyStore()]:#self.get_keystores():
            try:
                if k.can_sign(tx):
                    k.sign_transaction(tx, password)
            except Exception as ex:
                traceback.print_stack()
                continue

    def get_num_tx(self, address):
        """ return number of transactions where address is involved """
        return len(self.history.get(address, []))

    def estimate_fee(self, config, size):
        fee = int(10000 * size / 1000.)
        return fee

    def add_input_info(self, txin):
        txin['type'] = 'p2pkh' #self.txin_type
        # Add address for utxo that are in wallet
        if txin.get('scriptSig') == '':
            coins = self.get_spendable_coins()
            for item in coins:
                if txin.get('prevout_hash') == item.get('prevout_hash') and txin.get('prevout_n') == item.get('prevout_n'):
                    txin['address'] = item.get('address')
        address = txin['address']
        if self.is_mine(address):
            self.add_input_sig_info(txin, address)

    def add_input_sig_info(self, txin, address):
        # if not self.keystore.can_import():
        #     derivation = self.get_address_index(address)
        #     x_pubkey = self.keystore.get_xpubkey(*derivation)
        # else:
        # todo:
        x_pubkey = '0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967'
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]
        txin['num_sig'] = 1

    def is_mine(self, address):
        return address in self.get_addresses()

    def get_addresses(self):
        out = []
        out += self.get_receiving_addresses()
        out += self.get_change_addresses()
        return out

    def dummy_address(self):
        return self.get_receiving_addresses()[0]

    def get_receiving_addresses(self):
        return []

    def get_change_addresses(self):
        return []

    def get_local_height(self):
        """ return last known height if we are offline """
        return 0# self.network.get_local_height() if self.network else self.stored_height

    def get_spendable_coins(self, domain = None):
        return self.get_utxos(domain, exclude_frozen=True, mature=True)

    def get_utxos(self, domain = None, exclude_frozen = False, mature = False):
        coins = []
        if domain is None:
            domain = self.get_addresses()
        if exclude_frozen:
            domain = set(domain) - self.frozen_addresses
        for addr in domain:
            utxos = self.get_addr_utxo(addr)
            for x in utxos:
                if mature and x['coinbase'] and x['height'] + COINBASE_MATURITY > self.get_local_height():
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
        f = RELAY_FEE#self.network.relay_fee if self.network and self.network.relay_fee else RELAY_FEE
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
                'address':address,
                'value':value,
                'prevout_n':int(prevout_n),
                'prevout_hash':prevout_hash,
                'height':tx_height,
                'coinbase':is_cb
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
                received[tx_hash + ':%d'%n] = (height, v, is_cb)
        for tx_hash, height in h:
            l = self.txi.get(tx_hash, {}).get(address, [])
            for txi, v in l:
                sent[txi] = height
        return received, sent


class SimpleWallet(BaseWallet):
    _address = None

    def __init__(self, address):
        BaseWallet.__init__(self)
        self._address = address

    def init(self):
        NetWorkManager().client.add_message(GetHistory([self._address]), self.history_callback)

    def get_receiving_addresses(self):
        return [self._address,]

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
            print self._address, 'balance', TxStore().get_balance(self._address)
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return



class HDWallet(BaseWallet):
    pass


class WatchOnlySimpleWallet(BaseWallet):
    pass


class WatchOnlyHDWallet(BaseWallet):
    pass
