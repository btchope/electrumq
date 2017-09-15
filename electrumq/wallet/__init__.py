# -*- coding: utf-8 -*-
import random
import traceback
from Queue import Queue
from functools import partial

from datetime import datetime

from tornado import gen

from electrumq.blockchain import BlockChain
from electrumq.db.sqlite.block import BlockStore
from electrumq.db.sqlite.tx import TxStore
from electrumq.message.blockchain.address import *
from electrumq.message.blockchain.transaction import *
from electrumq.network import NetWorkManager
from electrumq.utils import coinchooser
from electrumq.utils.base58 import is_address, public_key_to_p2pkh, hash160_to_p2sh, hash_160
from electrumq.utils.parameter import TYPE_ADDRESS, COINBASE_MATURITY, Parameter
from electrumq.utils.storage import WalletStorage
from electrumq.utils.tx import Transaction, Input

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


EVENT_QUEUE = Queue()


class AbstractWallet(object):
    def __init__(self, wallet_config):
        self.wallet_confg = wallet_config
        pass

    # tx logic
    def make_unsigned_transaction(self, inputs, outputs, config, fixed_fee=None, change_addr=None):
        pass

    def sign_transaction(self, tx, password):
        pass

    def print_error(self, *args, **kwargs):
        pass

    def print_msg(self, *args, **kwargs):
        pass


class BaseWallet(AbstractWallet):
    max_change_outputs = 3
    keystore = None
    txin_type = 'p2pkh'

    def __init__(self, wallet_config):
        super(BaseWallet, self).__init__(wallet_config)
        self.storage = WalletStorage(self.wallet_confg.store_path)
        self.gap_limit_for_change = 6
        self.use_change = wallet_config.use_change
        self.multiple_change = wallet_config.multiple_change
        self.frozen_addresses = []
        self.receiving_addresses = []
        self.change_addresses = []
        self.load_addresses()
        # todo: wallet name logic
        self.wallet_name = 'abc'

    def can_import(self):
        if self.keystore is None:
            return True
        else:
            return self.keystore.can_import()

    @property
    def display_address(self):
        pass

    @property
    def balance(self):
        pass

    def get_txs(self):
        pass

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
        if type(d) is dict:
            if 'receiving' in d:
                self.receiving_addresses = d['receiving']
            if 'change' in d:
                self.change_addresses = d['change']

    def get_utxo(self):
        utxo = reduce(lambda x, y: x + y, [[
            Input({'prevout_hash': e[0], 'prevout_n': e[1],
             'scriptSig': e[2], 'value': e[3],
             'address': e[4],
             'coinbase': False,
             'height': e[5]}) for e in
            TxStore().get_unspend_outs(address=address)] for
            address in self.get_addresses()], [])
        return utxo

    def get_txs(self):
        txs = TxStore().get_all_txs(self.get_addresses())
        receives = {row[0]: row[1] for row in TxStore().get_all_tx_receive(self.get_addresses())}
        spents = {row[0]: row[1] for row in TxStore().get_all_tx_spent(self.get_addresses())}
        result = []
        for row in txs:
            receive = 0
            if row[0] in receives:
                receive = receives[row[0]]
            spent = 0
            if row[0] in spents:
                spent = spents[row[0]]
            delta = receive - spent
            result.append(
                {'tx_hash': row[0], 'tx_time': row[1], 'tx_delta': delta, 'tx_receive': receive,
                 'tx_spent': spent})
        return result

    def make_unsigned_transaction(self, inputs, outputs, config, fixed_fee=None, change_addr=None):
        # check outputs
        i_max = None
        for i, o in enumerate(outputs):
            _type, data, value = o.address_type, o.out_address, o.out_value
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
                change_addrs = [inputs[0].in_address]

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
            # _type, data, value = outputs[i_max]
            # outputs[i_max] = (_type, data, 0)
            outputs[i_max].out_value = 0
            tx = Transaction.from_io(inputs, outputs[:])
            fee = fee_estimator(tx.estimated_size())
            amount = max(0, sendable - tx.output_value() - fee)
            # outputs[i_max] = (_type, data, amount)
            outputs[i_max].out_value = amount
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
            # try:
            if k.can_sign(tx):
                k.sign_transaction(tx, password)
                # except Exception as ex:
                #     traceback.print_stack()
                #     continue

    def get_num_tx(self, address):
        # todo:
        return 0
        # """ return number of transactions where address is involved """
        # return len(self.history.get(address, []))

    def estimate_fee(self, config, size):
        fee = int(10000 * size / 1000.)
        return fee

    def add_input_info(self, txin):
        if txin.in_dict is None:
            txin.in_dict = {}
        txin.in_dict['type'] = self.txin_type  # 'p2pkh'
        # Add address for utxo that are in wallet
        if txin.in_dict.get('scriptSig') == '':
            coins = self.get_spendable_coins()
            for item in coins:
                if txin.prev_tx_hash == item.prev_tx_hash \
                        and txin.prev_out_sn == item.prev_out_sn:
                    txin.in_address = item.in_address
        address = txin.in_address
        if self.is_mine(address):
            self.add_input_sig_info(txin, address)
    # def add_input_info(self, txin):
    #     txin['type'] = self.txin_type  # 'p2pkh'
    #     # Add address for utxo that are in wallet
    #     if txin.get('scriptSig') == '':
    #         coins = self.get_spendable_coins()
    #         for item in coins:
    #             if txin.get('prevout_hash') == item.get('prevout_hash') \
    #                     and txin.get('prevout_n') == item.get('prevout_n'):
    #                 txin['address'] = item.get('address')
    #     address = txin['address']
    #     if self.is_mine(address):
    #         self.add_input_sig_info(txin, address)

    def add_input_sig_info(self, txin, address):
        if not self.can_import():
            derivation = self.get_address_index(address)
            x_pubkey = self.keystore.get_xpubkey(*derivation)
        else:
            x_pubkey = self.get_public_key(address)
        txin.in_dict['x_pubkeys'] = [x_pubkey]
        txin.in_dict['signatures'] = [None]
        txin.in_dict['num_sig'] = 1

    def get_address_index(self, address):
        # todo: need review
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
        # todo: need review
        if self.can_import():
            pubkey = self.get_address_index(address)
        else:
            sequence = self.get_address_index(address)
            pubkey = self.get_pubkey(*sequence)
        return pubkey

    def pubkeys_to_address(self, pubkey):
        # todo: need review
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
        return self.get_receiving_addresses() + self.get_change_addresses()

    def add_address(self, address):
        pass

    def dummy_address(self):
        return self.get_receiving_addresses()[0]

    def get_receiving_addresses(self):
        return self.receiving_addresses

    def get_change_addresses(self):
        return self.change_addresses

    def get_local_height(self):
        """ return last known height if we are offline """
        return BlockStore().height  # self.network.get_local_height() if self.network else self.stored_height

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
                if mature and x.is_coinbase and x.height + COINBASE_MATURITY > self.get_local_height():
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
        # todo: relay fee
        f = RELAY_FEE  # self.network.relay_fee if self.network and self.network.relay_fee else RELAY_FEE
        return min(f, MAX_RELAY_FEE)

    def get_addr_utxo(self, address):
        # todo: use sqlite to get data
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
            out.append(Input(x))
        return out

    def get_addr_io(self, address):
        # todo: use sqlite to get data not history
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

    # sync
    def init(self):
        NetWorkManager().client.add_message(GetHistory([self.address]), self.history_callback)

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
            global EVENT_QUEUE
            if len(self.wallet_tx_changed_event) > 0:
                for event in set(self.wallet_tx_changed_event):
                    EVENT_QUEUE.put(event)
            print self.address, 'balance', TxStore().get_balance(self.address)
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return

    def broadcast(self, tx):
        print Broadcast([str(tx)])
        NetWorkManager().client.add_message(Broadcast([str(tx)]))

    wallet_tx_changed_event = []
