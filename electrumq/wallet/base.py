# -*- coding: utf-8 -*-
import ast
import base64
import copy
import hashlib
import hmac
import json
import os
import random
import threading
from Queue import Queue
from functools import partial
from stat import S_IREAD, S_IWRITE

import pbkdf2
import zlib
from tornado import gen

from electrumq.blockchain.chain import BlockChain
from electrumq.db.sqlite.block import BlockStore
from electrumq.db.sqlite.tx import TxStore
from electrumq.message.blockchain.address import GetHistory
from electrumq.message.blockchain.transaction import GetMerkle, Get, Broadcast
from electrumq.network.manager import NetWorkManager
from electrumq.secret.key import EC_KEY, encrypt_message
from electrumq.tx import coinchooser
from electrumq.utils.base58 import is_address
from electrumq.utils.parameter import TYPE_ADDRESS, COINBASE_MATURITY
from electrumq.tx.tx import Input, Transaction

__author__ = 'zhouqi'

FINAL_SEED_VERSION = 13


class BaseWallet(object):
    max_change_outputs = 3
    keystore = None
    txin_type = 'p2pkh'

    def __init__(self, wallet_config):
        self.wallet_config = wallet_config
        self.storage = WalletStorage(self.wallet_config.store_path)
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
        raise NotImplementedError()

    @property
    def balance(self):
        raise NotImplementedError()

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

    """
    show for txs
    """
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

    """
    make transaction
    """

    def make_unsigned_transaction(self, inputs, outputs, config, fixed_fee=None, change_addr=None):
        # 1. check outputs
        spend_all = None
        for i, o in enumerate(outputs):
            _type, data, value = o.address_type, o.out_address, o.out_value
            if _type == TYPE_ADDRESS:
                if not is_address(data):
                    raise BaseException("Invalid bitcoin address:" + data)
            if value == '!':
                if spend_all is not None:
                    raise BaseException("More than one output set to spend max")
                spend_all = i

        # 2. check input
        if not inputs:
            # Avoid index-out-of-range with inputs[0] below
            raise Exception()  # NotEnoughFunds()
        for item in inputs:
            self.add_input_info(item)

        # 3. change address
        change_addrs = self._get_change_address(change_addr, inputs)
        # 4. Fee estimator
        fee_estimator = self._get_fee_estimator(config, fixed_fee)
        # 5. choose input and change
        tx = self._make_unsign_tx(change_addrs, config, fee_estimator, inputs, outputs, spend_all)
        # 6. Sort the inputs and outputs deterministically
        tx.bip_li01_sort()
        # 7. Time lock tx to current height.
        tx.locktime = self.get_local_height()
        # run_hook('make_unsigned_transaction', self, tx)
        return tx

    def _get_fee_estimator(self, config, fixed_fee):
        if fixed_fee is None and False:  # config.fee_per_kb() is None:
            raise BaseException('Dynamic fee estimates not available')
        if fixed_fee is None:
            fee_estimator = partial(self.estimate_fee, config)
        else:
            fee_estimator = lambda size: fixed_fee

        return fee_estimator

    def _make_unsign_tx(self, change_addrs, config, fee_estimator, inputs, outputs, spend_all):
        if spend_all is None:
            # Let the coin chooser select the coins to spend
            max_change = self.max_change_outputs if self.multiple_change else 1
            coin_chooser = coinchooser.get_coin_chooser(config)
            tx = coin_chooser.make_tx(inputs, outputs, change_addrs[:max_change],
                                      fee_estimator, self.dust_threshold())
        else:
            sendable = sum(map(lambda x: x['value'], inputs))
            # _type, data, value = outputs[i_max]
            # outputs[i_max] = (_type, data, 0)
            outputs[spend_all].out_value = 0
            tx = Transaction.from_io(inputs, outputs[:])
            fee = fee_estimator(tx.estimated_size())
            amount = max(0, sendable - tx.output_value() - fee)
            # outputs[i_max] = (_type, data, amount)
            outputs[spend_all].out_value = amount
            tx = Transaction.from_io(inputs, outputs[:])

        return tx

    def _get_change_address(self, change_addr, inputs):
        """
        wallet can implement self logic
        :param change_addr:
        :param inputs:
        :return: change_addresses
        """
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

        return change_addrs

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

    def add_input_sig_info(self, txin, address):
        txin.in_dict['x_pubkeys'] = [self.get_public_key(address)]
        txin.in_dict['signatures'] = [None]
        txin.in_dict['num_sig'] = 1

    def get_public_key(self, address):
        raise NotImplementedError()

    def pubkeys_to_address(self, pubkey):
        raise NotImplementedError()

    def is_mine(self, address):
        return address in self.get_addresses()

    def get_addresses(self):
        return self.get_receiving_addresses() + self.get_change_addresses()

    def add_address(self, address):
        raise NotImplementedError()

    def dummy_address(self):
        return self.get_receiving_addresses()[0]

    def get_receiving_addresses(self):
        return self.receiving_addresses

    def get_change_addresses(self):
        return self.change_addresses

    def get_local_height(self):
        """
        return last known height if we are offline
        """
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

    """
    wallet sync
    """

    def sync(self):
        NetWorkManager().add_message(GetHistory([self.address]), self.history_callback)

    @gen.coroutine
    def history_callback(self, msg_id, msg, param):
        for each in param:
            TxStore().add(msg['params'][0], each['tx_hash'], each['height'])
        for tx, height in TxStore().unverify_tx_list:
            NetWorkManager().add_message(GetMerkle([tx, height]), self.get_merkle_callback)
        for tx in TxStore().unfetch_tx:
            NetWorkManager().add_message(Get([tx]), self.get_tx_callback)

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
        tx = Transaction.init_from_raw(param)
        try:
            tx.deserialize()
            TxStore().add_tx_detail(tx_hash, tx)
            global EVENT_QUEUE
            if len(self.wallet_tx_changed_event) > 0:
                for event in set(self.wallet_tx_changed_event):
                    EVENT_QUEUE.put(event)
            print self.address, 'balance', TxStore().get_balance(self.address)
        except Exception as ex:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return

    wallet_tx_changed_event = []

    """
    wallet broadcast
    """

    def broadcast(self, tx):
        # todo: handle broadcast failed
        print Broadcast([str(tx)])
        NetWorkManager().add_message(Broadcast([str(tx)]))

    """
    util method
    """

    def print_error(self, *args, **kwargs):
        pass

    def print_msg(self, *args, **kwargs):
        pass


EVENT_QUEUE = Queue()


class WalletConfig(object):
    use_change = True
    multiple_change = False
    store_path = ''

    def __init__(self, **kwargs):
        fields = ['use_change', 'multiple_change', 'store_path']
        for k in fields:
            if k in kwargs:
                self.__setattr__(k, kwargs[k])


class WalletStorage():
    def __init__(self, path):

        # self.print_error("wallet path", path)
        self.lock = threading.RLock()
        self.data = {}
        self.path = path
        self.modified = False
        self.pubkey = None
        if self.file_exists():
            with open(self.path, "r") as f:
                self.raw = f.read()
            if not self.is_encrypted():
                self.load_data(self.raw)

    def load_data(self, s):
        try:
            self.data = json.loads(s)
        except:
            try:
                d = ast.literal_eval(s)
                labels = d.get('labels', {})
            except Exception as e:
                raise IOError("Cannot read wallet file '%s'" % self.path)
            self.data = {}
            # In old versions of Electrum labels were latin1 encoded, this fixes breakage.
            for i, label in labels.items():
                try:
                    unicode(label)
                except UnicodeDecodeError:
                    d['labels'][i] = unicode(label.decode('latin1'))
            for key, value in d.items():
                try:
                    json.dumps(key)
                    json.dumps(value)
                except:
                    self.print_error('Failed to convert label to json format', key)
                    continue
                self.data[key] = value

        # check here if I need to load a plugin
        t = self.get('wallet_type')
        # todo: plugin
        # l = plugin_loaders.get(t)
        # if l: l()

    def is_encrypted(self):
        try:
            return base64.b64decode(self.raw).startswith('BIE1')
        except:
            return False

    def file_exists(self):
        return self.path and os.path.exists(self.path)

    def get_key(self, password):
        secret = pbkdf2.PBKDF2(password, '', iterations=1024, macmodule=hmac,
                               digestmodule=hashlib.sha512).read(64)
        ec_key = EC_KEY(secret)
        return ec_key

    def decrypt(self, password):
        ec_key = self.get_key(password)
        s = zlib.decompress(ec_key.decrypt_message(self.raw)) if self.raw else None
        self.pubkey = ec_key.get_public_key()
        self.load_data(s)

    def set_password(self, password, encrypt):
        self.put('use_encryption', bool(password))
        if encrypt and password:
            ec_key = self.get_key(password)
            self.pubkey = ec_key.get_public_key()
        else:
            self.pubkey = None

    def get(self, key, default=None):
        with self.lock:
            v = self.data.get(key)
            if v is None:
                v = default
            else:
                v = copy.deepcopy(v)
        return v

    def put(self, key, value):
        try:
            json.dumps(key)
            json.dumps(value)
        except:
            self.print_error("json error: cannot save", key)
            return
        with self.lock:
            if value is not None:
                if self.data.get(key) != value:
                    self.modified = True
                    self.data[key] = copy.deepcopy(value)
            elif key in self.data:
                self.modified = True
                self.data.pop(key)

    # @profiler
    def write(self):
        # this ensures that previous versions of electrum won't open the wallet
        self.put('seed_version', FINAL_SEED_VERSION)
        with self.lock:
            self._write()

    def _write(self):
        if threading.currentThread().isDaemon():
            self.print_error('warning: daemon thread cannot write wallet')
            return
        if not self.modified:
            return
        s = json.dumps(self.data, indent=4, sort_keys=True)
        if self.pubkey:
            s = encrypt_message(zlib.compress(s), self.pubkey)

        temp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(temp_path, "w") as f:
            f.write(s)
            f.flush()
            os.fsync(f.fileno())

        mode = os.stat(self.path).st_mode if os.path.exists(self.path) else S_IREAD | S_IWRITE
        # perform atomic write on POSIX systems
        try:
            os.rename(temp_path, self.path)
        except:
            os.remove(self.path)
            os.rename(temp_path, self.path)
        os.chmod(self.path, mode)
        self.print_error("saved", self.path)
        self.modified = False

    def requires_split(self):
        d = self.get('accounts', {})
        return len(d) > 1

    def print_error(self, *args, **kwargs):
        pass




    def get_action(self):
        # todo: plugin
        pass
        # action = run_hook('get_action', self)
        # if action:
        #     return action
        # if not self.file_exists():
        #     return 'new'

    # def get_seed_version(self):
    #     seed_version = self.get('seed_version')
    #     if not seed_version:
    #         seed_version = OLD_SEED_VERSION if len(
    #             self.get('master_public_key', '')) == 128 else NEW_SEED_VERSION
    #     if seed_version >= 12:
    #         return seed_version
    #     if seed_version not in [OLD_SEED_VERSION, NEW_SEED_VERSION]:
    #         msg = "Your wallet has an unsupported seed version."
    #         msg += '\n\nWallet file: %s' % os.path.abspath(self.path)
    #         if seed_version in [5, 7, 8, 9, 10]:
    #             msg += "\n\nTo open this wallet, try 'git checkout seed_v%d'" % seed_version
    #         if seed_version == 6:
    #             # version 1.9.8 created v6 wallets when an incorrect seed was entered in the restore dialog
    #             msg += '\n\nThis file was created because of a bug in version 1.9.8.'
    #             if self.get('master_public_keys') is None and self.get(
    #                     'master_private_keys') is None and self.get('imported_keys') is None:
    #                 # pbkdf2 was not included with the binaries, and wallet creation aborted.
    #                 msg += "\nIt does not contain any keys, and can safely be removed."
    #             else:
    #                 # creation was complete if electrum was run from source
    #                 msg += "\nPlease open this file with Electrum 1.9.8, and move your coins to a new wallet."
    #         raise BaseException(msg)
    #     return seed_version