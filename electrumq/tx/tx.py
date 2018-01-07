# -*- coding: utf-8 -*-
from electrumq.tx.script import Script, get_scriptPubKey, multisig_script
from electrumq.utils import print_error
from electrumq.utils.base58 import double_sha256, hash_160
from electrumq.utils.key import EC_KEY
from electrumq.utils.key_store import xpubkey_to_pubkey
from electrumq.utils.parser import write_uint32, int_to_hex, write_uint64
from electrumq.utils.tx import BCDataStream, parse_scriptSig, get_address_from_output_script, \
    push_script

__author__ = 'zhouqi'


class TxMaker(object):
    pass


class Output(object):
    tx_hash = None
    out_sn = None
    out_value = None
    out_address = None
    # address_type = None
    out_script = None

    def __init__(self, tx_out_dict=None):
        super(Output, self).__init__()
        if tx_out_dict is not None:
            self.out_address = tx_out_dict[1]
            self.address_type = tx_out_dict[0]
            self.out_value = tx_out_dict[2]
            self.out_script = self.pay_script_from_address()

    @classmethod
    def init_from_raw(cls, vds, out_sn):
        tx_out = Output()
        tx_out.out_sn = out_sn
        tx_out.out_value = vds.read_int64()
        tx_out.out_script = vds.read_bytes(vds.read_compact_size()).encode('hex')
        _, tx_out.out_address = get_address_from_output_script(
            tx_out.out_script.decode('hex'))
        return tx_out

    def pay_script_from_address(self):
        return Script().get_script_pubkey(self.out_address)

    def serialize_output(self):
        s = write_uint64(self.out_value).encode('hex')
        script = self.pay_script_from_address()
        s += int_to_hex(len(script) / 2)
        s += script
        return s


class Input(object):
    tx_hash = None
    in_sn = None
    prev_tx_hash = None
    prev_out_sn = None
    in_signature = None
    in_sequence = 0xffffffff
    in_value = None
    in_address = None
    height = None
    in_dict = None

    tx_out = None

    def __init__(self, tx_in_dict=None):
        super(Input, self).__init__()

        if tx_in_dict is not None:
            self.prev_tx_hash = tx_in_dict['prevout_hash']
            self.prev_out_sn = tx_in_dict['prevout_n']
            self.in_signature = tx_in_dict['scriptSig']
            self.in_value = tx_in_dict['value']
            self.in_address = tx_in_dict['address']
            self.height = tx_in_dict['height']

    @classmethod
    def init_from_raw(cls, vds, in_sn):
        tx_in = Input()
        prevout_hash = vds.read_bytes(32)[::-1].encode('hex')
        prevout_n = vds.read_uint32()
        scriptSig = vds.read_bytes(vds.read_compact_size())
        sequence = vds.read_uint32()

        tx_in.in_sn = in_sn
        tx_in.prev_tx_hash = prevout_hash
        tx_in.prev_out_sn = prevout_n
        tx_in.in_signature = scriptSig.encode('hex')
        tx_in.in_sequence = sequence
        return tx_in

    def get_tx_in_dict(self):
        d = {}
        d['scriptSig'] = self.in_signature
        d['prevout_hash'] = self.prev_tx_hash
        d['prevout_n'] = self.prev_out_sn
        d['sequence'] = self.in_sequence
        if self.prev_tx_hash == '00' * 32:
            d['type'] = 'coinbase'
            self.in_address = None
        else:
            d['pubkeys'] = []
            d['signatures'] = {}
            d['address'] = None
            if self.in_signature:
                parse_scriptSig(d, self.in_signature)
            self.in_address = d['address']
        self.in_dict = d

    def serialize_input(self):
        script = self.in_signature
        # if script_type == 1:
        pubkeys, x_pubkeys = self.get_sorted_pubkeys()
        script = Script().input_script(self.in_dict, pubkeys, x_pubkeys)

        # Prev hash and index
        s = self.serialize_outpoint()
        # Script length, script, sequence
        s += int_to_hex(len(script) / 2)
        s += script
        s += write_uint32(self.in_sequence).encode('hex')
        return s

    def serialize_input_preimage(self, i):
        if i == self.in_sn:
            # serialize self
            script = Script().get_script_pubkey(self.in_address)
        else:
            # serialize other input
            script = ''
        # Prev hash and index
        s = self.serialize_outpoint()
        # Script length, script, sequence
        s += int_to_hex(len(script) / 2)
        s += script
        s += write_uint32(self.in_sequence).encode('hex')
        return s

    def serialize_outpoint(self):
        return self.prev_tx_hash.decode('hex')[::-1].encode('hex') \
               + write_uint32(self.prev_out_sn).encode('hex')

    def get_sorted_pubkeys(self):
        # sort pubkeys and x_pubkeys, using the order of pubkeys
        x_pubkeys = self.in_dict['x_pubkeys']
        pubkeys = self.in_dict.get('pubkeys')
        if pubkeys is None:
            pubkeys = [xpubkey_to_pubkey(x) for x in x_pubkeys]
            pubkeys, x_pubkeys = zip(*sorted(zip(pubkeys, x_pubkeys)))
            self.in_dict['pubkeys'] = pubkeys = list(pubkeys)
            self.in_dict['x_pubkeys'] = x_pubkeys = list(x_pubkeys)
        return pubkeys, x_pubkeys

    def is_segwit_input(self):
        return self.in_dict['type'] in ['p2wpkh-p2sh']

    def get_preimage_script(self):
        # only for non-segwit
        if self.in_dict['type'] == 'p2pkh':
            return get_scriptPubKey(self.in_address)
        elif self.in_dict['type'] == 'p2sh':
            pubkeys, x_pubkeys = self.get_sorted_pubkeys()
            return multisig_script(pubkeys, self.in_dict['num_sig'])
        else:
            raise TypeError('Unknown txin type', self.in_dict['type'])

    def estimated_input_size(self):
        '''Return an estimated of serialized input size in bytes.'''
        # todo:
        return 34
        # script = self.input_script(True)
        # return len(self.serialize_input(script)) / 2

    @property
    def is_coinbase(self):
        return self.prev_tx_hash == '00' * 32


class Transaction(object):
    tx_hash = None
    tx_ver = 0
    tx_locktime = 0
    tx_time = 0
    block_no = -1
    source = -1

    raw = None
    need_deserialize = False

    _output_list = None
    _input_list = None

    def __init__(self):
        """
        new transaction
        """
        self.tx_ver = 1
        self._output_list = []
        self._input_list = []

    @classmethod
    def init_from_raw(cls, raw, lazy_load=True):
        pass

    @classmethod
    def from_io(cls, inputs, outputs, locktime=0, tx_ver=1):
        self = cls()
        self._input_list = inputs
        self._output_list = outputs
        self.locktime = locktime
        self.tx_ver = tx_ver
        return self

    def serialize(self, estimate_size=False, witness=True):
        """
        raw to struct info

        :return:
        """
        version = write_uint32(self.tx_ver).encode('hex')
        locktime = write_uint32(self.tx_locktime).encode('hex')
        input_list = self._input_list
        output_list = self._output_list
        txins = int_to_hex(len(input_list)) + ''.join(
            txin.serialize_input() for txin in input_list)
        txouts = int_to_hex(len(output_list)) + ''.join(o.serialize_output() for o in output_list)
        if witness and self.is_segwit():
            marker = '00'
            flag = '01'
            witness = ''.join(x.serialize_witness() for x in input_list)
            return version + marker + flag + txins + txouts + witness + locktime
        else:
            return version + txins + txouts + locktime

    def is_segwit(self):
        return False

    def deserialize(self):
        """
        struct info to raw
        :return:
        """
        if self.raw is None or not self.need_deserialize:
            return
        vds = BCDataStream()
        vds.write(self.raw.decode('hex'))

        start = vds.read_cursor
        self.tx_ver = vds.read_int32()
        n_vin = vds.read_compact_size()
        is_segwit = (n_vin == 0)
        if is_segwit:
            marker = vds.read_bytes(1)
            assert marker == chr(1)
            n_vin = vds.read_compact_size()
        self._input_list = []
        for i in xrange(n_vin):
            self._input_list.append(Input.init_from_raw(vds, i))
        n_vout = vds.read_compact_size()
        self._output_list = []
        for i in xrange(n_vout):
            self._output_list.append(Output.init_from_raw(vds, i))
        # if is_segwit:
        #     d['witness'] = list(parse_witness(vds) for i in xrange(n_vin))
        self.tx_locktime = vds.read_uint32()
        self.need_deserialize = False

    def serialize_preimage(self, i):
        """
        get to be sign content
        :param i:
        :return:
        """
        version = write_uint32(self.tx_ver).encode('hex')
        hash_type = write_uint32(1).encode('hex')
        locktime = write_uint32(self.tx_locktime).encode('hex')
        input_list = self._input_list
        output_list = self._output_list
        txin = input_list[i]
        if txin.is_segwit_input():
            hash_prevouts = double_sha256(
                ''.join(txin.serialize_outpoint() for txin in input_list).decode('hex')).encode(
                'hex')
            hash_sequence = double_sha256(
                ''.join(write_uint32(txin.in_sequence) for txin in input_list).decode(
                    'hex')).encode('hex')
            hash_outputs = double_sha256(
                ''.join(o.serialize_output() for o in output_list).decode('hex')).encode('hex')
            outpoint = txin.serialize_outpoint()
            pubkey = txin.in_dict['pubkeys'][0]
            pkh = hash_160(pubkey.decode('hex')).encode('hex')
            # redeem_script = '00' + push_script(pkh)
            script_code = push_script('76a9' + push_script(pkh) + '88ac')
            # script_hash = hash_160(redeem_script.decode('hex')).encode('hex')
            # script_pub_key = 'a9' + push_script(script_hash) + '87'
            amount = write_uint64(txin.in_value)
            sequence = write_uint32(txin.in_sequence)
            preimage = version + hash_prevouts + hash_sequence + outpoint + script_code + amount + sequence + hash_outputs + locktime + hash_type
        else:
            txins = int_to_hex(len(input_list)) + ''.join(
                txin.serialize_input_preimage(k) for
                k, txin in enumerate(input_list))
            txouts = int_to_hex(len(output_list)) + ''.join(
                o.serialize_output() for o in output_list)
            preimage = version + txins + txouts + locktime + hash_type
        return preimage

    def sign(self, keypairs):
        """

        :param keypairs: pubkey:secret dict
        :return:
        """
        for i, txin in enumerate(self._input_list):
            num = txin.in_dict['num_sig']
            pubkeys, x_pubkeys = txin.get_sorted_pubkeys()
            for j, x_pubkey in enumerate(x_pubkeys):
                signatures = filter(None, txin.in_dict['signatures'])
                if len(signatures) == num:
                    # txin is complete
                    break
                if x_pubkey in keypairs.keys():
                    print_error("adding signature for", x_pubkey)
                    secret = keypairs.get(x_pubkey)
                    key = EC_KEY.init_from_secret(secret)
                    msg = double_sha256(self.serialize_preimage(i).decode('hex'))
                    sig = key.sign(msg)
                    assert key.verify_sign(sig, msg)
                    txin.in_dict['signatures'][j] = sig.encode('hex')
                    txin.in_dict['x_pubkeys'][j] = x_pubkeys
                    self._input_list[i] = txin
        # print_error("is_complete", self.is_complete())
        self.raw = self.serialize()

    def __str__(self):
        return self.serialize()


    def estimated_size(self):
        """
        Return an estimated tx size in bytes.
        """
        return len(self.serialize(True)) / 2 if not self.is_complete() or self.raw is None else len(
            self.raw) / 2  # ASCII hex string


    def input_list(self):
        self.deserialize()
        return self._input_list

    def output_list(self):
        self.deserialize()
        return self._output_list

    def input_value(self):
        return sum(x.in_value for x in self.input_list())

    def output_value(self):
        return sum(e.out_value for e in self.output_list())

    def get_fee(self):
        return self.input_value() - self.output_value()

    def add_input_list(self, inputs):
        self._input_list.extend(inputs)
        self.raw = None

    def add_output_list(self, outputs):
        self._output_list.extend([Output(e) for e in outputs])
        self.raw = None

    def is_complete(self):
        s, r = self.signature_count()
        return r == s

    def signature_count(self):
        r = 0
        s = 0
        for txin in self.input_list():
            if txin.is_coinbase:
                continue
            signatures = filter(None, txin.in_dict.get('signatures', []))
            s += len(signatures)
            r += txin.in_dict.get('num_sig', -1)
        return s, r

    def bip_li01_sort(self):
        # See https://github.com/kristovatlas/rfc/blob/master/bips/bip-li01.mediawiki
        self._input_list.sort(key=lambda i: (i.prev_tx_hash, i.prev_out_sn))
        for idx, each in enumerate(self._input_list):
            if each.in_sn is None:
                each.in_sn = idx
        self._output_list.sort(key=lambda o: (o.out_value, o.out_script))
        for idx, each in enumerate(self._output_list):
            if each.out_sn is None:
                each.out_sn = idx

    def txid(self):
        all_segwit = all(x.is_segwit_input() for x in self.input_list())
        if not all_segwit and not self.is_complete():
            return None
        ser = self.serialize(witness=False)
        return double_sha256(ser.decode('hex'))[::-1].encode('hex')


