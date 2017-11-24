# -*- coding: utf-8 -*-
from electrumq.utils.parser import write_uint32, int_to_hex
from electrumq.utils.tx import BCDataStream, parse_scriptSig, get_address_from_output_script

__author__ = 'zhouqi'


class TxMaker(object):
    pass


class Output(object):
    tx_hash = None
    out_sn = None
    out_value = None
    out_address = None
    address_type = None
    out_script = None

    @classmethod
    def init_from_raw(cls, vds, out_sn):
        tx_out = Output()
        tx_out.out_sn = out_sn
        tx_out.out_value = vds.read_int64()
        tx_out.out_script = vds.read_bytes(vds.read_compact_size()).encode('hex')
        tx_out.address_type, tx_out.out_address = get_address_from_output_script(
            tx_out.out_script.decode('hex'))
        return tx_out


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
            txin.serialize_input(txin.input_script(estimate_size)) for txin in input_list)
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
        pass

    def sign(self, keypairs):
        """

        :param keypairs: pubkey:secret dict
        :return:
        """
        pass

    def __str__(self):
        return self.serialize()
