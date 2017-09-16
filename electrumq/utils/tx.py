# -*- coding: utf-8 -*-
import exceptions
import hashlib
import struct
import types

from ecdsa import SECP256k1, util

from electrumq.utils import *
from electrumq.utils.base58 import hash160_to_p2sh, hash160_to_p2pkh, hash_160, \
    bc_address_to_type_and_hash_160, double_sha256
from electrumq.utils.key import public_key_from_private_key, MySigningKey
from electrumq.utils.key import regenerate_key
from electrumq.utils.key_store import xpubkey_to_pubkey, xpubkey_to_address
from electrumq.utils.parameter import TYPE_SCRIPT, TYPE_ADDRESS, TYPE_PUBKEY, Parameter
from electrumq.utils.parser import int_to_hex, op_push, write_uint32, write_uint64

__author__ = 'zhouqi'

NO_SIGNATURE = 'ff'


class Output(object):
    tx_hash = None
    out_sn = None
    out_value = None
    out_address = None
    address_type = None
    out_script = None

    def __init__(self, tx_out_dict=None):
        super(Output, self).__init__()
        if tx_out_dict is not None:
            self.out_address = tx_out_dict[1]
            self.address_type = tx_out_dict[0]
            self.out_value = tx_out_dict[2]
            if len(tx_out_dict) == 4:
                self.out_script = tx_out_dict[3]

    def parse_output_json(self, vds, out_sn):
        self.out_sn = out_sn
        self.out_value = vds.read_int64()
        self.out_script = vds.read_bytes(vds.read_compact_size()).encode('hex')
        self.address_type, self.out_address = get_address_from_output_script(
            self.out_script.decode('hex'))

    def pay_script(self):
        if self.address_type == TYPE_SCRIPT:
            return self.out_address.encode('hex')
        elif self.address_type == TYPE_ADDRESS:
            return get_scriptPubKey(self.out_address)
        else:
            raise TypeError('Unknown output type')

    def serialize_output(self):
        s = write_uint64(self.out_value).encode('hex')
        script = self.pay_script()
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

    def __init__(self, tx_in_dict=None):
        super(Input, self).__init__()

        if tx_in_dict is not None:
            self.prev_tx_hash = tx_in_dict['prevout_hash']
            self.prev_out_sn = tx_in_dict['prevout_n']
            self.in_signature = tx_in_dict['scriptSig']
            self.in_value = tx_in_dict['value']
            self.in_address = tx_in_dict['address']
            self.height = tx_in_dict['height']

    @property
    def is_coinbase(self):
        return self.prev_tx_hash == '00' * 32

    def parse_input_json(self, vds, in_sn):
        d = {}
        prevout_hash = vds.read_bytes(32)[::-1].encode('hex')
        prevout_n = vds.read_uint32()
        scriptSig = vds.read_bytes(vds.read_compact_size())
        sequence = vds.read_uint32()

        self.in_sn = in_sn
        self.prev_tx_hash = prevout_hash
        self.prev_out_sn = prevout_n
        self.in_signature = scriptSig.encode('hex')
        self.in_sequence = sequence

        d['scriptSig'] = scriptSig.encode('hex')
        d['prevout_hash'] = prevout_hash
        d['prevout_n'] = prevout_n
        d['sequence'] = sequence
        if prevout_hash == '00' * 32:
            d['type'] = 'coinbase'
            self.in_address = None
        else:
            d['pubkeys'] = []
            d['signatures'] = {}
            d['address'] = None
            if scriptSig:
                parse_scriptSig(d, scriptSig)
            self.in_address = d['address']
        self.in_dict = d
        return d

    def serialize_input(self, script):
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

    def get_preimage_script(self):
        # only for non-segwit
        if self.in_dict['type'] == 'p2pkh':
            return get_scriptPubKey(self.in_address)
        elif self.in_dict['type'] == 'p2sh':
            pubkeys, x_pubkeys = self.get_sorted_pubkeys()
            return multisig_script(pubkeys, self.in_dict['num_sig'])
        else:
            raise TypeError('Unknown txin type', self.in_dict['type'])

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

    def input_script(self, estimate_size=False):
        _type = self.in_dict['type']
        if _type == 'coinbase':
            return self.in_dict['scriptSig']
        pubkeys, sig_list = self.get_siglist(estimate_size)
        script = ''.join(push_script(x) for x in sig_list)
        if _type == 'p2pk':
            pass
        elif _type == 'p2sh':
            # put op_0 before script
            script = '00' + script
            redeem_script = multisig_script(pubkeys, self.in_dict['num_sig'])
            script += push_script(redeem_script)
        elif _type == 'p2pkh':
            script += push_script(pubkeys[0])
        elif _type == 'p2wpkh-p2sh':
            redeem_script = self.in_dict.get('redeemScript') or segwit_script(pubkeys[0])
            return push_script(redeem_script)
        elif _type == 'address':
            script += push_script(pubkeys[0])
        else:
            raise TypeError('Unknown txin type', _type)
        return script

    def get_siglist(self, estimate_size=False):
        # if we have enough signatures, we use the actual pubkeys
        # otherwise, use extended pubkeys (with bip32 derivation)
        num_sig = self.in_dict.get('num_sig', 1)
        if estimate_size:
            # we assume that signature will be 0x48 bytes long
            pk_list = ["00" * 0x21] * num_sig
            sig_list = ["00" * 0x48] * num_sig
        else:
            pubkeys, x_pubkeys = self.get_sorted_pubkeys()
            x_signatures = self.in_dict['signatures']
            signatures = filter(None, x_signatures)
            is_complete = len(signatures) == num_sig
            if is_complete:
                pk_list = pubkeys
                sig_list = [(sig + '01') for sig in signatures]
            else:
                pk_list = x_pubkeys
                sig_list = [(sig + '01') if sig else NO_SIGNATURE for sig in x_signatures]
        return pk_list, sig_list

    def serialize_witness(self):
        pubkeys, sig_list = self.get_siglist()
        n = len(pubkeys) + len(sig_list)
        return int_to_hex(n) + ''.join(push_script(x) for x in sig_list) + ''.join(
            push_script(x) for x in pubkeys)

    def estimated_input_size(self):
        '''Return an estimated of serialized input size in bytes.'''
        script = self.input_script(True)
        return len(self.serialize_input(script)) / 2

    def is_segwit_input(self):
        return self.in_dict['type'] in ['p2wpkh-p2sh']


class Transaction:
    def __str__(self):
        if self.raw is None:
            self.raw = self.serialize()
        return self.raw

    def __init__(self, raw):
        if raw is None:
            self.raw = None
        elif type(raw) in [str, unicode]:
            self.raw = raw.strip() if raw else None
        elif type(raw) is dict:
            self.raw = raw['hex']
        else:
            raise BaseException("cannot initialize transaction", raw)
        self._input_list = []
        self._output_list = []
        self.need_deserialize = True
        self.locktime = 0
        self.tx_ver = 1

    @classmethod
    def from_io(cls, inputs, outputs, locktime=0, tx_ver=1):
        self = cls(None)
        self._input_list = inputs
        self._output_list = outputs
        self.locktime = locktime
        self.tx_ver = tx_ver
        return self

    def update(self, raw):
        self.raw = raw
        self.need_deserialize = True
        self.deserialize()

    def input_list(self):
        self.deserialize()
        return self._input_list

    def output_list(self):
        self.deserialize()
        return self._output_list

    @classmethod
    def get_sorted_pubkeys(cls, txin):
        # sort pubkeys and x_pubkeys, using the order of pubkeys
        x_pubkeys = txin['x_pubkeys']
        pubkeys = txin.get('pubkeys')
        if pubkeys is None:
            pubkeys = [xpubkey_to_pubkey(x) for x in x_pubkeys]
            pubkeys, x_pubkeys = zip(*sorted(zip(pubkeys, x_pubkeys)))
            txin['pubkeys'] = pubkeys = list(pubkeys)
            txin['x_pubkeys'] = x_pubkeys = list(x_pubkeys)
        return pubkeys, x_pubkeys

    def deserialize(self):
        if self.raw is None or not self.need_deserialize:
            return
        d = deserialize(self.raw)
        self._input_list = d['input_list']
        self._output_list = d['output_list']
        self.locktime = d['lockTime']
        self.tx_ver = d['version']
        self.need_deserialize = False
        return d

    def set_rbf(self, rbf):
        sequence = 0xffffffff - (2 if rbf else 0)
        for txin in self.input_list():
            txin.in_sequence = sequence

    def bip_li01_sort(self):
        # See https://github.com/kristovatlas/rfc/blob/master/bips/bip-li01.mediawiki
        self._input_list.sort(key=lambda i: (i.prev_tx_hash, i.prev_out_sn))
        self._output_list.sort(key=lambda o: (o.out_value, o.pay_script()))

    def serialize_preimage(self, i):
        version = write_uint32(self.tx_ver).encode('hex')
        hash_type = write_uint32(1).encode('hex')
        locktime = write_uint32(self.locktime).encode('hex')
        input_list = self.input_list()
        output_list = self.output_list()
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
                txin.serialize_input(txin.get_preimage_script() if i == k else '') for
                k, txin in enumerate(input_list))
            txouts = int_to_hex(len(output_list)) + ''.join(
                o.serialize_output() for o in output_list)
            preimage = version + txins + txouts + locktime + hash_type
        return preimage

    def is_segwit(self):
        return any(x.is_segwit_input() for x in self.input_list())

    def serialize(self, estimate_size=False, witness=True):
        version = write_uint32(self.tx_ver).encode('hex')
        locktime = write_uint32(self.locktime).encode('hex')
        # inputs = self.inputs()
        input_list = self.input_list()
        # outputs = self.outputs()
        output_list = self.output_list()
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

    def hash(self):
        print "warning: deprecated tx.hash()"
        return self.txid()

    def txid(self):
        all_segwit = all(x.is_segwit_input() for x in self.input_list())
        if not all_segwit and not self.is_complete():
            return None
        ser = self.serialize(witness=False)
        return double_sha256(ser.decode('hex'))[::-1].encode('hex')

    def wtxid(self):
        ser = self.serialize(witness=True)
        return double_sha256(ser.decode('hex'))[::-1].encode('hex')

    def add_input_list(self, inputs):
        self._input_list.extend(inputs)
        self.raw = None

    def add_output_list(self, outputs):
        self._output_list.extend([Output(e) for e in outputs])
        self.raw = None

    def input_value(self):
        return sum(x.in_value for x in self.input_list())

    def output_value(self):
        return sum(e.out_value for e in self.output_list())

    def get_fee(self):
        return self.input_value() - self.output_value()

    def is_final(self):
        return not any([x.in_sequence < 0xffffffff - 1 for x in self.input_list()])

    # @profiler
    def estimated_size(self):
        '''Return an estimated tx size in bytes.'''
        return len(self.serialize(True)) / 2 if not self.is_complete() or self.raw is None else len(
            self.raw) / 2  # ASCII hex string

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

    def is_complete(self):
        s, r = self.signature_count()
        return r == s

    def sign(self, keypairs):
        for i, txin in enumerate(self.input_list()):
            num = txin.in_dict['num_sig']
            pubkeys, x_pubkeys = txin.get_sorted_pubkeys()
            for j, x_pubkey in enumerate(x_pubkeys):
                signatures = filter(None, txin.in_dict['signatures'])
                if len(signatures) == num:
                    # txin is complete
                    break
                if x_pubkey in keypairs.keys():
                    print_error("adding signature for", x_pubkey)
                    sec = keypairs.get(x_pubkey)
                    pubkey = public_key_from_private_key(sec)
                    # add signature
                    pre_hash = double_sha256(self.serialize_preimage(i).decode('hex'))
                    pkey = regenerate_key(sec)
                    secexp = pkey.secret
                    private_key = MySigningKey.from_secret_exponent(secexp, curve=SECP256k1)
                    public_key = private_key.get_verifying_key()
                    sig = private_key.sign_digest_deterministic(pre_hash, hashfunc=hashlib.sha256,
                                                                sigencode=util.sigencode_der)
                    assert public_key.verify_digest(sig, pre_hash,
                                                    sigdecode=util.sigdecode_der)
                    txin.in_dict['signatures'][j] = sig.encode('hex')
                    txin.in_dict['x_pubkeys'][j] = pubkey
                    self._input_list[i] = txin
                    # self._inputs[i] = txin
        print_error("is_complete", self.is_complete())
        self.raw = self.serialize()

    def has_address(self, addr):
        return (addr in (e.out_address for e in self.output_list())) or (
            addr in (tx.in_dict.get("address") for tx in self.input_list()))

    def as_dict(self):
        if self.raw is None:
            self.raw = self.serialize()
        self.deserialize()
        out = {
            'hex': self.raw,
            'complete': self.is_complete(),
            'final': self.is_final(),
        }
        return out

    def requires_fee(self, wallet):
        # see https://en.bitcoin.it/wiki/Transaction_fees
        #
        # size must be smaller than 1 kbyte for free tx
        size = len(self.serialize()) / 2
        if size >= 10000:
            return True
        # all outputs must be 0.01 BTC or larger for free tx
        for tx_out in self.output_list():
            if tx_out.out_value < 1000000:
                return True
        # priority must be large enough for free tx
        threshold = 57600000
        weight = 0
        for txin in self.input_list():
            height, conf, timestamp = wallet.get_tx_height(txin.prev_tx_hash)
            weight += txin.in_value * conf
        priority = weight / size
        print_error(priority, threshold)

        return priority < threshold


class EnumException(exceptions.Exception):
    pass


class Enumeration:
    def __init__(self, name, enumList):
        self.__doc__ = name
        lookup = {}
        reverseLookup = {}
        i = 0
        uniqueNames = []
        uniqueValues = []
        for x in enumList:
            if type(x) == types.TupleType:
                x, i = x
            if type(x) != types.StringType:
                raise EnumException, "enum name is not a string: " + x
            if type(i) != types.IntType:
                raise EnumException, "enum value is not an integer: " + i
            if x in uniqueNames:
                raise EnumException, "enum name is not unique: " + x
            if i in uniqueValues:
                raise EnumException, "enum value is not unique for " + x
            uniqueNames.append(x)
            uniqueValues.append(i)
            lookup[x] = i
            reverseLookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverseLookup = reverseLookup

    def __getattr__(self, attr):
        if not self.lookup.has_key(attr):
            raise AttributeError
        return self.lookup[attr]

    def whatis(self, value):
        return self.reverseLookup[value]


opcodes = Enumeration("Opcodes", [
    ("OP_0", 0), ("OP_PUSHDATA1", 76), "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE", "OP_RESERVED",
    "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7",
    "OP_8", "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF", "OP_ELSE", "OP_ENDIF",
    "OP_VERIFY",
    "OP_RETURN", "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP", "OP_2OVER",
    "OP_2ROT", "OP_2SWAP",
    "OP_IFDUP", "OP_DEPTH", "OP_DROP", "OP_DUP", "OP_NIP", "OP_OVER", "OP_PICK", "OP_ROLL",
    "OP_ROT",
    "OP_SWAP", "OP_TUCK", "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE", "OP_INVERT",
    "OP_AND",
    "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY", "OP_RESERVED1", "OP_RESERVED2", "OP_1ADD",
    "OP_1SUB", "OP_2MUL",
    "OP_2DIV", "OP_NEGATE", "OP_ABS", "OP_NOT", "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL",
    "OP_DIV",
    "OP_MOD", "OP_LSHIFT", "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR",
    "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL", "OP_LESSTHAN",
    "OP_GREATERTHAN", "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX",
    "OP_WITHIN", "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160",
    "OP_HASH256", "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    ("OP_SINGLEBYTE_END", 0xF0),
    ("OP_DOUBLEBYTE_BEGIN", 0xF000),
    "OP_PUBKEY", "OP_PUBKEYHASH",
    ("OP_INVALIDOPCODE", 0xFFFF),
])


def script_GetOp(bytes):
    i = 0
    while i < len(bytes):
        vch = None
        opcode = ord(bytes[i])
        i += 1
        if opcode >= opcodes.OP_SINGLEBYTE_END:
            opcode <<= 8
            opcode |= ord(bytes[i])
            i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                nSize = ord(bytes[i])
                i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                (nSize,) = struct.unpack_from('<H', bytes, i)
                i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                (nSize,) = struct.unpack_from('<I', bytes, i)
                i += 4
            vch = bytes[i:i + nSize]
            i += nSize

        yield (opcode, vch, i)


def script_GetOpName(opcode):
    return (opcodes.whatis(opcode)).replace("OP_", "")


def decode_script(bytes):
    result = ''
    for (opcode, vch, i) in script_GetOp(bytes):
        if len(result) > 0: result += " "
        if opcode <= opcodes.OP_PUSHDATA4:
            result += "%d:" % (opcode,)
            result += vch.encode('hex')
        else:
            result += script_GetOpName(opcode)
    return result


def match_decoded(decoded, to_match):
    if len(decoded) != len(to_match):
        return False
    for i in range(len(decoded)):
        if to_match[i] == opcodes.OP_PUSHDATA4 and decoded[i][0] <= opcodes.OP_PUSHDATA4 and \
                        decoded[i][0] > 0:
            continue  # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        if to_match[i] != decoded[i][0]:
            return False
    return True


def parse_sig(x_sig):
    s = []
    for sig in x_sig:
        if sig[-2:] == '01':
            s.append(sig[:-2])
        else:
            assert sig == NO_SIGNATURE
            s.append(None)
    return s


def parse_scriptSig(d, bytes):
    try:
        decoded = [x for x in script_GetOp(bytes)]
    except Exception:
        # coinbase transactions raise an exception
        print_error("cannot find address in input script", bytes.encode('hex'))
        return

    match = [opcodes.OP_PUSHDATA4]
    if match_decoded(decoded, match):
        item = decoded[0][1]
        if item[0] == chr(0):
            redeemScript = item.encode('hex')
            d['address'] = hash160_to_p2sh(hash_160(redeemScript.decode('hex')))
            d['type'] = 'p2wpkh-p2sh'
            d['redeemScript'] = redeemScript
            d['x_pubkeys'] = ["(witness)"]
            d['pubkeys'] = ["(witness)"]
            d['signatures'] = ['(witness)']
            d['num_sig'] = 1
        else:
            # payto_pubkey
            d['type'] = 'p2pk'
            d['address'] = "(pubkey)"
            d['signatures'] = [item.encode('hex')]
            d['num_sig'] = 1
            d['x_pubkeys'] = ["(pubkey)"]
            d['pubkeys'] = ["(pubkey)"]
        return

    # non-generated TxIn transactions push a signature
    # (seventy-something bytes) and then their public key
    # (65 bytes) onto the stack:
    match = [opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4]
    if match_decoded(decoded, match):
        sig = decoded[0][1].encode('hex')
        x_pubkey = decoded[1][1].encode('hex')
        try:
            signatures = parse_sig([sig])
            pubkey, address = xpubkey_to_address(x_pubkey)
        except:
            import traceback
            traceback.print_exc(file=sys.stdout)
            # print_error("cannot find address in input script", bytes.encode('hex'))
            return
        d['type'] = 'p2pkh'
        d['signatures'] = signatures
        d['x_pubkeys'] = [x_pubkey]
        d['num_sig'] = 1
        d['pubkeys'] = [pubkey]
        d['address'] = address
        return

    # p2sh transaction, m of n
    match = [opcodes.OP_0] + [opcodes.OP_PUSHDATA4] * (len(decoded) - 1)
    if not match_decoded(decoded, match):
        print_error("cannot find address in input script", bytes.encode('hex'))
        return
    x_sig = [x[1].encode('hex') for x in decoded[1:-1]]
    dec2 = [x for x in script_GetOp(decoded[-1][1])]
    m = dec2[0][0] - opcodes.OP_1 + 1
    n = dec2[-2][0] - opcodes.OP_1 + 1
    op_m = opcodes.OP_1 + m - 1
    op_n = opcodes.OP_1 + n - 1
    match_multisig = [op_m] + [opcodes.OP_PUSHDATA4] * n + [op_n, opcodes.OP_CHECKMULTISIG]
    if not match_decoded(dec2, match_multisig):
        print_error("cannot find address in input script", bytes.encode('hex'))
        return
    x_pubkeys = map(lambda x: x[1].encode('hex'), dec2[1:-2])
    pubkeys = [xpubkey_to_pubkey(x) for x in x_pubkeys]
    redeemScript = multisig_script(pubkeys, m)
    # write result in d
    d['type'] = 'p2sh'
    d['num_sig'] = m
    d['signatures'] = parse_sig(x_sig)
    d['x_pubkeys'] = x_pubkeys
    d['pubkeys'] = pubkeys
    d['redeemScript'] = redeemScript
    d['address'] = hash160_to_p2sh(hash_160(redeemScript.decode('hex')))


def get_address_from_output_script(bytes):
    decoded = [x for x in script_GetOp(bytes)]

    # The Genesis Block, self-payments, and pay-by-IP-address payments look like:
    # 65 BYTES:... CHECKSIG
    match = [opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG]
    if match_decoded(decoded, match):
        return TYPE_PUBKEY, decoded[0][1].encode('hex')

    # Pay-by-Bitcoin-address TxOuts look like:
    # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
    match = [opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY,
             opcodes.OP_CHECKSIG]
    if match_decoded(decoded, match):
        return TYPE_ADDRESS, hash160_to_p2pkh(decoded[2][1])

    # p2sh
    match = [opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUAL]
    if match_decoded(decoded, match):
        return TYPE_ADDRESS, hash160_to_p2sh(decoded[1][1])

    return TYPE_SCRIPT, bytes


# def parse_input(vds, in_sn):
#     d = {}
#     prevout_hash = vds.read_bytes(32)[::-1].encode('hex')
#     prevout_n = vds.read_uint32()
#     scriptSig = vds.read_bytes(vds.read_compact_size())
#     sequence = vds.read_uint32()
#     d['scriptSig'] = scriptSig.encode('hex')
#     d['prevout_hash'] = prevout_hash
#     d['prevout_n'] = prevout_n
#     d['sequence'] = sequence
#     if prevout_hash == '00' * 32:
#         d['type'] = 'coinbase'
#     else:
#         d['pubkeys'] = []
#         d['signatures'] = {}
#         d['address'] = None
#         if scriptSig:
#             parse_scriptSig(d, scriptSig)
#     return d


def parse_witness(vds):
    n = vds.read_compact_size()
    for i in range(n):
        x = vds.read_bytes(vds.read_compact_size())


# def parse_output(vds, i):
#     d = {}
#     d['value'] = vds.read_int64()
#     scriptPubKey = vds.read_bytes(vds.read_compact_size())
#     d['type'], d['address'] = get_address_from_output_script(scriptPubKey)
#     d['scriptPubKey'] = scriptPubKey.encode('hex')
#     d['prevout_n'] = i
#     return d


class SerializationError(Exception):
    """ Thrown when there's a problem deserializing or serializing """


class BCDataStream(object):
    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, data):  # Initialize with string of bytes
        if self.input is None:
            self.input = data
        else:
            self.input += data

    def read_string(self):
        # Strings are encoded depending on length:
        # 0 to 252 :  1-byte-length followed by bytes (if any)
        # 253 to 65,535 : byte'253' 2-byte-length followed by bytes
        # 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
        # ... and the Bitcoin client is coded to understand:
        # greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
        # ... but I don't think it actually handles any strings that big.
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        try:
            length = self.read_compact_size()
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

        return self.read_bytes(length)

    def write_string(self, string):
        # Length-encoded as with read-string
        self.write_compact_size(len(string))
        self.write(string)

    def read_bytes(self, length):
        try:
            result = self.input[self.read_cursor:self.read_cursor + length]
            self.read_cursor += length
            return result
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

    def read_boolean(self):
        return self.read_bytes(1)[0] != chr(0)

    def read_int16(self):
        return self._read_num('<h')

    def read_uint16(self):
        return self._read_num('<H')

    def read_int32(self):
        return self._read_num('<i')

    def read_uint32(self):
        return self._read_num('<I')

    def read_int64(self):
        return self._read_num('<q')

    def read_uint64(self):
        return self._read_num('<Q')

    def write_boolean(self, val):
        return self.write(chr(1) if val else chr(0))

    def write_int16(self, val):
        return self._write_num('<h', val)

    def write_uint16(self, val):
        return self._write_num('<H', val)

    def write_int32(self, val):
        return self._write_num('<i', val)

    def write_uint32(self, val):
        return self._write_num('<I', val)

    def write_int64(self, val):
        return self._write_num('<q', val)

    def write_uint64(self, val):
        return self._write_num('<Q', val)

    def read_compact_size(self):
        size = ord(self.input[self.read_cursor])
        self.read_cursor += 1
        if size == 253:
            size = self._read_num('<H')
        elif size == 254:
            size = self._read_num('<I')
        elif size == 255:
            size = self._read_num('<Q')
        return size

    def write_compact_size(self, size):
        if size < 0:
            raise SerializationError("attempt to write size < 0")
        elif size < 253:
            self.write(chr(size))
        elif size < 2 ** 16:
            self.write('\xfd')
            self._write_num('<H', size)
        elif size < 2 ** 32:
            self.write('\xfe')
            self._write_num('<I', size)
        elif size < 2 ** 64:
            self.write('\xff')
            self._write_num('<Q', size)

    def _read_num(self, format):
        (i,) = struct.unpack_from(format, self.input, self.read_cursor)
        self.read_cursor += struct.calcsize(format)
        return i

    def _write_num(self, format, num):
        s = struct.pack(format, num)
        self.write(s)


def deserialize(raw):
    vds = BCDataStream()
    vds.write(raw.decode('hex'))
    d = {}
    start = vds.read_cursor
    d['version'] = vds.read_int32()
    n_vin = vds.read_compact_size()
    is_segwit = (n_vin == 0)
    if is_segwit:
        marker = vds.read_bytes(1)
        assert marker == chr(1)
        n_vin = vds.read_compact_size()
    d['input_list'] = []
    for i in xrange(n_vin):
        tx_in = Input()
        tx_in.parse_input_json(vds, i)
        d['input_list'].append(tx_in)
    d['inputs'] = [e.in_dict for e in
                   d['input_list']]  # list(Input().parse_input_json(vds, i) for i in xrange(n_vin))
    n_vout = vds.read_compact_size()
    d['output_list'] = []
    for i in xrange(n_vout):
        tx_out = Output()
        tx_out.parse_output_json(vds, i)
        d['output_list'].append(tx_out)
    d['outputs'] = [e.out_dict for e in d[
        'output_list']]  # list(Output().parse_output_json(vds, i) for i in xrange(n_vout))
    if is_segwit:
        d['witness'] = list(parse_witness(vds) for i in xrange(n_vin))
    d['lockTime'] = vds.read_uint32()
    return d


# pay & redeem scripts

def push_script(x):
    return op_push(len(x) / 2) + x


def get_scriptPubKey(addr):
    addrtype, hash_160 = bc_address_to_type_and_hash_160(addr)
    if addrtype == Parameter().ADDRTYPE_P2PKH:
        script = '76a9'  # op_dup, op_hash_160
        script += push_script(hash_160.encode('hex'))
        script += '88ac'  # op_equalverify, op_checksig
    elif addrtype == Parameter().ADDRTYPE_P2SH:
        script = 'a9'  # op_hash_160
        script += push_script(hash_160.encode('hex'))
        script += '87'  # op_equal
    else:
        raise BaseException('unknown address type')
    return script


def segwit_script(pubkey):
    pkh = hash_160(pubkey.decode('hex')).encode('hex')
    return '00' + push_script(pkh)


def multisig_script(public_keys, m):
    n = len(public_keys)
    assert n <= 15
    assert m <= n
    op_m = format(opcodes.OP_1 + m - 1, 'x')
    op_n = format(opcodes.OP_1 + n - 1, 'x')
    keylist = [op_push(len(k) / 2) + k for k in public_keys]
    return op_m + ''.join(keylist) + op_n + 'ae'
