# -*- coding: utf-8 -*-

import struct

from utils.opcode import *
from utils.base58 import hash_160_to_bc_address, public_key_to_bc_address, hash_160

__author__ = 'zhouqi'


def read_uint16(content, offset=0):
    return struct.unpack_from('<H', content, offset)[0]


def read_uint32(content, offset=0):
    return struct.unpack_from('<I', content, offset)[0]


def read_uint64(content, offset=0):
    return struct.unpack_from('<Q', content, offset)[0]


def read_compact_size(content, offset=0):
    size = ord(content[offset])
    offset += 1
    if size == 253:
        size = read_uint16(content, offset)
        offset += 2
    elif size == 254:
        size = read_uint32(content, offset)
        offset += 4
    elif size == 255:
        size = read_uint64(content, offset)
        offset += 8
    return size, offset

def parse_TxIn(reader):
    d = {}
    d['start'] = reader.read_cursor
    d['prevout_hash'] = reader.read_bytes(32)
    d['prevout_n'] = reader.read_uint32()
    d['scriptSig'] = reader.read_bytes(reader.read_compact_size())
    d['sequence'] = reader.read_uint32()
    d['end'] = reader.read_cursor
    return d


def parse_TxOut(reader):
    d = {}
    d['start'] = reader.read_cursor
    d['value'] = reader.read_int64()
    d['scriptPubKey'] = reader.read_bytes(reader.read_compact_size())
    d['end'] = reader.read_cursor
    return d


def parse_Transaction(reader, has_nTime=False):
    d = {}
    start_pos = reader.read_cursor
    d['version'] = reader.read_int32()
    if has_nTime:
        d['nTime'] = reader.read_uint32()
    n_vin = reader.read_compact_size()
    d['txIn'] = []
    for i in xrange(n_vin):
        d['txIn'].append(parse_TxIn(reader))
    n_vout = reader.read_compact_size()
    d['txOut'] = []
    for i in xrange(n_vout):
        d['txOut'].append(parse_TxOut(reader))
    d['lockTime'] = reader.read_uint32()
    d['__data__'] = reader.input[start_pos:reader.read_cursor]
    return d


def parse_MerkleTx(reader):
    d = parse_Transaction(reader)
    d['hashBlock'] = reader.read_bytes(32)
    n_merkleBranch = reader.read_compact_size()
    d['merkleBranch'] = reader.read_bytes(32 * n_merkleBranch)
    d['nIndex'] = reader.read_int32()
    return d


def parse_BlockHeader(reader):
    d = {}
    header_start = reader.read_cursor
    d['version'] = reader.read_int32()
    d['hashPrev'] = reader.read_bytes(32)
    d['hashMerkleRoot'] = reader.read_bytes(32)
    d['nTime'] = reader.read_uint32()
    d['nBits'] = reader.read_uint32()
    d['nNonce'] = reader.read_uint32()
    header_end = reader.read_cursor
    d['__header__'] = reader.input[header_start:header_end]
    return d


def parse_Block(reader):
    d = parse_BlockHeader(reader)
    d['transactions'] = []
    # if d['version'] & (1 << 8):
    # d['auxpow'] = parse_AuxPow(vds)
    nTransactions = reader.read_compact_size()
    for i in xrange(nTransactions):
        d['transactions'].append(parse_Transaction(reader))

    return d


def parse_BlockLocator(reader):
    d = {'hashes': []}
    nHashes = reader.read_compact_size()
    for i in xrange(nHashes):
        d['hashes'].append(reader.read_bytes(32))
    return d


def parse_script(script):
    i = 0
    result = []
    while i < len(script):
        vch = ''
        op_code = ord(script[i])
        i += 1

        try:
            size = -1
            if OP_0 <= op_code < OP_PUSHDATA1:
                size = op_code
            elif op_code == OP_PUSHDATA1:
                size = ord(script[i])
                i += 1
            elif op_code == OP_PUSHDATA2:
                size = struct.unpack_from('<H', script, i)[0]
                i += 2
            elif op_code == OP_PUSHDATA4:
                size = struct.unpack_from('<I', script, i)[0]
                i += 4

            if size != -1:
                vch = script[i:i + size]
                i += size
        except:
            vch = '_INVALID_NULL'
            i = len(script)

        result.append((op_code, vch, i))
    return result


def get_pattern(decoded):
    result = []
    for each in decoded:
        if OP_0 < each[0] <= OP_PUSHDATA4:
            result.append(OP_PUSHDATA4)
        else:
            result.append(each[0])
    return result


def extract_script_pub_key(script):
    decoded = parse_script(script)
    pattern = get_pattern(decoded)

    # The Genesis Block, self-payments, and pay-by-IP-address payments look like:
    # 65 BYTES:... CHECKSIG
    match = [OP_PUSHDATA4, OP_CHECKSIG]
    if pattern == match:
        return public_key_to_bc_address(decoded[0][1]), decoded[0][1]

    # Pay-by-Bitcoin-address TxOuts look like:
    # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
    match = [OP_DUP, OP_HASH160, OP_PUSHDATA4, OP_EQUALVERIFY, OP_CHECKSIG]
    if pattern == match:
        return hash_160_to_bc_address(decoded[2][1]), None

    # BIP16 TxOuts look like:
    # HASH160 20 BYTES:... EQUAL
    match = [OP_HASH160, OP_PUSHDATA4, OP_EQUAL]
    if pattern == match:
        return hash_160_to_bc_address(decoded[1][1], version="\x05"), None

    # BIP11 TxOuts look like one of these:
    # Note that match_decoded is dumb, so OP_1 actually matches OP_1/2/3/etc:
    first = [e + 0x51 for e in range(16)]  # [OP_1, OP_2, OP_3]
    left = [[OP_PUSHDATA4, ] * (e + 1) + [e + 0x51] + [OP_CHECKMULTISIG, ] for e in range(16)]
    # left = [[OP_PUSHDATA4, OP_1, OP_CHECKMULTISIG],
    # [OP_PUSHDATA4, OP_PUSHDATA4, OP_2, OP_CHECKMULTISIG],
    # [OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4, OP_3, OP_CHECKMULTISIG]]
    multisigs = [[x, ] + y for x in first for y in left]
    if pattern in multisigs:
        return "[" + ','.join([public_key_to_bc_address(decoded[i][1]) for i in range(1, len(decoded) - 2)]) + "]" \
            , chr(len(decoded) - 3) + ''.join([decoded[i][1] for i in xrange(1, len(decoded) - 2)])

    return None, None

def extract_script_pub_key2(script):
    decoded = parse_script(script)
    pattern = get_pattern(decoded)

    # The Genesis Block, self-payments, and pay-by-IP-address payments look like:
    # 65 BYTES:... CHECKSIG
    match = [OP_PUSHDATA4, OP_CHECKSIG]
    if pattern == match:
        return hash_160(decoded[0][1]), "\x01", decoded[0][1]

    # Pay-by-Bitcoin-address TxOuts look like:
    # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
    match = [OP_DUP, OP_HASH160, OP_PUSHDATA4, OP_EQUALVERIFY, OP_CHECKSIG]
    if pattern == match:
        return decoded[2][1], "\x01", None

    # BIP16 TxOuts look like:
    # HASH160 20 BYTES:... EQUAL
    match = [OP_HASH160, OP_PUSHDATA4, OP_EQUAL]
    if pattern == match:
        return decoded[1][1], "\x05", None

    # # BIP11 TxOuts look like one of these:
    # # Note that match_decoded is dumb, so OP_1 actually matches OP_1/2/3/etc:
    # first = [e + 0x51 for e in range(16)]  # [OP_1, OP_2, OP_3]
    # left = [[OP_PUSHDATA4, ] * (e + 1) + [e + 0x51] + [OP_CHECKMULTISIG, ] for e in range(16)]
    # # left = [[OP_PUSHDATA4, OP_1, OP_CHECKMULTISIG],
    # # [OP_PUSHDATA4, OP_PUSHDATA4, OP_2, OP_CHECKMULTISIG],
    # # [OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4, OP_3, OP_CHECKMULTISIG]]
    # multisigs = [[x, ] + y for x in first for y in left]
    # if pattern in multisigs:
    #     return "[" + ','.join([public_key_to_bc_address(decoded[i][1]) for i in range(1, len(decoded) - 2)]) + "]" \
    #         , chr(len(decoded) - 3) + ''.join([decoded[i][1] for i in xrange(1, len(decoded) - 2)])

    return None, None, None


def extract_script_pub_key_full(byte):
    decoded = parse_script(byte)
    pattern = get_pattern(decoded)

    # The Genesis Block, self-payments, and pay-by-IP-address payments look like:
    # 65 BYTES:... CHECKSIG
    match = [OP_PUSHDATA4, OP_CHECKSIG]
    if pattern == match:
        # return None, None
        return public_key_to_bc_address(decoded[0][1]), decoded[0][1]

    # Pay-by-Bitcoin-address TxOuts look like:
    # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
    match = [OP_DUP, OP_HASH160, OP_PUSHDATA4, OP_EQUALVERIFY, OP_CHECKSIG]
    if pattern == match:
        # return None, None
        return hash_160_to_bc_address(decoded[2][1]), None

    # BIP16 TxOuts look like:
    # HASH160 20 BYTES:... EQUAL
    match = [OP_HASH160, OP_PUSHDATA4, OP_EQUAL]
    if pattern == match:
        # return None, None
        return hash_160_to_bc_address(decoded[1][1], version="\x05"), None

    # BIP11 TxOuts look like one of these:
    # Note that match_decoded is dumb, so OP_1 actually matches OP_1/2/3/etc:
    first = [e + 0x51 for e in range(16)]  # [OP_1, OP_2, OP_3]
    left = [[OP_PUSHDATA4, ] * (e + 1) + [e + 0x51] + [OP_CHECKMULTISIG, ] for e in range(16)]
    # left = [[OP_PUSHDATA4, OP_1, OP_CHECKMULTISIG],
    # [OP_PUSHDATA4, OP_PUSHDATA4, OP_2, OP_CHECKMULTISIG],
    # [OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4, OP_3, OP_CHECKMULTISIG]]
    multisigs = [[x, ] + y for x in first for y in left]
    if pattern in multisigs:
        for e in decoded[1:-2]:
            isNone = False
            if e[1] is None:
                isNone = True
        # return None, None
        return "[" + ','.join([public_key_to_bc_address(decoded[i][1]) for i in range(1, len(decoded) - 2)]) + "]" \
            , chr(len(decoded) - 3) + ''.join([decoded[i][1] for i in xrange(1, len(decoded) - 2)])

    if len(pattern) > 20:
        # too many OP_CHECKSIG
        return 'unknown', None

    if pattern == [OP_DUP, OP_HASH160, OP_PUSHDATA4, OP_EQUALVERIFY, OP_CHECKSIG, OP_NOP]:
        # 5492a05f1edfbd29c525a3dbf45f654d0fc45a805ccd620d0a4dff47de63f90b 0
        # cee16a9b222f636cd27d734da0a131cee5dd7a1d09cb5f14f4d1330b22aaa38e 0
        # 0adfc9f9ace87a2956626777c2e2637c789ca4919a77c314d53ffc1d0bc8ad38 0
        # 3077f4b06d7cdb9434019696b4e1dcb6daddde4331ca3749bdd599d50912f569 2
        # db3f14e43fecc80eb3e0827cecce85b3499654694d12272bf91b1b2b8c33b5cb 2
        return 'unknown', None

    if pattern == [OP_DUP, OP_HASH160, OP_FALSE, OP_EQUALVERIFY, OP_CHECKSIG]:
        # out:6d5088c138e2fbf4ea7a8c2cb1b57a76c4b0a5fab5f4c188696aad807a5ba6d8 0
        # out:07d33c8c74e945c50e45d3eaf4add7553534154503a478cf6d48e1c617b3f9f3 0
        # out:6d39eeb2ae7f9d42b0569cf1009de4c9f031450873bf2ec84ce795837482e7a6 0
        # out:2d00ef4895f20904d7d4c0bada17a8e9d47d6c049cd2e5002f8914bfa7f1d27b 1
        # out:15ad0894ab42a46eb04108fb8bd66786566a74356d2103f077710733e0516c3a 1
        # out:03acfae47d1e0b7674f1193237099d1553d3d8a93ecc85c18c4bec37544fe386 1
        # out:3ab5f53978850413a273920bfc86f4278d9c418272accddade736990d60bdd53 1
        # out:0ca7f7299dc8d87c26c82badf9a303049098af050698c694fbec35c4b08fc3df 0
        # out:7ad47a19b201ce052f98161de1b1457bacaca2e698f542e196d4c7f8f45899ab 0
        # out:6a86e6a5e8d5f9e9492114dafe5056c5618222f5042408ad867d3c1888855a31 0
        # out:aa62bdd690de061a6fbbd88420f7a7aa574ba86da4fe82edc27e2263f8743988 0
        # out:aebe39a99114f1b46fc5a67289545e54cbfec92d08fc8ffc92dc9df4a15ea05a 1
        # out:835d4dcc52e160c23173658de0b747082f1937d1184e8e1838e9394bc62c0392 1
        # out:9edab6e7fadf1d6006315ff9394c08a7bf42e19cf61502200a1f73994f8da94b 1
        # out:3be0ac3dc1c3b7fa7fbe34f4678037ed733a14e801abe6d3da42bc643a651401 1
        # out:64c01fedd5cf6d306ca18d85e842f068e19488126c411741e089be8f4052df09 1
        # out:5bd88ab32b50e4a691dcfd1fff9396f512e003d7275bb5c1b816ab071beca5ba 1
        # out:633acf266c913523ab5ed9fcc4632bae18d2a7efc1744fd43dd669e5f2869ce5 0
        # out:f0137a6b31947cf7ab367ae23942a263272c41f36252fcd3460ee8b6e94a84c1 0
        # out:305fbc2ec7f7f2bc5a21d2dfb01a5fc52ab5d064a7278e2ecbab0d2a27b8c392 0
        # out:ddddf9f04b4c1d4e1185cacf5cf302f3d11dee5d74f71721d741fbb507062e9e 0
        # out:81f591582b436c5b129f347fe7e681afd6811417973c4a4f83b18e92a9d130fd 1
        # out:111291fcf8ab84803d42ec59cb4eaceadd661185242a1e8f4b7e49b79ecbe5f3 1
        return 'unknown', None

    if pattern == [OP_PUSHDATA4]:
        # odds coin base out
        return 'unknown', None

    if pattern == [OP_IFDUP, OP_IF, OP_2SWAP, OP_VERIFY, OP_2OVER, OP_DEPTH]:
        # odds coin base out
        return 'unknown', None

    if pattern == [OP_PUSHDATA4, OP_NOP2, OP_DROP]:
        # can spent by OP_FALSE 30440220276d6dad3defa37b5f81add3992d510d2f44a317fd85e04f93a1e2daea64660202200f862a0da684249322ceb8ed842fb8c859c0cb94c81e1c5308b4868157a428ee01 OP_CODESEPARATOR OP_1 0232abdc893e7f0631364d7fd01cb33d24da45329a00357b3a7886211ab414d55a OP_1 OP_CHECKMULTISIG
        # b8fd633e7713a43d5ac87266adc78444669b987a56b3a65fb92d58c2c4b0e84d 2
        return 'unknown', None

    if pattern == [OP_PUSHDATA4, OP_DROP, OP_SHA256, OP_PUSHDATA4, OP_EQUAL]:
        # can spent by 04678afd04678a (04678afd04678afd OP_DROP OP_SHA256 894eeb82f9a851f5d1cb1be3249f58bc8d259963832c5e7474a76f7a859ee95c OP_EQUAL )
        # 9969603dca74d14d29d1d5f56b94c7872551607f8c2d6837ab9715c60721b50e
        # can spent by 04678afd04678a (04678afd04678afd OP_DROP OP_SHA256 894eeb82f9a851f5d1cb1be3249f58bc8d259963832c5e7474a76f7a859ee95c OP_EQUAL)
        # 8c8baf2e0529c0193ad3a583306a16fcc3e9cd271ba625e12bfd74261a46ad7c
        return 'unknown', None

    if pattern == [OP_DUP, OP_HASH160, OP_PUSHDATA4, OP_EQUALVERIFY, OP_NOP1]:
        # OP_DUP OP_HASH160 07e761706c63b36e5a328fab1d94e9397f40704d OP_EQUALVERIFY OP_NOP1 spent by 04e19cb94dab9efa1e4507c17c81d4fdb0fc9d03c01caac970995ca4788f6e3fd3b2eb0efba75a98b1e1a62f9bdcb71430ce066869facb4f1e20b9ee1d1669b356
        # f003f0c1193019db2497a675fd05d9f2edddf9b67c59e677c48d3dbd4ed5f00b
        return 'unknown', None

    if pattern == [OP_DUP, OP_DUP, OP_DUP]:
        # can spent by OP_1
        # b38bb421d9a54c58ea331c4b4823dd498f1e42e25ac96d3db643308fcc70503e
        return 'unknown', None

    if pattern == [OP_3, OP_DROP, OP_DROP, OP_1]:
        # can spent by OP_1
        # c0b69d1e5ed13732dbd704604f7c08bc96549cc556c464aa42cc7525b3897987
        return 'unknown', None

    if pattern == [OP_MIN, OP_3, OP_EQUAL]:
        # can spent by "hex" : "01030103"  [OP_PUSHDATA4, OP_PUSHDATA4]  or "hex" : "5354"
        # aea682d68a3ea5e3583e088dcbd699a5d44d4b083f02ad0aaf2598fe1fa4dfd4
        return 'unknown', None

    if pattern == [OP_1]:
        # can spent by [OP_FALSE OP_DROP]
        # cdb553214a51ef8d4393b96a185ebbbc2c84b7014e9497fea8aec1ff990dae35
        return 'unknown', None

    if pattern == [OP_HASH256, OP_PUSHDATA4, OP_EQUAL]:
        # af32bb06f12f2ae5fdb7face7cd272be67c923e86b7a66a76ded02d954c2f94d
        # OP_HASH256 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000 OP_EQUAL can spent by 0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c
        # a4bfa8ab6435ae5f25dae9d89e4eb67dfa94283ca751f393c1ddc5a837bbc31b
        return 'unknown', None

    if pattern == [OP_PUSHDATA4, OP_DROP, OP_DUP, OP_HASH160, OP_PUSHDATA4, OP_EQUALVERIFY, OP_CHECKSIG]:
        # c0b2cf75b47d1e7f48cdb4287109ff1dd5bcf146d5f77a9e8784c0c9c0ef02ad
        # 010000000127478b07dae63322d1999419115cf287c69ff0f11de3f96d46df6926de61143c010000006b483045022100cca50bfed991240a7603eea19340f6e24102b29db2dfcc56fdfe549dacddcc6402207eefe2688670d349615ed184d1f84ac54365afd258524e55266c992ce2d68b7f012102ff9d6e0c33fb3cfc677857d2cd654db91fe051811433654d25442ee0182dac52000000000180969800000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688accc500300 OP_DROP OP_DUP OP_HASH160 fb99bed1a4ea8d1d01d879581fce07b27ab5357f OP_EQUALVERIFY OP_CHECKSIG spent by 30450221008e03c31c35c151be8ffd865c9e411346562797c267a956a8177239beaceb70a102207aa18e8ff22c69a00b616d91bdd3b2e9b0777d06c17165ad650399f8fb1e0b5701 028f2bb71ec2c796cab46d5b61c28ad6cde73dacacf60f18943788053d6040eacd
        # 2bf4ff04b40d03ff71570877d8267aed91d3595d172737d096241d08277135e2
        return 'unknown', None

    if pattern == [OP_RETURN, OP_PUSHDATA4] or pattern == [OP_RETURN] or pattern[0] == OP_RETURN:
        # 220fb62341d3cc95ac4080daf9b953b68f75647a8b39587c2b712d65dedd2b2a
        return 'unknown', None

    if pattern == [OP_IF, OP_HASH160, OP_PUSHDATA4, OP_EQUALVERIFY, OP_HASH160, OP_PUSHDATA4, OP_EQUALVERIFY,
                   OP_HASH160, OP_PUSHDATA4, OP_EQUAL, OP_ELSE, OP_PUSHDATA4, OP_CHECKSIG, OP_ENDIF]:
        # 002d2eabd145d13ed20a6a005b77a35d4041ae3c868a10c173b90e6383ff6dbf
        return 'unknown', None

    if pattern == [OP_DEPTH, OP_NOP8, OP_DUP, OP_TOALTSTACK, OP_DUP, OP_3, OP_NOP, OP_EQUAL, OP_IF, OP_DROP, OP_HASH256,
                   OP_PUSHDATA4, OP_EQUALVERIFY, OP_NOP1, OP_ELSE, OP_7, OP_NOP7, OP_EQUAL, OP_NOTIF, OP_RETURN,
                   OP_RESERVED, OP_VER, OP_RESERVED1, OP_RESERVED2, OP_ENDIF, OP_NEGATE, OP_3, OP_ADD, OP_NOP2, OP_ABS,
                   OP_2, OP_SUB, OP_2, OP_EQUALVERIFY, OP_NOP6, OP_NOP9, OP_FROMALTSTACK, OP_DUP, OP_3, OP_ADD,
                   OP_TOALTSTACK, OP_SWAP, OP_NEGATE, OP_2, OP_SUB, OP_NOP10, OP_ABS, OP_MIN, OP_5, OP_EQUALVERIFY,
                   OP_FROMALTSTACK, OP_DUP, OP_TOALTSTACK, OP_1SUB, OP_6, OP_NOP4, OP_SUB, OP_EQUALVERIFY, OP_ADD,
                   OP_NOP5, OP_4, OP_EQUALVERIFY, OP_ENDIF, OP_DUP, OP_HASH160, OP_PUSHDATA4, OP_NOP3, OP_EQUALVERIFY,
                   OP_CHECKSIG, OP_PUSHDATA4, OP_DROP]:
        # dd754e98867fc8eab853d721d32a160418acca020e6dddeb27592c7628177486
        # OP_DEPTH OP_NOP8 OP_DUP OP_TOALTSTACK OP_DUP OP_3 OP_NOP OP_EQUAL OP_IF OP_DROP OP_HASH256 7a73cf250e33244910bd6316b57dbadfcb7a8deb63e5b3b148d0c7b8465cfcc2 OP_EQUALVERIFY OP_NOP1 OP_ELSE OP_7 OP_NOP7 OP_EQUAL OP_NOTIF OP_RETURN OP_RESERVED OP_VER OP_RESERVED1 OP_RESERVED2 OP_ENDIF OP_NEGATE OP_3 OP_ADD OP_NOP2 OP_ABS OP_2 OP_SUB OP_2 OP_EQUALVERIFY OP_NOP6 OP_NOP9 OP_FROMALTSTACK OP_DUP OP_3 OP_ADD OP_TOALTSTACK OP_SWAP OP_NEGATE OP_2 OP_SUB OP_NOP10 OP_ABS OP_MIN OP_5 OP_EQUALVERIFY OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_1SUB OP_6 OP_NOP4 OP_SUB OP_EQUALVERIFY OP_ADD OP_NOP5 OP_4 OP_EQUALVERIFY OP_ENDIF OP_DUP OP_HASH160 3df74edff637d4c649e16ad96d8b45a71bc8daf9 OP_NOP3 OP_EQUALVERIFY OP_CHECKSIG 20706f7574696e652f667265656e6f646520 OP_DROP can spent by 3044022062df12f33c8abf30cdb73625a1d0e3c507640f0f7cce650b96da6304a9b7797502203975fc2e197198d57483d7815a32b097c01ed6b542f62f6e4cb91409ca1e8e7601 0330c6eb121ba4e2defe7a56101c52623cec4d34142975b8fcb1483b710dbfd5e2 OP_3 OP_1 OP_3 OP_3 OP_7
        return 'unknown', None

    if pattern == [OP_ADD, OP_ADD, OP_13, OP_EQUAL, OP_PUSHDATA4, OP_DROP]:
        # can spent by [OP_4, OP_6, OP_3]
        # a165c82cf21a6bae54dde98b7e00ab43b695debb59dfe7d279ac0c59d6043e24
        return 'unknown', None

    if pattern == [OP_PUSHDATA4, OP_DROP, OP_1]:
        # can spent by [OP_1]
        # 8ff89472c457f97c30d5013382377107dd204bc734c1c6003cda9fceecd09842
        return 'unknown', None

    if pattern == [OP_SIZE, OP_PUSHDATA4, OP_PUSHDATA4, OP_WITHIN, OP_SWAP, OP_SHA256, OP_PUSHDATA4, OP_EQUAL,
                   OP_BOOLAND, OP_SWAP, OP_PUSHDATA4, OP_CHECKSIGVERIFY, OP_SWAP, OP_PUSHDATA4, OP_CHECKSIG, OP_BOOLOR]:
        # 9837a637931f74df1cb52b1045e479e4d7065f72db4d449d732211eb0e5cfd4c
        return 'unknown', None

    print(pattern)
    return None, None


def extract_script_sig(byte):
    decoded = parse_script(byte)
    pattern = get_pattern(decoded)

    # non-generated TxIn transactions push a signature
    # (seventy-something bytes) and then their public key
    # (33 or 65 bytes) onto the stack:
    match = [OP_PUSHDATA4, OP_PUSHDATA4]
    if pattern == match:
        return public_key_to_bc_address(decoded[1][1]), decoded[1][1]

    return None, None

def extract_script_sig2(byte):
    decoded = parse_script(byte)
    pattern = get_pattern(decoded)

    # non-generated TxIn transactions push a signature
    # (seventy-something bytes) and then their public key
    # (33 or 65 bytes) onto the stack:
    match = [OP_PUSHDATA4, OP_PUSHDATA4]
    if pattern == match:
        return hash_160(decoded[1][1]), "\x01", decoded[1][1]

    multisigs = [[OP_0, ] + [OP_PUSHDATA4, ] * i for i in range(1, 20)]
    if pattern in multisigs:
        # multi-sig
        return hash_160(decoded[-1][1]), '\x05', None

    return None, None, None


def extract_script_sig_full(byte):
    decoded = parse_script(byte)
    pattern = get_pattern(decoded)

    match = [OP_PUSHDATA4]
    if pattern == match:
        # depend on out
        return None, None

    # non-generated TxIn transactions push a signature
    # (seventy-something bytes) and then their public key
    # (33 or 65 bytes) onto the stack:
    match = [OP_PUSHDATA4, OP_PUSHDATA4]
    if pattern == match:
        # return None, None
        return public_key_to_bc_address(decoded[1][1]), decoded[1][1]

    # multisigs = [[OP_0, OP_PUSHDATA4],
    # [OP_0, OP_PUSHDATA4, OP_PUSHDATA4],
    # [OP_0, OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4],
    #              [OP_0, OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4]]
    multisigs = [[OP_0, ] + [OP_PUSHDATA4, ] * i for i in range(1, 20)]
    if pattern in multisigs:
        # multi-sig
        return None, None

    p1 = [OP_FALSE, ]
    p2s = [[OP_PUSHDATA4, OP_CODESEPARATOR, OP_1], [OP_PUSHDATA4, OP_PUSHDATA4, OP_CODESEPARATOR, OP_2]
        , [OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4, OP_CODESEPARATOR, OP_3]]
    p3s = [[OP_PUSHDATA4, OP_1], [OP_PUSHDATA4, OP_PUSHDATA4, OP_2], [OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4, OP_3]]
    p4 = [OP_CHECKMULTISIG, ]
    odds_multisigs = [p1 + p2 + p3 + p4 for p2 in p2s for p3 in p3s]
    if pattern in odds_multisigs:
        # spent odds out [OP_PUSHDATA4, OP_NOP2, OP_DROP]
        return 'unknown', None

    if pattern == [OP_1]:
        # can spent [OP_DUP, OP_DUP, OP_DUP] [OP_3, OP_DROP, OP_DROP, OP_1]  and p2pool 's coinbase 's first out( it can also spent by empty script).
        return 'unknown', None

    if pattern == [OP_3, OP_4]:
        # can spent [OP_MIN, OP_3, OP_EQUAL]
        # 3ee060fb1856f111859fb108d079635a2d225ef68d5ae5250ce70d39ac2a2dc4
        return 'unknown', None

    if pattern == [OP_FALSE, OP_DROP]:
        # can spent [OP_1]
        # 51874c4b26a92dacb256f0e60303daabf60a63681111c4c1948f0bba25d8df96
        return 'unknown', None

    if pattern == []:
        # can spent odds p2pool 's coinbase
        # c58b6a83c1b09a90011c4663380fea67977424df757f4459109583c56821308a
        return 'unknown', None

    if pattern == [OP_1, OP_FALSE]:
        # OP_1 OP_FALSE can spent OP_HASH160 e9454f0ffef4501baf8199e8927c6a8f922a8b7a OP_EQUAL
        # e3d0d35635bf2aaf9a0c492dbabe34d5a0c1954054e582bd02e23f645d8c4d38
        # d7a74d6039a8f3724a13deaa4660f19c488826227df9d738de8fd71b8091228c
        # 0d2dcd5582cf62c198ece2976efda177682b890a323cff1c6512cdbe65d531bb
        return 'unknown', None

    if pattern == [OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4]:
        # 13378d03853777510f071657c838fdca09f10b615c959b424ff3a3ea01eb0b49 can spent [OP_HASH160 fc7f6a8a9df76e0fa8e3fc1d519509fdfc4ad259 OP_EQUAL ]
        return 'unknown', None

    if pattern == [OP_FALSE, OP_PUSHDATA4, OP_PUSHDATA4, OP_FALSE, OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4]:
        # [OP_FALSE, OP_PUSHDATA4, OP_PUSHDATA4, OP_FALSE, OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4] can spent OP_HASH160 82e3fbe1795234de2bdfe8525a7be1b7f62ee219 OP_EQUAL
        # 37f0880ded42171a5f3dcc471f35c79027233ff0fe3178bebcb071729c75e5a3
        # 3b6ffb563fb32b9782cc183acd8694b74cee483f2443fe86c550de102c8972ae
        return 'unknown', None

    if pattern == [OP_1, OP_RIGHT, OP_PUSHDATA4]:
        # OP_1 OP_RIGHT 6e879169907c9087 can spent OP_HASH160 fe441065b6532231de2fac563152205ec4f59c74 OP_EQUAL
        # d2eb886aa53ea9a7f1199c48618086caa918ecbe1a61dfc0ec7d42aea5a41c80
        return 'unknown', None

    if pattern == [OP_1, ] or pattern == [OP_1, OP_2, ] or pattern == [OP_0, OP_NOT] \
            or pattern == [OP_FALSE, OP_FALSE, OP_FALSE, OP_CHECKMULTISIG] or pattern == [OP_1, OP_NOP1] \
            or pattern == [OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4, OP_1, OP_PUSHDATA4] \
            or pattern == [OP_1, OP_PUSHDATA4]:
        # 08e1026eaf044127d7103415570afd564dfac3131d7a5e4b645f591cd349bb2c
        # 7bdc22fb35f0a8eb6241782a306a8904fb6f793126ff106a04a96f9f223cb8e1
        return 'unknown', None

    if pattern == [OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4, OP_1]:
        # 9b78962d840f1ff681e5042264e4d0359cda98ce49d97569df14ce956622b966
        return 'unknown', None

    if pattern == [OP_PUSHDATA4, OP_1, OP_PUSHDATA4]:
        # 937946719beafc7ea9f5c751f58d6b414094866854926dddd9ca9b64874121fb
        return 'unknown', None

    if pattern == [OP_FALSE, OP_PUSHDATA4, OP_PUSHDATA4, OP_FALSE, OP_1, OP_PUSHDATA4]:
        # 9967963c900fb9896ab88021b401c6d197ac9337d368b0d3ac7cb8e987088507
        return 'unknown', None

    if pattern == [OP_FALSE, OP_PUSHDATA4, OP_PUSHDATA4, OP_1, OP_1, OP_PUSHDATA4]:
        # 0b274321565b7eb2d7b71af60be3e3d7a710e6681c3407c9c51dd21e569614d9
        return 'unknown', None

    if pattern == [OP_FALSE, OP_FALSE, OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4]:
        # 4ea91ccfdcfb1d5b27b0e0da31253c7e2f39215792fbe4d125b9d26acae82b88
        return 'unknown', None

    if pattern == [OP_PUSHDATA4, OP_PUSHDATA4, OP_3, OP_1, OP_3, OP_3, OP_7]:
        # 4fea28ca023cae8498cf10541826f5da8e06eabf0d9cc03c8cdc4b91cb0c49e2
        return 'unknown', None

    if pattern == [OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4]:
        # c8b86e0dcfe3a1dd48c99ee4b5ddf6172a552303e7f338d49124e060caf62d09
        return 'unknown', None

    if pattern == [OP_1, OP_PUSHDATA4, OP_PUSHDATA4]:
        # d2eb886aa53ea9a7f1199c48618086caa918ecbe1a61dfc0ec7d42aea5a41c80
        return 'unknown', None

    if pattern == [OP_FALSE, OP_PUSHDATA4, OP_PUSHDATA4, OP_1, OP_PUSHDATA4]:
        # bc7477925c98b6ec04aa5c270cfa24b1712c6e16910b09c24d5477f26ecc9faf
        return 'unknown', None

    if pattern == [OP_PUSHDATA4, OP_PUSHDATA4, OP_1]:
        # 3044022056af64535e0235f197375158f8bfc9271fef5e6653bc6b6e9218793671a6ba7c02203db72457a929094b81aa919886ad2a65997cbd7159f02d63e3c967e92f6f64e201 48656c6c6f20576f726c6421 OP_1 spent OP_IF OP_HASH160 85b0c1edc20ec4437ab5f936a7e1691498dd0a73 OP_EQUALVERIFY 03a64bea9701f7225af90f6bdc7ae1ea9374e8a9e3cc91524ae1a970aa237704bf OP_CHECKSIG OP_ELSE 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_CHECKSIG OP_ENDIF
        # f722419970705db54ba8785b01a16afac3d398822676615100a228b5c02939ce
        return 'unknown', None

    if pattern == [OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4, OP_PUSHDATA4]:
        # 073485b9ef24033c39592f14027afd19ddf6cab7b2a1a797d8fa4cb0434c8afb
        return 'unknown', None

    if pattern == [OP_8, OP_6, OP_7, OP_5, OP_3, OP_FALSE, OP_9]:
        # 2c1462024303955581e74ff750a019ed817f682191eb1ef7e3162d91a17cb633
        return 'unknown', None

    if pattern == [OP_4, OP_6, OP_3]:
        # 435fb30baf0d93712d021158636be1e1bc77c557e5b8e4c687741f8275687001
        return 'unknown', None

    print(pattern)
    return None, None


def parse_sig_from_in(in_bytes):
    l, offset = read_compact_size(in_bytes, 36)
    in_script = in_bytes[offset:offset + l]
    return parse_sig_from_in_script(in_script)


def parse_sig_from_in_script(in_script):
    decoded = parse_script(in_script)
    result = []
    for e in decoded:
        if is_sign(e[1]):
            r, s = parse_sig(e[1])
            if r is not None and s is not None:
                result.append((r, s))
    return result


def is_sign(sig_bytes):
    if len(sig_bytes) > 1 and ord(sig_bytes[0]) == 0x30 and len(sig_bytes) == ord(sig_bytes[1]) + 3:
        return True
    else:
        return False


def parse_sig(sig_bytes):
    if ord(sig_bytes[0]) == 0x30 and len(sig_bytes) == ord(sig_bytes[1]) + 3:
        pos = 3
        r = sig_bytes[pos + 1: pos + ord(sig_bytes[pos]) + 1]
        if len(r) == 33 and r[0] == '\x00':
            r = r[-32:]
        pos += 1 + ord(sig_bytes[pos]) + 1
        s = sig_bytes[pos + 1: pos + ord(sig_bytes[pos]) + 1]
        if len(s) == 33 and s[0] == '\x00':
            s = s[-32:]
        return r, s
    else:
        return None, None


# def parse_r_from_in_script(in_script):
#     decoded = parse_script(in_script)
#     result = []
#     for e in decoded:
#         if e[1] is not None and len(e[1]) > 33 and ord(e[1][0]) == 0x30:
#             result.append(parse_r_from_sig(e[1]))
#     return result
#
#
# def parse_r_from_sig(sig):
#     start = 4
#     if sig[3] == '\x21' and sig[4] == '\x00':
#         start = 5
#     return sig[start:start + 32]
#
#
# def parse_r(in_bytes):
#     l, offset = read_compact_size(in_bytes, 36)
#     in_script = in_bytes[offset:offset + l]
#     return parse_r_from_in_script(in_script)
#
#
# def parse_r_and_s(in_bytes):
#     l, offset = read_compact_size(in_bytes, 36)
#     in_script = in_bytes[offset:offset + l]
#     decoded = parse_script(in_script)
#     result = []
#     for e in decoded:
#         if e[1] is not None and len(e[1]) > 33 and ord(e[1][0]) == 0x30:
#             tmp = parse_sig(e[1])
#             if tmp != None:
#                 result.append(tmp)
#     return result
#
#
# def parse_r_from_in_script(in_script):
#     # l, offset = read_compact_size(in_bytes, 36)
#     # in_script = in_bytes[offset:offset + l]
#     decoded = parse_script(in_script)
#     result = []
#     for e in decoded:
#         if e[1] is not None and len(e[1]) > 33 and ord(e[1][0]) == 0x30:
#             result.append(parse_r_from_sig(e[1]))
#     return result
