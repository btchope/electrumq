# -*- coding: utf-8 -*-
import logging
import traceback

from db.sqlite import execute_one
from utils import Singleton
from utils.base58 import reverse_hex_str, Hash
from utils.parser import int_to_hex, write_compact_size, write_uint32

__author__ = 'zhouqi'

MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

logger = logging.getLogger('blockstore')

class BlockStore():
    __metaclass__ = Singleton

    _chained_headers = []
    _unchain_headers = []

    def __init__(self):
        pass

    @property
    def height(self):
        return len(self._chained_headers) - 1
        # return execute_one('select ifnull(max(block_no),-1) from blocks')

    def save_header(self, header):
        data = self.serialize_header_hex(header)
        assert len(data) == 80
        height = header.get('block_height')
        if height - len(self._chained_headers) + 1 > 0:
            self._chained_headers.extend([None, ] * (height - len(self._chained_headers) + 1))
        self._chained_headers[height] = data

    def read_header(self, block_height):
        if self.height < block_height or self._chained_headers[block_height] is None:
            return None
        h = self._chained_headers[block_height]
        if len(h) == 80:
            h = self.deserialize_header(h)
            return h
        return None

    def get_target(self, index, chain=None):
        if index == 0:
            return 0x1d00ffff, MAX_TARGET
        first = self.read_header((index - 1) * 2016)
        last = self.read_header(index * 2016 - 1)
        if last is None:
            for h in chain:
                if h.get('block_height') == index * 2016 - 1:
                    last = h
        assert last is not None
        # bits to target
        bits = last.get('bits')
        bitsN = (bits >> 24) & 0xff
        assert bitsN >= 0x03 and bitsN <= 0x1d, "First part of bits should be in [0x03, 0x1d]"
        bitsBase = bits & 0xffffff
        assert bitsBase >= 0x8000 and bitsBase <= 0x7fffff, "Second part of bits should be in [0x8000, 0x7fffff]"
        target = bitsBase << (8 * (bitsN - 3))
        # new target
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 14 * 24 * 60 * 60
        nActualTimespan = max(nActualTimespan, nTargetTimespan / 4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
        new_target = min(MAX_TARGET, (target * nActualTimespan) / nTargetTimespan)
        # convert new target to bits
        c = ("%064x" % new_target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) / 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        new_bits = bitsN << 24 | bitsBase
        return new_bits, bitsBase << (8 * (bitsN - 3))

    def deserialize_header(self, s):
        hex_to_int = lambda s: int('0x' + s[::-1].encode('hex'), 16)
        h = {}
        h['version'] = hex_to_int(s[0:4])
        h['prev_block_hash'] = s[4:36][::-1].encode('hex')
        h['merkle_root'] = s[36:68][::-1].encode('hex')
        h['timestamp'] = hex_to_int(s[68:72])
        h['bits'] = hex_to_int(s[72:76])
        h['nonce'] = hex_to_int(s[76:80])
        return h

    def verify_header(self, header, prev_header, bits, target):
        prev_hash = self.hash_header(prev_header)
        if prev_hash != header.get('prev_block_hash'):
            logger.warning("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
            return False
        # if bitcoin.TESTNET or bitcoin.NOLNET: return
        if bits != header.get('bits'):
            logger.warning("bits mismatch: %s vs %s" % (bits, header.get('bits')))
            return False
        _hash = self.hash_header(header)
        if int('0x' + _hash, 16) > target:
            logger.warning("insufficient proof of work: %s vs target %s" % (int('0x' + _hash, 16), target))
            return False
        return True

    def hash_header(self, header):
        if header is None:
            return '0' * 64
        # return hash_encode(Hash(self.serialize_header(header).decode('hex')))
        return Hash(self.serialize_header_hex(header))[::-1].encode('hex')

    def serialize_header(self, res):
        s = int_to_hex(res.get('version')) \
            + reverse_hex_str(res.get('prev_block_hash')) \
            + reverse_hex_str(res.get('merkle_root')) \
            + int_to_hex(int(res.get('timestamp'))) \
            + int_to_hex(int(res.get('bits'))) \
            + int_to_hex(int(res.get('nonce')))
        return s

    def serialize_header_hex(self, res):
        s = write_uint32(res.get('version')) \
            + res.get('prev_block_hash').decode('hex')[::-1] \
            + res.get('merkle_root').decode('hex')[::-1] \
            + write_uint32(int(res.get('timestamp'))) \
            + write_uint32(int(res.get('bits'))) \
            + write_uint32(int(res.get('nonce')))
        return s

    def connect_chunk(self, idx, data):
        try:
            previous_height = idx * 2016 - 1
            if previous_height > 0 and (self.height < previous_height or self._chained_headers[
                previous_height] is None):
                for i in xrange(2016):
                    self._unchain_headers.append((idx * 2016 + i, data[i * 80:i * 80 + 80]))
                logger.debug('save chunk to unchain %d' % idx)
            else:
                # self.verify_chunk(idx, data)
                self.save_chunk(idx, data)
                logger.debug('save chunk to chain %d' % idx)
            # return idx + 1
        except BaseException as ex:
            print ex
            traceback.print_exc()
            # self.print_error('verify_chunk failed', str(e))
            # return idx - 1

    def connect_header(self, header, height=None):
        '''Builds a header chain until it connects.  Returns True if it has
        successfully connected, False if verification failed, otherwise the
        height of the next header needed.'''
        # chain.append(header)  # Ordered by decreasing height
        # header = BlockStore().deserialize_header(data)
        header['block_height'] = height
        previous_height = header['block_height'] - 1
        if self.height < previous_height or self._chained_headers[previous_height] is None:
            self._unchain_headers.append((height, self.serialize_header_hex(header)))
            logger.debug('save header to unchain %d' % height)
        else:
            # previous_header = BlockStore().read_header(previous_height)
            #
            # # Missing header, request it
            # if not previous_header:
            #     return previous_height
            #
            # # Does it connect to my chain?
            # prev_hash = BlockStore().hash_header(previous_header)
            # if prev_hash != header.get('prev_block_hash'):
            #     return previous_height
            BlockStore().save_header(header)
            logger.debug('save header to chain %d' % height)

    def verify_chunk(self, index, data):
        num = len(data) / 80
        prev_header = None
        if index != 0:
            prev_header = self.read_header(index * 2016 - 1)
        bits, target = self.get_target(index)
        for i in range(num):
            raw_header = data[i * 80:(i + 1) * 80]
            header = self.deserialize_header(raw_header)
            verified = self.verify_header(header, prev_header, bits, target)
            if not verified:
                return False
            prev_header = header
        return True

    def save_chunk(self, index, chunk):
        if index * 2016 + 2016 - len(self._chained_headers) > 0:
            self._chained_headers.extend(
                [None, ] * (index * 2016 + 2016 - len(self._chained_headers)))
        for idx in xrange(2016):
            self._chained_headers[index * 2016 + idx] = chunk[idx * 80:idx * 80 + 80]