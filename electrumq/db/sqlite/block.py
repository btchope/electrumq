# -*- coding: utf-8 -*-
import logging
import traceback

from db.sqlite import execute_one, BlockItem, Connection, header_dict_to_block_item
from utils.parameter import Parameter
from utils import Singleton

__author__ = 'zhouqi'

MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

logger = logging.getLogger('blockstore')


class BlockStore():
    __metaclass__ = Singleton

    def __init__(self):
        pass

    @property
    def height(self):
        return execute_one('SELECT ifnull(max(block_no),-1) FROM blocks')[0]

    def save_block_item(self, block_item):
        sql = 'INSERT INTO blocks(block_no, block_hash, block_root, block_ver, block_bits, block_nonce, block_time, block_prev, is_main) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);'
        with Connection.gen_db() as conn:
            c = conn.cursor()
            try:
                c.execute(sql, (block_item.block_no, block_item.block_hash, block_item.block_root,
                                block_item.block_ver, block_item.block_bits, block_item.block_nonce,
                                block_item.block_time, block_item.block_prev, block_item.is_main))
            except Exception as ex:
                print ex.message
                traceback.print_exc()

    def save_block_item_batch(self, block_item_list):
        sql = 'INSERT INTO blocks(block_no, block_hash, block_root, block_ver, block_bits, block_nonce, block_time, block_prev, is_main) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);'
        with Connection.gen_db() as conn:
            c = conn.cursor()
            block_hashes = list(set([block.block_hash for block in block_item_list]))
            each_time = 999
            exist_blocks = set([])
            for i in xrange(len(block_hashes) / each_time + int(len(block_hashes) % each_time > 0)):
                seq = ','.join(['?'] * len(block_hashes[i * each_time:i * each_time + each_time]))
                exist_blocks ^= set([row[0] for row in c.execute(
                    'SELECT block_hash FROM blocks WHERE block_hash in ({seq})'.format(seq=seq),
                    block_hashes[i * each_time:i * each_time + each_time]).fetchall()])
            params = [(block.block_no, block.block_hash, block.block_root,
                       block.block_ver, block.block_bits, block.block_nonce,
                       block.block_time, block.block_prev, block.is_main) for block in
                      block_item_list if block.block_hash not in exist_blocks]
            c.executemany(sql, params)
            conn.commit()

    def get_block(self, block_no):
        b = execute_one('SELECT block_no, block_hash, block_root, block_ver, block_bits'
                        '  , block_nonce, block_time, block_prev, is_main '
                        '  FROM blocks WHERE block_no=? AND blocks.is_main=1', (block_no,))
        if b is None:
            return None
        block = BlockItem()
        block.block_no, block.block_hash, block.block_root, block.block_ver, block.block_bits \
            , block.block_nonce, block.block_time, block.block_prev, block.is_main = b
        return block

    def get_block_root(self, block_no):
        return execute_one(
            'SELECT block_root FROM blocks WHERE block_no=? AND blocks.is_main=1', (block_no,))[0]

    def get_target(self, index, chain=None):
        if index == 0:
            return 0x1d00ffff, MAX_TARGET
        first = self.get_block((index - 1) * 2016)
        last = self.get_block(index * 2016 - 1)
        if last is None:
            for h in chain:
                if h.block_no == index * 2016 - 1:
                    last = h
        assert last is not None
        # bits to target
        bits = last.block_bits
        bitsN = (bits >> 24) & 0xff
        assert bitsN >= 0x03 and bitsN <= 0x1d, "First part of bits should be in [0x03, 0x1d]"
        bitsBase = bits & 0xffffff
        assert bitsBase >= 0x8000 and bitsBase <= 0x7fffff, "Second part of bits should be in [0x8000, 0x7fffff]"
        target = bitsBase << (8 * (bitsN - 3))
        # new target
        nActualTimespan = last.block_time - first.block_time
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

    def verify_header(self, header, prev_header, bits, target):
        if prev_header is None:
            prev_hash = '0' * 64
        else:
            prev_hash = prev_header.block_hash
        if prev_hash != header.block_prev:
            logger.warning("prev hash mismatch: %s vs %s" % (prev_hash, header.block_prev))
            return False
        if Parameter().TESTNET or Parameter().NOLNET: return True
        if bits != header.block_bits:
            logger.warning("bits mismatch: %s vs %s" % (bits, header.block_bits))
            return False
        _hash = header.block_hash
        if int('0x' + _hash, 16) > target:
            logger.warning(
                "insufficient proof of work: %s vs target %s" % (int('0x' + _hash, 16), target))
            return False
        return True

    def connect_chunk(self, idx, data):
        try:
            previous_height = idx * 2016 - 1
            if previous_height > 0 \
                    and (self.height < previous_height or self.get_block(previous_height) is None):
                # todo store unchain
                logger.debug('save chunk to unchain %d' % idx)
            else:
                result = self.verify_chunk(idx, data)
                if len(result) == 2016:
                    self.save_block_item_batch(result)
                    logger.debug('save chunk to chain %d' % idx)
                else:
                    self.save_block_item_batch(result)
                    # todo store unchain
                    logger.debug('save chunk to chain %d, but length is %d' % (idx, len(result)))
        except BaseException as ex:
            print ex
            traceback.print_exc()

    def connect_raw_header(self, raw, height):
        block = BlockItem(raw)
        return self.connect_block_item(block, height)

    def connect_header(self, header):
        block = header_dict_to_block_item(header)
        return self.connect_block_item(block, block.block_no)

    def connect_block_item(self, block_item, height=None):
        '''Builds a header chain until it connects.  Returns True if it has
        successfully connected, False if verification failed, otherwise the
        height of the next header needed.'''
        # chain.append(header)  # Ordered by decreasing height
        block_item.block_no = height
        block_item.is_main = 1
        previous_height = block_item.block_no - 1
        if self.height < previous_height or self.get_block(previous_height) is None:
            # todo store unchain
            logger.debug('save header to unchain %d' % height)
        else:
            prev_block = BlockStore().get_block(previous_height)
            #
            # # Missing header, request it
            if not prev_block:
                # todo store unchain
                logger.debug('save header to unchain %d' % height)
            #
            # # Does it connect to my chain?
            prev_hash = prev_block.block_hash
            if prev_hash != block_item.block_prev:
                # todo store unchain
                logger.debug('save header to unchain %d' % height)
            BlockStore().save_block_item(block_item)
            logger.debug('save header to chain %d' % height)

    def verify_chunk(self, index, data):
        num = len(data) / 80
        # prev_header = None
        # if index != 0:
        #     prev_header = self.get_block(index * 2016 - 1)
        # bits, target = self.get_target(index)
        result = []
        for i in range(num):
            raw_header = data[i * 80:(i + 1) * 80]
            block = BlockItem(raw_header)
            block.block_no = index * 2016 + i
            verified = True  # self.verify_header(block, prev_header, bits, target)
            if not verified:
                return []
            block.is_main = 1
            prev_header = block
            result.append(block)
        return result
