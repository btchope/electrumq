# -*- coding: utf-8 -*-
import traceback

from tornado import gen

from electrumq.blockchain import logger
from electrumq.db.sqlite import header_dict_to_block_item
from electrumq.db.sqlite.block import BlockStore
from electrumq.message.all import GetChunk
from electrumq.message.all import headers_subscribe
from electrumq.message.blockchain.block import GetHeaderFile
from electrumq.network.manager import NetWorkManager
from electrumq.utils import Singleton

__author__ = 'zhouqi'

BLOCK_INTERVAL = 2016

# 块同步
class BlockChain:
    __metaclass__ = Singleton

    def __init__(self):
        pass

    def init_header(self):
        if BlockStore().height <= 0:
            NetWorkManager().add_message(GetHeaderFile([]), self.init_header_callback)
        else:
            NetWorkManager().add_message(headers_subscribe([]), callback=self.catch_up,
                                                  subscribe=self.receive_header)  # do not have id

    def init_header_callback(self, future):
        try:
            result = future.result()
            block_cnt = len(result) / 80
            for idx in xrange(block_cnt / BLOCK_INTERVAL):
                BlockStore().connect_chunk(idx, result[
                                                idx * 80 * BLOCK_INTERVAL: idx * 80 * BLOCK_INTERVAL + 80 * BLOCK_INTERVAL])
            if block_cnt > block_cnt / BLOCK_INTERVAL * BLOCK_INTERVAL:
                for idx in xrange(block_cnt - (block_cnt / BLOCK_INTERVAL * BLOCK_INTERVAL)):
                    height = block_cnt / BLOCK_INTERVAL * BLOCK_INTERVAL + idx
                    BlockStore().connect_raw_header(result[(
                                                               block_cnt / BLOCK_INTERVAL * BLOCK_INTERVAL + idx) * 80:(
                                                                                                                           block_cnt / BLOCK_INTERVAL * BLOCK_INTERVAL + idx) * 80 + 80],
                                                    height)
            NetWorkManager().add_message(headers_subscribe([]), callback=self.catch_up,
                                                  subscribe=self.receive_header)  # do not have id
        except Exception as ex:
            logger.exception(ex.message)
            traceback.print_exc()

    @gen.coroutine
    def receive_header(self, params):
        for h in params:
            block = header_dict_to_block_item(h)
            BlockStore().connect_block_item(block, h['block_height'])

    @gen.coroutine
    def catch_up(self, msg_id, msg, result):
        logger.debug('catchup %s, %s, %s' % (msg_id, msg, result))
        height = result['block_height']
        local_height = BlockStore().height
        if height > local_height:
            next_height = min(height,
                              local_height / BLOCK_INTERVAL * BLOCK_INTERVAL + BLOCK_INTERVAL - 1)
            logger.debug('catch up trunc from %d to %d' % (
                next_height / BLOCK_INTERVAL, height / BLOCK_INTERVAL))
            for h in xrange(next_height / BLOCK_INTERVAL, height / BLOCK_INTERVAL + 1):
                NetWorkManager().add_message(GetChunk([h]), self.get_trunc_callback)

    @gen.coroutine
    def get_header_callback(self, msg_id, msg, header):
        BlockStore().connect_header(header)

    @gen.coroutine
    def get_trunc_callback(self, msg_id, msg, data):
        BlockStore().connect_chunk(msg['params'][0], data.decode('hex'))

    def get_block_root(self, height):
        return BlockStore().get_block_root(height)

