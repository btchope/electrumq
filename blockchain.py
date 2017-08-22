# -*- coding: utf-8 -*-
import traceback
from datetime import datetime

import logging
from tornado import gen

# from db.mem.blockstore import BlockStore
from tornado.concurrent import Future

from db.sqlite import header_dict_to_block_item
from db.sqlite.block import BlockStore
from network import NetWorkManager
from utils import Singleton
from message.all import headers_subscribe

__author__ = 'zhouqi'

logger = logging.getLogger('blockchain')

BLOCK_INTERVAL = 2016


class BlockChain():
    __metaclass__ = Singleton

    def __init__(self):
        pass

    def init_header(self):
        if BlockStore().height <= 0:
            NetWorkManager().init_header(self.init_header_callback)
        else:
            NetWorkManager().client.add_subscribe(headers_subscribe([]), callback=self.catch_up,
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
            NetWorkManager().client.add_subscribe(headers_subscribe([]), callback=self.catch_up,
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
            from message.all import GetHeader, GetChunk
            next_height = min(height,
                              local_height / BLOCK_INTERVAL * BLOCK_INTERVAL + BLOCK_INTERVAL - 1)
            logger.debug('catch up trunc from %d to %d' % (
            next_height / BLOCK_INTERVAL, height / BLOCK_INTERVAL))
            for h in xrange(next_height / BLOCK_INTERVAL, height / BLOCK_INTERVAL + 1):
                NetWorkManager().client.add_message(GetChunk([h]), self.get_trunc_callback)

    @gen.coroutine
    def get_header_callback(self, msg_id, msg, header):
        BlockStore().connect_header(header)

    @gen.coroutine
    def get_trunc_callback(self, msg_id, msg, data):
        BlockStore().connect_chunk(msg['params'][0], data.decode('hex'))

    def get_block_root(self, height):
        return BlockStore().get_block_root(height)


class MemBlockChain(BlockChain):
    __metaclass__ = Singleton

    def init_header(self):
        NetWorkManager().init_header(self.init_header_callback)

    def init_header_callback(self, future):
        try:
            dt = datetime.now()
            result = future.result()
            cnt = len(result)
            for idx in xrange(cnt / (80 * BLOCK_INTERVAL)):
                print idx
                BlockStore().connect_chunk(idx,
                                           result[
                                           idx * 80 * BLOCK_INTERVAL: idx * 80 * BLOCK_INTERVAL + 80 * BLOCK_INTERVAL])
            if cnt > cnt / (80 * BLOCK_INTERVAL) * (80 * BLOCK_INTERVAL):
                for idx in xrange(
                                (cnt - (cnt / (80 * BLOCK_INTERVAL) * (80 * BLOCK_INTERVAL))) / 80):
                    height = cnt / (80 * BLOCK_INTERVAL) * BLOCK_INTERVAL + idx
                    header = BlockStore().deserialize_header(result[(cnt / (
                    80 * BLOCK_INTERVAL) * BLOCK_INTERVAL + idx) * 80:(cnt / (
                    80 * BLOCK_INTERVAL) * BLOCK_INTERVAL + idx) * 80 + 80])
                    BlockStore().connect_header(header, height)
                    print height
            print datetime.now() - dt
            from message.all import headers_subscribe
            NetWorkManager().client.add_subscribe(headers_subscribe([]), callback=self.catch_up,
                                                  subscribe=self.receive_header)  # do not have id
        except Exception as ex:
            print ex
            traceback.print_exc()

    @gen.coroutine
    def receive_header(self, params):
        for h in params:
            block = BlockStore().header_dict_to_block_item(h)
            BlockStore().connect_header(block, h['block_height'])

    @gen.coroutine
    def catch_up(self, msg_id, msg, result):
        print 'catchup', msg_id, msg, result
        height = result['block_height']
        local_height = BlockStore().height
        if height > local_height:
            from message.all import GetHeader, GetChunk
            next_height = min(height, local_height / BLOCK_INTERVAL * BLOCK_INTERVAL + 2015)
            # logger.debug('catch up header from %d to %d' % (local_height + 1, next_height))
            # for h in xrange(local_height + 1, next_height + 1):
            #     # pass
            #     NetWorkManager().client.add_message(GetHeader([h]), self.connect_header2)
            logger.debug('catch up trunc from %d to %d' % (
            next_height / BLOCK_INTERVAL, height / BLOCK_INTERVAL))
            for h in xrange(next_height / BLOCK_INTERVAL, height / BLOCK_INTERVAL + 1):
                NetWorkManager().client.add_message(GetChunk([h]), self.get_trunc_callback)
                # logger.debug('catch up header from %d to %d' % (height / BLOCK_INTERVAL * BLOCK_INTERVAL, height))
                # for h in xrange(height / BLOCK_INTERVAL * BLOCK_INTERVAL, height + 1):
                #     # pass
                #     NetWorkManager().client.add_message(GetHeader([h]), self.connect_header2)

    @gen.coroutine
    def get_header_callback(self, msg_id, msg, header):
        block = BlockStore().header_dict_to_block_item(header)
        BlockStore().connect_header(block, header['block_height'])

    @gen.coroutine
    def get_trunc_callback(self, msg_id, msg, data):
        BlockStore().connect_chunk(msg['params'][0], data.decode('hex'))

    # def get_header(self, height):
    #     return BlockStore().read_header(height)

    def get_block_root(self, height):
        return BlockStore().get_block_root(height)
