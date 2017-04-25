# -*- coding: utf-8 -*-
import traceback
from datetime import datetime

import logging
from tornado import gen

# from db.mem.blockstore import BlockStore
from db.sqlite.block import BlockStore
from network import NetWorkManager
from utils import Singleton

__author__ = 'zhouqi'

logger = logging.getLogger('blockchain')

class BlockChain():

    __metaclass__ = Singleton

    def init_header(self):
        NetWorkManager().init_header(self.init_header_callback)

    def init_header_callback(self, future):
        try:
            dt = datetime.now()
            result = future.result()
            print len(result)
            for idx in xrange(len(result) / (80 * 2016)):
                print idx
                BlockStore().connect_chunk(idx, result[idx * 80 * 2016: idx * 80 * 2016 + 80 * 2016])
            if len(result) > len(result) / (80 * 2016) * (80 * 2016):
                for idx in xrange((len(result) - (len(result) / (80 * 2016) * (80 * 2016))) / 80):
                    height = len(result) / (80 * 2016) * 2016 + idx
                    # header = BlockStore().deserialize_header(result[(len(result) / (80 * 2016) * 2016 + idx) * 80:(len(result) / (80 * 2016) * 2016 + idx) * 80 + 80])
                    block_item = BlockStore().deserialize_block_item(result[(len(result) / (80 * 2016) * 2016 + idx) * 80:(len(result) / (80 * 2016) * 2016 + idx) * 80 + 80])
                    BlockStore().connect_block_item(block_item, height)
                    print height
            print datetime.now() - dt
            from message.all import headers_subscribe
            NetWorkManager().client.add_subscribe(headers_subscribe([]), callback=self.catch_up,
                                         subscribe=self.recieve_header)  # do not have id
        except Exception as ex:
            print ex
            traceback.print_exc()

    @gen.coroutine
    def recieve_header(self, params):
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
            next_height = min(height, local_height / 2016 * 2016 + 2015)
            # logger.debug('catch up header from %d to %d' % (local_height + 1, next_height))
            # for h in xrange(local_height + 1, next_height + 1):
            #     # pass
            #     NetWorkManager().client.add_message(GetHeader([h]), self.connect_header2)
            logger.debug('catch up trunc from %d to %d' % (next_height / 2016, height / 2016))
            for h in xrange(next_height / 2016, height / 2016 + 1):
                NetWorkManager().client.add_message(GetChunk([h]), self.get_trunc_callback)
            # logger.debug('catch up header from %d to %d' % (height / 2016 * 2016, height))
            # for h in xrange(height / 2016 * 2016, height + 1):
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