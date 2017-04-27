# -*- coding: utf-8 -*-
import os

import sqlite3
from datetime import datetime, timedelta

from utils.base58 import double_sha256
from utils.parser import read_uint32, write_uint32

__author__ = 'zhouqi'

sqlite_path = 'data/tx.sqlite'


class BaseItem(object):
    pass


def header_dict_to_block_item(header):
    block = BlockItem()
    block.block_ver = header['version']
    block.block_prev = header['prev_block_hash']
    block.block_root = header['merkle_root']
    block.block_ver = header['timestamp']
    block.block_ver = header['bits']
    block.block_ver = header['nonce']
    block.block_no = header['block_height']
    block.block_hash = double_sha256(block.serialize())[::-1].encode('hex')
    return block

class BlockItem(BaseItem):
    block_no = -1
    block_hash = ''
    block_root = ''
    block_ver = -1
    block_bits = -1
    block_nonce = -1
    block_time = -1
    block_prev = ''
    is_main = 0

    def __init__(self, raw=None):
        if raw is not None:
            self.block_ver = read_uint32(raw[0:4])
            self.block_prev = raw[4:36][::-1].encode('hex')
            self.block_root = raw[36:68][::-1].encode('hex')
            self.block_time = read_uint32(raw[68:72])
            self.block_bits = read_uint32(raw[72:76])
            self.block_nonce = read_uint32(raw[76:80])
            self.block_hash = double_sha256(raw)[::-1].encode('hex')

    def serialize(self):
        s = write_uint32(self.block_ver) \
            + self.block_prev.decode('hex')[::-1] \
            + self.block_root.decode('hex')[::-1] \
            + write_uint32(self.block_time) \
            + write_uint32(self.block_bits) \
            + write_uint32(self.block_nonce)
        return s

class TxItem(BaseItem):
    tx_hash = ''
    tx_ver = -1
    tx_locktime = -1
    tx_time = -1
    block_no = -1
    source = -1


class InItem(BaseItem):
    tx_hash = ''
    in_sn = -1
    prev_tx_hash = ''
    prev_out_sn = -1
    in_signature = ''
    in_sequence = -1


class _outItem(BaseItem):
    tx_hash = ''
    out_sn = -1
    out_script = ''
    out_value = -1
    out_status = -1
    out_address = ''


class AddressTxItem(BaseItem):
    address = ''
    tx_hash = ''


blocks_sql = '''
CREATE TABLE IF NOT EXISTS blocks
    (block_no INTEGER NOT NULL
    , block_hash TEXT NOT NULL PRIMARY KEY
    , block_root TEXT NOT NULL
    , block_ver INTEGER NOT NULL
    , block_bits INTEGER NOT NULL
    , block_nonce INTEGER NOT NULL
    , block_time INTEGER NOT NULL
    , block_prev TEXT
    , is_main INTEGER NOT NULL);
'''

index_blocks_block_no_sql = 'CREATE INDEX idx_blocks_block_no ON blocks (block_no);'
index_blocks_block_prev_sql = 'CREATE INDEX idx_blocks_block_prev ON blocks (block_prev);'
txs_sql = '''
CREATE TABLE IF NOT EXISTS txs
    (tx_hash TEXT PRIMARY KEY
    , tx_ver INTEGER
    , tx_locktime INTEGER
    , tx_time INTEGER
    , block_no INTEGER
    , source INTEGER);
'''
index_txs_block_no_sql = 'CREATE INDEX idx_tx_block_no ON txs (block_no);'
addresses_txs_sql = '''
CREATE TABLE IF NOT EXISTS addresses_txs
    (address TEXT NOT NULL
    , tx_hash TEXT NOT NULL
    , PRIMARY KEY (address, tx_hash));
'''
ins_sql = '''
CREATE TABLE IF NOT EXISTS ins
    (tx_hash TEXT NOT NULL
    , in_sn INTEGER NOT NULL
    , prev_tx_hash TEXT
    , prev_out_sn INTEGER
    , in_signature TEXT
    , in_sequence INTEGER
    , PRIMARY KEY (tx_hash, in_sn));
'''
index_ins_prev_tx_hash_sql = 'CREATE INDEX idx_in_prev_tx_hash ON ins (prev_tx_hash);'
outs_sql = '''
CREATE TABLE IF NOT EXISTS outs
    (tx_hash TEXT NOT NULL
    , out_sn INTEGER NOT NULL
    , out_script TEXT NOT NULL
    , out_value INTEGER NOT NULL
    , out_status INTEGER NOT NULL
    , out_address TEXT
    , PRIMARY KEY (tx_hash, out_sn));
'''
index_outs_outAddress_sql = 'CREATE INDEX idx_out_out_address ON outs (out_address);'


def init():
    if not os.path.exists(sqlite_path):
        conn = sqlite3.connect(sqlite_path)
        c = conn.cursor()
        for sql in [blocks_sql, index_blocks_block_no_sql, index_blocks_block_prev_sql,
                    txs_sql, index_txs_block_no_sql,
                    addresses_txs_sql,
                    ins_sql, index_ins_prev_tx_hash_sql,
                    outs_sql, index_outs_outAddress_sql]:
            c.execute(sql)
        conn.commit()
        conn.close()


def drop():
    if os.path.exists(sqlite_path):
        os.remove(sqlite_path)


class Connection():
    @classmethod
    def gen_db(cls):
        return sqlite3.connect(sqlite_path)


def execute_one(sql, params=None):
    conn = Connection.gen_db()
    if params is None:
        res = conn.execute(sql)
    else:
        res = conn.execute(sql, params)
    return res.fetchone()


def execute_all(sql, params = None):
    conn = Connection.gen_db()
    if params is None:
        res = conn.execute(sql)
    else:
        res = conn.execute(sql, params)
    return res.fetchall()
