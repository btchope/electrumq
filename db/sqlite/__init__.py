# -*- coding: utf-8 -*-
import os

import sqlite3

__author__ = 'zhouqi'

sqlite_path = 'data/tx.sqlite'

class BaseItem(object):
    pass

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
create table if not exists blocks
    (block_no integer not null
    , block_hash text not null primary key
    , block_root text not null
    , block_ver integer not null
    , block_bits integer not null
    , block_nonce integer not null
    , block_time integer not null
    , block_prev text
    , is_main integer not null);
'''

index_blocks_block_no_sql = 'create index idx_blocks_block_no on blocks (block_no);'
index_blocks_block_prev_sql = 'create index idx_blocks_block_prev on blocks (block_prev);'
txs_sql = '''
create table if not exists txs 
    (tx_hash text primary key
    , tx_ver integer
    , tx_locktime integer
    , tx_time integer
    , block_no integer
    , source integer);
'''
index_txs_block_no_sql = 'create index idx_tx_block_no on txs (block_no);'
addresses_txs_sql = '''
create table if not exists addresses_txs
    (address text not null
    , tx_hash text not null
    , primary key (address, tx_hash));
'''
ins_sql = '''
create table if not exists ins
    (tx_hash text not null
    , in_sn integer not null
    , prev_tx_hash text
    , prev_out_sn integer
    , in_signature text
    , in_sequence integer
    , primary key (tx_hash, in_sn));
'''
index_ins_prev_tx_hash_sql = 'create index idx_in_prev_tx_hash on ins (prev_tx_hash);'
outs_sql = '''
create table if not exists outs
    (tx_hash text not null
    , out_sn integer not null
    , out_script text not null
    , out_value integer not null
    , out_status integer not null
    , out_address text
    , primary key (tx_hash, out_sn));
'''
index_outs_outAddress_sql = 'create index idx_out_out_address on outs (out_address);'

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