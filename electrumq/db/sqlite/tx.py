# -*- coding: utf-8 -*-
from db.sqlite import Connection, execute_all, execute_one
from utils import Singleton
from utils.base58 import Hash

__author__ = 'zhouqi'

class TxStore():
    __metaclass__ = Singleton

    def __init__(self):
        pass

    @property
    def unverify_tx_list(self):
        return set(execute_all('select tx_hash,block_no from txs WHERE source=0'))

    @property
    def unfetch_tx(self):
        return set([e[0] for e in execute_all('SELECT tx_hash FROM txs WHERE tx_ver IS NULL ')])

    def add(self, address, tx, block_height):
        with Connection.gen_db() as conn:
            c = conn.cursor()
            if c.execute('select count(0) from txs WHERE tx_hash=?', (tx,)).fetchone()[0] == 0:
                block_time = None#c.execute('select block_time from blocks WHERE block_no=?', (block_height,)).fetchone()[0]
                c.execute('insert into txs(tx_hash, block_no, tx_time, source) VALUES (?, ?, ?, ?)', (tx, block_height, block_time, 0))
            if c.execute('select count(0) from addresses_txs WHERE tx_hash=? and address=?', (tx, address)).fetchone()[0] == 0:
                c.execute('insert into addresses_txs(tx_hash, address) VALUES (?, ?)', (tx, address))

    def verify_merkle(self, tx, merkle, block_root):
        # Verify the hash of the server-provided merkle branch to a
        # transaction matches the merkle root of its block
        tx_hash = tx
        tx_height = merkle.get('block_height')
        pos = merkle.get('pos')
        merkle_root = self.hash_merkle_root(merkle['merkle'], tx_hash, pos)
        # header = self.network.get_header(tx_height)
        if not block_root or block_root != merkle_root:
            # FIXME: we should make a fresh connection to a server to
            # recover from this, as this TX will now never verify
            # self.print_error("merkle verification failed for", tx_hash)
            return False
        return True


    def hash_merkle_root(self, merkle_s, target_hash, pos):
        h = target_hash.decode('hex')[::-1]
        for i in range(len(merkle_s)):
            item = merkle_s[i]
            h = Hash( item.decode('hex')[::-1] + h ) if ((pos >> i) & 1) else Hash( h + item.decode('hex')[::-1] )
        return h[::-1].encode('hex')


    def undo_verifications(self, height):
        # todo:
        pass
        # tx_hashes = self.wallet.undo_verifications(height)
        # for tx_hash in tx_hashes:
        #     self.print_error("redoing", tx_hash)
        #     self.merkle_roots.pop(tx_hash, None)


    def verified_tx(self, tx):
        with Connection.gen_db() as conn:
            c = conn.cursor()
            c.execute('UPDATE txs SET source=1 WHERE tx_hash=?', (tx,))

    def add_tx_detail(self, tx_hash, tx_detail):
        with Connection.gen_db() as conn:
            c = conn.cursor()
            c.execute('UPDATE txs SET tx_ver=?,tx_locktime=? WHERE tx_hash=?',
                      (tx_detail.tx_ver, tx_detail.locktime, tx_hash))
            for idx, out in enumerate(tx_detail.outputs()):
                spent = c.execute('select count(0) from ins WHERE prev_tx_hash=? and prev_out_sn=?', (tx_hash, idx)).fetchone()[0]
                c.execute('insert into outs(tx_hash, out_sn, out_script, out_value, out_status, out_address) VALUES (?, ?, ?, ?, ?, ?)', (tx_hash, idx, out[3], out[2], spent, out[1]))
            for idx, tx_in in enumerate(tx_detail.inputs()):
                prevout_hash = tx_in['prevout_hash']
                prevout_n = tx_in['prevout_n']
                in_signature = tx_in['scriptSig']
                in_sequence = tx_in['sequence']
                c.execute('insert into ins(tx_hash, in_sn, prev_tx_hash, prev_out_sn, in_signature, in_sequence) VALUES (?, ?, ?, ?, ?, ?)', (tx_hash, idx, prevout_hash, prevout_n, in_signature, in_sequence))
                c.execute('update outs set out_status=1 WHERE tx_hash=? and out_sn=?', (prevout_hash, prevout_n))


    def get_balance(self, address):
        return execute_one('select ifnull(sum(out_value),0) from outs WHERE out_status=0 AND out_address=?', (address,))[0]

    def get_unspend_outs(self, address):
        res = execute_all('select a.tx_hash,a.out_sn,a.out_script,a.out_value,a.out_address,b.block_no'
                          '  from outs a, txs b'
                          '  WHERE a.tx_hash=b.tx_hash'
                          '    and a.out_status=0 and a.out_address=?', (address,))
        return res

    def get_max_tx_block(self, address):
        return execute_one(
            'SELECT ifnull(max(a.block_no),-1) FROM txs a, addresses_txs b WHERE b.address=? AND a.tx_hash=b.tx_hash',
            (address,))[0]

    def get_txs(self, address):
        return execute_all("SELECT b.tx_hash, ifnull(b.tx_time, strftime('%s', 'now')) tx_time FROM addresses_txs a,txs b WHERE a.address=? and a.tx_hash=b.tx_hash", (address,))

    def get_all_txs(self, addresses):
        seq = ','.join(['?']*len(addresses))
        sql = "SELECT b.tx_hash, ifnull(b.tx_time, strftime('%s', 'now')) tx_time " \
              "  FROM addresses_txs a,txs b " \
              "  WHERE a.tx_hash=b.tx_hash and a.address in ({seq}) ".format(seq=seq)
        return execute_all(sql, addresses)

    def get_all_tx_spent(self, addresses):
        seq = ','.join(['?'] * len(addresses))
        sql = 'SELECT b.tx_hash,sum(a.out_value) spent' \
              '  FROM outs a, ins b ' \
              '  WHERE a.tx_hash=b.prev_tx_hash and a.out_sn=b.prev_out_sn and a.out_address IN ({seq}) ' \
              '  GROUP BY a.tx_hash'.format(seq=seq)
        return execute_all(sql, addresses)

    def get_all_tx_receive(self, addresses):
        seq = ','.join(['?'] * len(addresses))
        sql = 'SELECT a.tx_hash,sum(a.out_value) receive' \
              '  FROM outs a ' \
              '  WHERE a.out_address IN ({seq}) GROUP BY a.tx_hash'.format(seq=seq)
        return execute_all(sql, addresses)
