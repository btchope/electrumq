# -*- coding: utf-8 -*-
from db.sqlite import Connection, execute_all, execute_one
from utils import Singleton, hash_decode, hash_encode
from utils.base58 import Hash

__author__ = 'zhouqi'

class TxStore():
    __metaclass__ = Singleton

    # address_tx_dict = {}
    # verified_tx_list = set([])
    # unverify_tx_list = set([])
    # tx_detail = {}
    # unfetch_tx = set([])

    # unspent_out = []
    # all_ins = set([])

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
                c.execute('insert into txs(tx_hash, block_no, source) VALUES (?, ?, ?)', (tx, block_height, 0))
            if c.execute('select count(0) from addresses_txs WHERE tx_hash=? and address=?', (tx, address)).fetchone()[0] == 0:
                c.execute('insert into addresses_txs(tx_hash, address) VALUES (?, ?)', (tx, address))
        # if address in self.address_tx_dict:
        #     self.address_tx_dict[address].append(tx)
        # else:
        #     self.address_tx_dict[address] = [tx, ]
        # if tx not in self.tx_detail:
        #     self.unfetch_tx.add(tx)
        # if tx not in self.verified_tx_list:
        #     self.unverify_tx_list.add((tx, block_height))

    def verify_merkle(self, tx, merkle, block_root):
        # if r.get('error'):
        #     # self.print_error('received an error:', r)
        #     return

        # params = r['params']
        # merkle = r['result']

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

        # # we passed all the tests
        # self.merkle_roots[tx_hash] = merkle_root
        # self.print_error("verified %s" % tx_hash)
        # self.wallet.add_verified_tx(tx_hash, (tx_height, header.get('timestamp'), pos))
        return True


    def hash_merkle_root(self, merkle_s, target_hash, pos):
        h = hash_decode(target_hash)
        for i in range(len(merkle_s)):
            item = merkle_s[i]
            h = Hash( hash_decode(item) + h ) if ((pos >> i) & 1) else Hash( h + hash_decode(item) )
        return hash_encode(h)


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
        # self.unverify_tx_list.remove(tx)
        # self.verified_tx_list.add(tx)

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
        return execute_one('select ifnull(sum(out_value),0) from outs WHERE out_status=0 AND out_address=?', address)[0]
