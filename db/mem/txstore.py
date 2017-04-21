# -*- coding: utf-8 -*-
from utils import Singleton, hash_decode, hash_encode, Hash

__author__ = 'zhouqi'

class TxStore():
    __metaclass__ = Singleton

    address_tx_dict = {}
    verified_tx_list = set([])
    unverify_tx_list = set([])
    tx_detail = {}
    unfetch_tx = set([])

    unspent_out = []
    all_ins = set([])

    def __init__(self):
        pass

    def add(self, address, tx, block_height):
        if address in self.address_tx_dict:
            self.address_tx_dict[address].append(tx)
        else:
            self.address_tx_dict[address] = [tx, ]
        if tx not in self.tx_detail:
            self.unfetch_tx.add(tx)
        if tx not in self.verified_tx_list:
            self.unverify_tx_list.add((tx, block_height))

    def verify_merkle(self, tx, merkle, header):
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
        if not header or header.get('merkle_root') != merkle_root:
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
        self.unverify_tx_list.remove(tx)
        self.verified_tx_list.add(tx)

    def add_tx_detail(self, tx_hash, tx_detail):
        self.unfetch_tx.remove(tx_hash)
        self.tx_detail[tx_hash] = tx_detail
        for idx, out in enumerate(tx_detail.outputs()):
            if (tx_hash, idx) not in self.all_ins:
                self.unspent_out.append((tx_hash, idx, out[1], out[2], out[0]))
        for idx, tx_in in enumerate(tx_detail.inputs()):
            prevout_hash = tx_in['prevout_hash']
            prevout_n = tx_in['prevout_n']
            self.unspent_out = filter(lambda x: not (x[0] == prevout_hash and x[1] == prevout_n),
                                      self.unspent_out)
            self.all_ins.add((prevout_hash, prevout_n))

    def get_unspent_out(self, address):
        return filter(lambda x: x[2] == address,self.unspent_out)

    def get_balance(self, address):
        return sum([e[3] for e in self.get_unspent_out(address)])

