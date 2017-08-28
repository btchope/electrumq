# -*- coding: utf-8 -*-
__author__ = 'zhouqi'


def address_show_format(address):
    l = len(address)
    return '\n'.join([' '.join(
        [e for e in [address[i * 16 + j * 4: i * 16 + j * 4 + 4] for j in xrange(4)] if len(e) > 0])
                      for i in range(l / 16 + 1)])


if __name__ == '__main__':
    for i in xrange(1, 35):
        address = ''.join([str(j) for j in xrange(i)])
        print address
        print address_show_format(address)
        print ''