# -*- coding: utf-8 -*-
from electrumq.utils.base58 import b58decode, is_address
from electrumq.utils.exception import VerificationException

__author__ = 'zhouqi'


def check_address(address):
    #合法地址判断
    if not is_address(address):
        raise VerificationException(u'不是合法的地址')


def check_amount(amount):
    try:
        int(amount)
    except Exception as ex:
        raise VerificationException(u'不是合法的金额')



if __name__ == '__main__':
    print check_address('1')