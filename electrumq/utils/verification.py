# -*- coding: utf-8 -*-
from electrumq.utils.base58 import b58decode, is_address
from electrumq.utils.exception import VerificationException
from electrumq.engine.engine import Engine

__author__ = 'zhouqi'


def check_address(address):
    if not is_address(address):
        raise VerificationException(u'不是合法的地址')
    if Engine().current_wallet is not None:
        if Engine().current_wallet.address == address:
            raise VerificationException(u'是本钱包的地址')


def check_amount(amount):
    try:
        int(amount)
    except Exception as ex:
        raise VerificationException(u'不是合法的金额')
    if int(amount) == 0:
        raise VerificationException(u'发送金额不能0')


if __name__ == '__main__':
    print check_address('1')