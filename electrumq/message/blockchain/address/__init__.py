# -*- coding: utf-8 -*-
from electrumq.message import BaseMessage

__author__ = 'zhouqi'


class Subscribe(BaseMessage):
    def __init__(self, params, **kwargs):
        super(Subscribe, self).__init__(params, __name__, **kwargs)

class GetHistory(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetHistory, self).__init__(params, __name__, **kwargs)


class GetMempool(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetMempool, self).__init__(params, __name__, **kwargs)

class GetBalance(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetBalance, self).__init__(params, __name__, **kwargs)

class GetProof(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetProof, self).__init__(params, __name__, **kwargs)

class Listunspent(BaseMessage):
    def __init__(self, params, **kwargs):
        super(Listunspent, self).__init__(params, __name__, **kwargs)