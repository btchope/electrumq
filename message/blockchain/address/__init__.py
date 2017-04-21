# -*- coding: utf-8 -*-
from message import BaseMessage

__author__ = 'zhouqi'


class Subscribe(BaseMessage):
    def __init__(self, params, **kwargs):
        super(Subscribe, self).__init__(params, **kwargs)

class GetHistory(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetHistory, self).__init__(params, **kwargs)


class GetMempool(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetMempool, self).__init__(params, **kwargs)

class GetBalance(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetBalance, self).__init__(params, **kwargs)

class GetProof(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetProof, self).__init__(params, **kwargs)

class Listunspent(BaseMessage):
    def __init__(self, params, **kwargs):
        super(Listunspent, self).__init__(params, **kwargs)