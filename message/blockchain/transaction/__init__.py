# -*- coding: utf-8 -*-
from message import BaseMessage

__author__ = 'zhouqi'


class Broadcast(BaseMessage):
    def __init__(self, params, **kwargs):
        super(Broadcast, self).__init__(params, __name__, **kwargs)


class GetMerkle(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetMerkle, self).__init__(params, __name__, **kwargs)


class Get(BaseMessage):
    def __init__(self, params, **kwargs):
        super(Get, self).__init__(params, __name__, **kwargs)
