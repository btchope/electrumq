# -*- coding: utf-8 -*-
from electrumq.message import BaseMessage

__author__ = 'zhouqi'

class Subscribe(BaseMessage):
    def __init__(self, params, **kwargs):
        super(Subscribe, self).__init__(params, __name__, **kwargs)