# -*- coding: utf-8 -*-
from message import BaseMessage

__author__ = 'zhouqi'

class Subscribe(BaseMessage):
    def __init__(self, params, **kwargs):
        super(Subscribe, self).__init__(params, **kwargs)