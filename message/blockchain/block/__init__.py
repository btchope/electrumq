# -*- coding: utf-8 -*-
from message import BaseMessage

__author__ = 'zhouqi'

class GetHeader(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetHeader, self).__init__(params, **kwargs)

class GetChunk(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetChunk, self).__init__(params, **kwargs)
