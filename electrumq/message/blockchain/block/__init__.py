# -*- coding: utf-8 -*-
from electrumq.message.base import BaseMessage

__author__ = 'zhouqi'


class GetHeader(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetHeader, self).__init__(params, __name__, **kwargs)


class GetChunk(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetChunk, self).__init__(params, __name__, **kwargs)


class GetHeaderFile(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetHeaderFile, self).__init__(params, __name__, **kwargs)
