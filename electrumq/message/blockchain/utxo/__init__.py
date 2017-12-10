# -*- coding: utf-8 -*-
from electrumq.message.base import BaseMessage

__author__ = 'zhouqi'


class GetAddress(BaseMessage):
    def __init__(self, params, **kwargs):
        super(GetAddress, self).__init__(params, __name__, **kwargs)
