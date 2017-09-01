# -*- coding: utf-8 -*-
from message import BaseMessage

__author__ = 'zhouqi'


class Estimatefee(BaseMessage):
    def __init__(self, params, **kwargs):
        super(Estimatefee, self).__init__(params, __name__, **kwargs)
