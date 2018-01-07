# -*- coding: utf-8 -*-
from electrumq.message.base import BaseMessage

__author__ = 'zhouqi'

class Version(BaseMessage):
    def __init__(self, params, **kwargs):
        super(Version, self).__init__(params, __name__, **kwargs)


class Banner(BaseMessage):
    def __init__(self, params, **kwargs):
        super(Banner, self).__init__(params, __name__, **kwargs)


class DonationAddress(BaseMessage):
    def __init__(self, params, **kwargs):
        super(DonationAddress, self).__init__(params, __name__, **kwargs)