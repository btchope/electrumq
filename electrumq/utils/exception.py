# -*- coding: utf-8 -*-
__author__ = 'zhouqi'


class VerificationException(Exception):
    def __init__(self, message, *args):
        super(VerificationException, self).__init__(*args)
        self.message = message
