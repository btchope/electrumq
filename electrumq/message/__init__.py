# -*- coding: utf-8 -*-
import inspect

__author__ = 'zhouqi'


def camel_to_underline(camel_format):
    underline_format = camel_format[0].lower()
    if isinstance(camel_format, str):
        for each in camel_format[1:]:
            underline_format += each if each.islower() or each == '_' else '_' + each.lower()
    return underline_format


def underline_to_camel(underline_format):
    camel_format = ''
    if isinstance(underline_format, str):
        for each in underline_format.split('_'):
            camel_format += each.capitalize()
    return camel_format


class BaseMessage(dict):
    __is_subscribe = False
    __method = None

    def __init__(self, params, name, **kwargs):
        super(BaseMessage, self).__init__(**kwargs)
        if self.__class__.__method is None:
            self.__class__.__method = name[18:] + '.' \
                                      + camel_to_underline(self.__class__.__name__)
            self.__class__.__is_subscribe = self.__class__.__method.endswith('subscribe')
        self["params"] = params
        self['method'] = self.__class__.__method

    def is_subscribe(self):
        return self.__class__.__is_subscribe
