# -*- coding: utf-8 -*-
import json
import logging
import sys
from collections import deque

from tornado import gen
from tornado.concurrent import Future, is_future
from tornado.ioloop import PeriodicCallback
from tornado.iostream import StreamClosedError
from tornado.tcpclient import TCPClient

from electrumq.net import logger

__author__ = 'zhouqi'


class RPCClient:
    ip, port = '176.9.108.141', 50001
    stream = None
    is_connected = False
    sequence = xrange(sys.maxint).__iter__()
    _message_list = deque()
    _sent_dict = {}
    _response_list = deque()
    _subscribe_list = deque()
    _callback_dict = {}
    _subscribe_dict = {}
    ioloop = None
    connect_future = None
    connect_timeout = 0.5
    connect_retry_time = 0
    logger = logging.getLogger('rpcclient')

    timeout = None

    def __init__(self, ioloop, ip=None, port=None):
        if ip is not None:
            self.ip = ip
        if port is not None:
            self.port = port
        self.ioloop = ioloop

    def __del__(self):
        if self.stream is not None:
            self.stream.close()

    def connect_with_future(self):
        self.connect_future = Future()
        self.ioloop.add_future(TCPClient().connect(self.ip, self.port), self.connect_callback)
        self.set_timout(timeout=3)
        return self.connect_future

    def connect_callback(self, future):
        if not future.done():
            return
        if future.exception() is None:
            self.stream = future.result()
            self.is_connected = True
            logger.debug('client connected by callback')
            try:
                self.stream.read_until(b"\n", callback=self.parse_response)
            except Exception as ex:
                logger.debug(ex.message)
            self.ioloop.add_periodic(self.send_all)
            self.ioloop.add_periodic(self.callback)
            self.ioloop.add_periodic(self.subscribe)
            if self.connect_future._callbacks is None:
                self.connect_future._callbacks = []
            self.connect_future.set_result(True)
        else:
            print future.exception()
            if self.connect_retry_time > 0:
                self.connect_retry_time -= 1
                self.ioloop.add_future(TCPClient().connect(self.ip, self.port),
                                       self.connect_callback)
                self.set_timout(timeout=3)
            else:
                self.connect_future.set_result(False)

    def set_timout(self, timeout):
        self.timeout = self.ioloop.add_timeout(self.ioloop.time() + timeout,
                                               self.on_timeout)

    def on_timeout(self):
        self.timeout = None
        if self.connect_future is not None and not self.connect_future.done():
            self.connect_future.set_result(False)
            # self.connect_future.set_exception(Exception())

    def clear_timeout(self):
        if self.timeout is not None:
            self.ioloop.remove_timeout(self.timeout)

    @gen.coroutine
    def connect(self):
        try:
            self.stream = yield TCPClient().connect(self.ip, self.port)
            self.is_connected = True
            self.stream.read_until(b"\n", callback=self.parse_response)
            logger.debug('client connected')
            self.ioloop.add_periodic(self.send_all)
            self.ioloop.add_periodic(self.callback)
            self.ioloop.add_periodic(self.subscribe)
        except StreamClosedError as ex:
            self.is_connected = False
        except Exception as ex:
            print ex
            self.is_connected = False

    @gen.coroutine
    def send_all(self):
        if self.is_connected:
            if len(self._message_list) > 0:
                self.logger.debug('begin to send all')
                content = ''
                while len(self._message_list) > 0:
                    msg = self._message_list.popleft()
                    content += json.dumps(msg).replace(' ', '') + '\n'
                    self._sent_dict[msg.pop('id')] = msg
                self.logger.debug('send:' + content)
                self.stream.write(content)

    @gen.coroutine
    def callback(self):
        if len(self._response_list) > 0:
            self.logger.debug('begin to callback all')
            msg_id, msg, result = self._response_list.popleft()
            self.logger.debug(str((msg_id, msg, result)))
            if msg_id in self._callback_dict:
                func = self._callback_dict.pop(msg_id)
                try:
                    feature = func(msg_id, msg, result)
                    if not is_future(feature):
                        raise Exception('callback must be a feature')
                    self.ioloop.add_future(feature)
                except Exception as ex:
                    self.logger.exception(ex.message)

    @gen.coroutine
    def subscribe(self):
        if len(self._subscribe_list):
            method, params = self._subscribe_list.popleft()
            self.logger.debug(str((method, params)))
            if method in self._subscribe_dict:
                funcs = self._subscribe_dict[method]
                for func in funcs:
                    try:
                        feature = func(params)
                        if not is_future(feature):
                            raise Exception('callback must be a feature')
                        self.ioloop.add_future(feature)
                    except Exception as ex:
                        self.logger.exception(ex.message)

    def parse_response(self, content):
        try:
            j = json.loads(content)
            if 'error' in j:
                raise Exception(j['error'])
            elif 'method' in j:
                if 'jsonrpc' in j:
                    j.pop('jsonrpc')
                self.logger.debug('subscribe:' + json.dumps(j).replace(' ', ''))
                self._subscribe_list.append((j['method'], j['params']))
            else:
                if 'jsonrpc' in j:
                    j.pop('jsonrpc')
                self.logger.debug('receive:' + json.dumps(j).replace(' ', ''))
                print j['id'], 'sent result has received'
                self._response_list.append((j['id'], self._sent_dict.pop(j['id']), j['result']))
        except Exception as ex:
            self.logger.exception('error message:' + content)
        self.stream.read_until(b"\n", callback=self.parse_response)

    def add_message(self, message, callback=None):
        message["id"] = self.sequence.next()
        if callback is not None:
            self._callback_dict[message['id']] = callback
        self._message_list.append(message)

    def add_subscribe(self, message, callback=None, subscribe=None):
        message["id"] = self.sequence.next()
        if callback is not None:
            self._callback_dict[message['id']] = callback
        if subscribe is not None:
            method = message['method']
            if method in self._subscribe_dict:
                self._subscribe_dict[method].append(subscribe)
            else:
                self._subscribe_dict[method] = [subscribe, ]
        self._message_list.append(message)
