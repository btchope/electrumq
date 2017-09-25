# -*- coding: utf-8 -*-
import json
import random
import socket
from collections import deque

import time

import signal

import logging
from logging.config import dictConfig

import sys
import tornado
from tornado import gen
from tornado.concurrent import is_future, Future
from tornado.httpclient import AsyncHTTPClient
from tornado.iostream import StreamClosedError
from tornado.tcpclient import TCPClient

from electrumq.ioloop import IOLoop
from electrumq.message.server import Version
from electrumq.utils import Singleton
from electrumq.utils.parameter import Parameter

__author__ = 'zhouqi'

# logging.config.fileConfig('logging.conf')
logger = logging.getLogger('rpcclient')


class NetWorkManager:
    """
    1. start/stop ioloop
    2. collect client
    3. regist notify
    """
    __metaclass__ = Singleton

    ioloop = None
    client = None

    def __init__(self):
        signal.signal(signal.SIGTERM, self.sig_handler)
        signal.signal(signal.SIGINT, self.sig_handler)

    def start(self):
        self.start_ioloop()
        self.start_client()

    def start_ioloop(self):
        if self.ioloop is None:
            self.ioloop = IOLoop()
        self.ioloop.start()

    def sig_handler(self, sig, frame):
        logging.warning('Caught signal: %s', sig)
        self.quit()

    def quit(self):
        if self.ioloop is not None:
            self.ioloop.quit()
            self.ioloop = None

    def start_client(self, ip=None, port=None):
        ip, port, _ = self.deserialize_server(self.pick_random_server())
        port = int(port)
        logger.debug('begin to connect to %s %d' % (ip, port))
        try:
            l = socket.getaddrinfo(ip, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ip, port = l[0][-1]
        except socket.gaierror:
            logger.debug('cannot resolve hostname')
        # ip, port = '176.9.108.141', 50001
        self.client = RPCClient(ioloop=self.ioloop, ip=ip, port=port)
        self.ioloop.add_future(self.client.connect2(), self.connect_callback)

    def connect_callback(self, feature):
        if not self.client.is_connected:
            logger.debug('connect failed and retry')
            self.client = None
            self.start_client()
        else:
            self.client.add_message(
                Version([Parameter().ELECTRUM_VERSION, Parameter().PROTOCOL_VERSION]))

    def filter_protocol(self, hostmap, protocol='s'):
        '''Filters the hostmap for those implementing protocol.
        The result is a list in serialized form.'''
        eligible = []
        for host, portmap in hostmap.items():
            port = portmap.get(protocol)
            if port:
                eligible.append(self.serialize_server(host, port, protocol))
        return eligible

    def pick_random_server(self, hostmap=None, protocol='t', exclude_set=set()):
        if hostmap is None:
            hostmap = Parameter().DEFAULT_SERVERS
        eligible = list(set(self.filter_protocol(hostmap, protocol)) - exclude_set)
        return random.choice(eligible) if eligible else None

    def serialize_server(self, host, port, protocol):
        return str(':'.join([host, port, protocol]))

    def deserialize_server(self, server_str):
        host, port, protocol = str(server_str).split(':')
        assert protocol in 'st'
        int(port)  # Throw if cannot be converted to int
        return host, port, protocol

    def init_header(self, callback=None):
        self.ioloop.add_future(self.init(), callback)

    @gen.coroutine
    def init(self):
        retry = 5
        while retry > 0:
            try:
                request = tornado.httpclient.HTTPRequest(url=Parameter().HEADERS_URL, connect_timeout=20.0,
                                                         request_timeout=60*10)
                response = yield tornado.gen.Task(AsyncHTTPClient().fetch, request)
                #
                # response = yield AsyncHTTPClient().fetch(Parameter().HEADERS_URL)
            except Exception as ex:
                print ex.message
                retry -= 1
            else:
                raise gen.Return(response.body)


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
    f = None
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

    def connect2(self):
        self.try_connect()
        return self.connect_future

    def try_connect(self):
        self.connect_future = Future()
        print 'ip & port', self.ip, self.port
        self.ioloop.add_future(TCPClient().connect(self.ip, self.port), self.connect_callback)
        # self.set_timout(timeout=1)

    def connect_callback(self, future):
        if future.exception() is None:
            self.stream = future.result()
            self.is_connected = True
            self.stream.read_until(b"\n", callback=self.parse_response)
            logger.debug('client connected')
            self.ioloop.add_periodic(self.send_all)
            self.ioloop.add_periodic(self.callback)
            self.ioloop.add_periodic(self.subscribe)
            self.connect_future.set_result(True)
        else:
            print future.exception()
            if self.connect_retry_time > 0:
                self.connect_retry_time -= 1
                self.try_connect()
            else:
                self.connect_future.set_result(False)

    def set_timout(self, timeout):
        print 'set timeout'
        self.timeout = self.ioloop.add_timeout(self.ioloop.time() + timeout,
                                                self.on_timeout)

    def on_timeout(self):
        print 'triger timeout'
        self.timeout = None
        if self.connect_future is not None and not self.connect_future.done():
            self.connect_future.set_result(False)
            self.f.set_exception(Exception())

    def clear_timeout(self):
        if self.timeout is not None:
            self.ioloop.remove_timeout(self.timeout)

    @gen.coroutine
    def connect(self):
        try:
            self.port += 1
            from datetime import datetime
            d = datetime.now()
            self.stream = yield TCPClient().connect(self.ip, self.port)
            print 'stream' + str(datetime.now() - d)
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
            # raise ex

    @gen.coroutine
    def send_all(self):
        if self.is_connected:
            if len(self._message_list) > 0:
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





