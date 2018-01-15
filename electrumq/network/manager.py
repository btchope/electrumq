# -*- coding: utf-8 -*-
import json
import logging
import random
import signal
import socket

import tornado
from tornado import gen
from tornado.httpclient import AsyncHTTPClient

from electrumq.message.blockchain.block import GetHeaderFile
from electrumq.network.ioloop import IOLoop
from electrumq.message.server import Version
from electrumq.network import logger
from electrumq.network.client import RPCClient
from electrumq.utils import Singleton
from electrumq.utils.parameter import Parameter

__author__ = 'zhouqi'


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

    """
    interface for application:
    network.start()
    network.status
    """

    def start(self):
        """

        :return:
        """
        self.start_ioloop()
        self.start_client()

    status = {}

    """
    interface for engine
    network.add_message(message, callback)
    """

    def add_message(self, message, callback=None, subscribe=None):
        if message.__class__ is GetHeaderFile:
            self.ioloop.add_future(self.init(), callback)
        else:
            self.client.add_message(message, callback=callback, subscribe=subscribe)

    def http_request(self, url, method='GET', param=None, callback=None):
        """
        异步执行请求
        :rtype: None
        """
        self.ioloop.add_future(self._do_http_request(url, method, param), callback)

    @gen.coroutine
    def _do_http_request(self, url, method, param=None):
        retry = 5
        while retry > 0:
            try:
                # if param is not None:
                request = tornado.httpclient.HTTPRequest(url=url, method=method,
                                                         # body=json.dumps(param),
                                                         connect_timeout=20.0,
                                                         request_timeout=60 * 10)
                response = yield tornado.gen.Task(AsyncHTTPClient().fetch, request)
            except Exception as ex:
                print ex.message
                retry -= 1
            else:
                raise gen.Return(response.body)

    """
    inner method
    """

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

    def start_client(self):
        ip, port = self.get_server()
        self.client = RPCClient(ioloop=self.ioloop, ip=ip, port=port)

        def connect_callback(future):
            if not self.client.is_connected:
                logger.debug('connect failed and retry')
                self.client = None
                self.start_client()
            else:
                self.client.add_message(
                    Version([Parameter().ELECTRUM_VERSION, Parameter().PROTOCOL_VERSION]))

        self.ioloop.add_future(self.client.connect_with_future(), connect_callback)

    """
    dns
    
    """

    def get_server(self):
        ip, port, _ = self.deserialize_server(self.pick_random_server())
        port = int(port)
        logger.debug('begin to connect to %s %d' % (ip, port))
        try:
            l = socket.getaddrinfo(ip, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ip, port = l[0][-1]
        except socket.gaierror:
            logger.debug('cannot resolve hostname')
        return ip, port

    def filter_protocol(self, hostmap, protocol='s'):
        """
        Filters the hostmap for those implementing protocol.
        The result is a list in serialized form.
        """
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
                request = tornado.httpclient.HTTPRequest(url=Parameter().HEADERS_URL,
                                                         connect_timeout=20.0,
                                                         request_timeout=60 * 10)
                response = yield tornado.gen.Task(AsyncHTTPClient().fetch, request)
                #
                # response = yield AsyncHTTPClient().fetch(Parameter().HEADERS_URL)
            except Exception as ex:
                print ex.message
                retry -= 1
            else:
                raise gen.Return(response.body)
