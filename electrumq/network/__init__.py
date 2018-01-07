# -*- coding: utf-8 -*-
import logging

__author__ = 'zhouqi'

logger = logging.getLogger('network')

"""

与electrum节点的通信的封装。


network模块外部：

1. 对于engine需要调用

NetWorkManager().start()

2. 对于其他network外部的模块只需要调用

NetWorkManager().add_message(message, callback)
或者
NetWorkManager().add_message(message, subscribe)


network模块内部：

ioloop.py是一个线程，里面封装了一个Tornado IOLoop，如果升级到py3也可以用py3自带的ioloop以减少对于tornado依赖。
client.py是一个异步electrum client，利用ioloop.py来与electrum节点通信。
manager.py将维护 ioloop 和 client，监控二者的状态（未做）。


"""