# -*- coding: utf-8 -*-
__author__ = 'zhouqi'


"""

engine.py实现整个App的引擎，提供：

1. 启动network等服务（__init__）；
2. 新建钱包（new_wallet）；
3. 对当前钱包的管理（change_current_wallet）；

提供事件：

1. new_wallet_event
2. current_wallet_changed_event

"""