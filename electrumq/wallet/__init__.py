# -*- coding: utf-8 -*-

__author__ = 'zhouqi'


"""

实现各自模式的钱包，提供：

1. 同步交易（查看 sync 方法）；
2. 查询交易（查看 get_txs 方法）；
3. 生成未签名交易（查看 make_unsigned_transaction 方法）；
4. 签名交易（查看 sign_transaction 方法）；
5. 广播交易（查看 broadcast 方法）；

base.py 里包含了基本功能的实现，其他各类型的钱包应当根据自己逻辑去继承、重写对应的方法。

计划支持：

单地址钱包 single.py
hd钱包 hd.py
冷热钱包 coldhot.py


"""