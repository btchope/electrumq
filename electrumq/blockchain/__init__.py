# -*- coding: utf-8 -*-
import logging

__author__ = 'zhouqi'

logger = logging.getLogger('blockchain')

"""


chain.py实现块同步和验证的逻辑，包括：

1. 同步（init_header）；
2. 验证（目前在sqlite/block.py里，后续需要review）

"""