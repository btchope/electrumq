# -*- coding: utf-8 -*-
import os

from appdirs import AppDirs

__author__ = 'zhouqi'

dirs = AppDirs("ElectrumQ", "zhouqi", version="pre1.0")


def _mkdir_recursive(path):
    sub_path = os.path.dirname(path)
    if not os.path.exists(sub_path):
        _mkdir_recursive(sub_path)
    if not os.path.exists(path):
        os.mkdir(path)


if not os.path.exists(dirs.user_data_dir):
    _mkdir_recursive(dirs.user_data_dir)

conf_path = dirs.user_data_dir + '/electrumq.conf'
log_conf_path = dirs.user_data_dir + '/logging.conf'
sqlite_path = dirs.user_data_dir + '/tx.sqlite'
style_path = dirs.user_data_dir + '/main.style'


def init_configuration():
    if not os.path.exists(conf_path):
        f = open(conf_path, 'w')
        f.write('[wallet]')
        f.close()

    if not os.path.exists(log_conf_path):
        f = open(log_conf_path, 'w')
        f.write(log_conf_content)
        f.close()


log_conf_content = '''
[loggers]
keys=root,simpleExample,network,blockchain,blockstore,rpcclient

[handlers]
keys=consoleHandler

[formatters]
keys=simpleFormatter

[logger_root]
level=DEBUG
handlers=consoleHandler

[logger_network]
level=DEBUG
handlers=consoleHandler
qualname=network
propagate=0

[logger_rpcclient]
level=DEBUG
handlers=consoleHandler
qualname=rpcclient
propagate=0

[logger_blockchain]
level=DEBUG
handlers=consoleHandler
qualname=blockchain
propagate=0

[logger_blockstore]
level=DEBUG
handlers=consoleHandler
qualname=blockstore
propagate=0

[logger_simpleExample]
level=DEBUG
handlers=consoleHandler
qualname=simpleExample
propagate=0

[handler_consoleHandler]
class=StreamHandler
level=DEBUG
formatter=simpleFormatter
args=(sys.stdout,)

[formatter_simpleFormatter]
format=%(asctime)s %(name)s %(levelname)s %(message)s
datefmt=

'''

init_configuration()
