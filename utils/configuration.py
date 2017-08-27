# -*- coding: utf-8 -*-
import os

from appdirs import AppDirs

__author__ = 'zhouqi'

dirs = AppDirs("ElectrumQ", "zhouqi", version="pre1.0")

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

    if not os.path.exists(style_path):
        f = open(style_path, 'w')
        f.write(style_content)
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

style_content = '''

QWidget {
    /* background-color: gray; */
}

/* account controller */
.accountIcon {
    background-color: black;
}

.addAccount {
    background-color: red;
}


/* nav controller */
MainAddressView {
    background-color: black;
}

MainAddressView > QTextEdit {
    background-color: red;
}

MainAddressView > QPushButton {
    background-color: red;
}

.balanceDesc {
    background-color: red;
}

.balanceAmt {
    background-color: red;
}

.balanceUnit {
    background-color: red;
}

.navFunc {
    background-color: red;
}

.navFunc:checked {
    background-color: black;
}

/* tx table controller*/
TxFilterView {
    background-color: black;
    max-height: 50;
    min-height: 50;
}

TxTableView {
    background-color: red;
}

/* receive */
AddressView {
    background-color: black;
}

AddressView > QTextEdit{
    background-color: black;
}

AddressView > QTextEdit{
    background-color: black;
}

.bigQRCode {
    background-color: red;
}

'''

init_configuration()
