# -*- coding: utf-8 -*-
import os

from appdirs import AppDirs

__author__ = 'zhouqi'

dirs = AppDirs("ElectrumQ", "zhouqi", version="pre1.0")

if not os.path.exists(dirs.user_data_dir):
    os.mkdir(dirs.user_data_dir)

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
    background-color: gray;
    padding:0px;
}

/* account controller */
AccountController > QWidget {
    background-color: #2f2e30;
}

.accountIcon {
    background-color: #2f2e30;
    color: white;
    max-width:120;
    min-width:120;

    border-style: none;
}

.accountIcon:checked {
    background-color: #2f2e30;
    color: white;
    max-width:120;
    min-width:120;

    border-style: solid;
    border-top-width:0;

    border-left-width:5;
    border-left-color:red;

    border-right-width:0;
    border-bottom-width:0;
}

.addAccount {
    background-color: #2f2e30;
    color: white;
    max-width:120;
    min-width:120;
    border-style: none;
    font: bold 14px;
}


/* nav controller */
NavController > QWidget {
    background-color: white;
}

NavController .addressDesc {
    background-color: white;
    color: black;
    font: bold 12px;
}

MainAddressView {
    background-color: black;
}

MainAddressView .address {
    background-color: #eff0f0;

    font-family: Monaco;
    font: 12px;

    border-style: solid;
    border-width: 1px;
    border-color: #e0e0e0;
}

MainAddressView > QPushButton {
    background-color: white;

    font: 12px;
    border-style: solid;
    border-width: 1px;
    border-color: #e0e0e0;
}

NavController .balanceDesc {
    background-color: white;
    color: black;
    font: bold 12px;
}

NavController .balanceAmt {
    background-color: white;
    color: black;
    font: 12px;
}

NavController .balanceUnit {
    background-color: white;
    color: #e0e0e0;
    font: 12px;
}

.navFunc {
    background-color: #303030;
    color: white;
    max-width: 130px;
    min-width: 130px;
    border-style: none;
    font: 12px;
    padding: 5px;
    margin-top: 5px;
    margin-bottom: 5px;
}

.navFunc:checked {
    background-color: #fb5f63;
}

.navFunc:clicked {
    background-color: #fb5f63;
}

/* detail controller*/

DetailController > QWidget {
    background-color: white;
}

/* tx table controller*/
TxFilterView > QWidget {
    background-color: #f0f0f0;
    max-height: 30;
    min-height: 30;
}

TxTableView > QTreeView {
    show-decoration-selected: 0;
    outline: none;
    background-color: white;
    alternate-background-color: #f0f0f0;
}

TxTableView > QTreeView::item {
    height: 30px;
}

TxTableView > QTreeView > QHeaderView {
    height: 30px;
    background-color: white;
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
