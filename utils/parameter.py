# -*- coding: utf-8 -*-
from utils import Singleton

__author__ = 'zhouqi'


class Parameter(object):
    __metaclass__ = Singleton

    TESTNET = False
    NOLNET = False

    ADDRTYPE_P2PKH = 0
    ADDRTYPE_P2SH = 5
    ADDRTYPE_P2WPKH = 6

    XPRV_HEADER = 0x0488ade4
    XPUB_HEADER = 0x0488b21e

    HEADERS_URL = 'http://127.0.0.1:8866/files/blockchain_headers'

    ELECTRUM_VERSION = '2.8.3'  # version of the client package
    PROTOCOL_VERSION = '0.10'  # protocol version requested

    # The hash of the mnemonic seed must begin with this
    SEED_PREFIX = '01'  # Electrum standard wallet
    SEED_PREFIX_SW = '02'  # Electrum segwit wallet
    SEED_PREFIX_2FA = '101'  # extended seed for two-factor authentication

    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    DEFAULT_SERVERS = {
        'erbium1.sytes.net': DEFAULT_PORTS,  # core, e-x
        'ecdsa.net': {'t': '50001', 's': '110'},  # core, e-x
        'gh05.geekhosters.com': DEFAULT_PORTS,  # core, e-s
        'VPS.hsmiths.com': DEFAULT_PORTS,  # core, e-x
        'electrum.anduck.net': DEFAULT_PORTS,  # core, e-s; banner with version pending
        'electrum.no-ip.org': DEFAULT_PORTS,  # core, e-s
        'electrum.be': DEFAULT_PORTS,  # core, e-x
        'helicarrier.bauerj.eu': DEFAULT_PORTS,  # core, e-x
        'elex01.blackpole.online': DEFAULT_PORTS,  # core, e-x
        'electrumx.not.fyi': DEFAULT_PORTS,  # core, e-x
        'node.xbt.eu': DEFAULT_PORTS,  # core, e-x
        'kirsche.emzy.de': DEFAULT_PORTS,  # core, e-x
        'electrum.villocq.com': DEFAULT_PORTS,  # core?, e-s; banner with version recommended
        'us11.einfachmalnettsein.de': DEFAULT_PORTS,  # core, e-x
        'electrum.trouth.net': DEFAULT_PORTS,  # BU, e-s
        'Electrum.hsmiths.com': {'t': '8080', 's': '995'},  # core, e-x
        'electrum3.hachre.de': DEFAULT_PORTS,  # core, e-x
        'b.1209k.com': DEFAULT_PORTS,  # XT, jelectrum
        'elec.luggs.co': {'s': '443'},  # core, e-x
        'btc.smsys.me': {'t': '110', 's': '995'},  # BU, e-x
    }


# HEADERS_URL = "https://headers.electrum.org/blockchain_headers"


################################## transactions

FEE_STEP = 10000
MAX_FEE_RATE = 300000
FEE_TARGETS = [25, 10, 5, 2]

COINBASE_MATURITY = 100
COIN = 100000000

# supported types of transction outputs
TYPE_ADDRESS = 0
TYPE_PUBKEY = 1
TYPE_SCRIPT = 2

# There is a schedule to move the default list to e-x (electrumx) by Jan 2018
# Schedule is as follows:
# move ~3/4 to e-x by 1.4.17
# then gradually switch remaining nodes to e-x nodes




NODES_RETRY_INTERVAL = 60
SERVER_RETRY_INTERVAL = 10


def set_testnet():
    Parameter().TESTNET = True
    Parameter().ADDRTYPE_P2PKH = 111
    Parameter().ADDRTYPE_P2SH = 196
    Parameter().ADDRTYPE_P2WPKH = 3
    Parameter().XPRV_HEADER = 0x04358394
    Parameter().XPUB_HEADER = 0x043587cf
    # HEADERS_URL = "https://headers.electrum.org/testnet_headers"
    Parameter().HEADERS_URL = 'http://127.0.0.1:8866/files/testnet_headers'

    # Parameter().DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    # Parameter().DEFAULT_SERVERS = {
    #     '14.3.140.101': Parameter().DEFAULT_PORTS,
    #     'testnet.hsmiths.com': {'t': '53011', 's': '53012'},
    #     'electrum.akinbo.org': Parameter().DEFAULT_PORTS,
    #     'ELEX05.blackpole.online': {'t': '52011', 's': '52002'},
    # }
    Parameter().DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    Parameter().DEFAULT_SERVERS = {
        'testnetnode.arihanc.com': Parameter().DEFAULT_PORTS,
        'testnet1.bauerj.eu': Parameter().DEFAULT_PORTS,
        # '14.3.140.101': Parameter().DEFAULT_PORTS,
        # 'testnet.hsmiths.com': {'t': '53011', 's': '53012'},
        'electrum.akinbo.org': Parameter().DEFAULT_PORTS,
        # 'ELEX05.blackpole.online': {'t': '52011', 's': '52002'},
    }


def set_nolnet():
    Parameter().NOLNET = True
    Parameter().ADDRTYPE_P2PKH = 0
    Parameter().ADDRTYPE_P2SH = 5
    Parameter().ADDRTYPE_P2WPKH = 6
    Parameter().XPRV_HEADER = 0x0488ade4
    Parameter().XPUB_HEADER = 0x0488b21e
    Parameter().HEADERS_URL = "https://headers.electrum.org/nolnet_headers"

    Parameter().DEFAULT_PORTS = {'t': '52001', 's': '52002'}
    Parameter().DEFAULT_SERVERS = {
        '14.3.140.101': Parameter().DEFAULT_PORTS,
    }
