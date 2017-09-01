#!/usr/bin/env python2

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp
import argparse

# version = imp.load_source('version', 'lib/version.py')

if sys.version_info[:3] < (2, 7, 0):
    sys.exit("Error: Electrum requires Python version >= 2.7.0...")

data_files = []

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root=', dest='root_path', metavar='dir', default='/')
    opts, _ = parser.parse_known_args(sys.argv[1:])
    usr_share = os.path.join(sys.prefix, "share")
    if not os.access(opts.root_path + usr_share, os.W_OK) and \
       not os.access(opts.root_path, os.W_OK):
        if 'XDG_DATA_HOME' in os.environ.keys():
            usr_share = os.environ['XDG_DATA_HOME']
        else:
            usr_share = os.path.expanduser('~/.local/share')
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum.desktop']),
        (os.path.join(usr_share, 'pixmaps/'), ['icons/electrum.png'])
    ]

setup(
    name="ElectrumQ",
    version='0.0.1',
    install_requires=[
        'pyaes',
        'ecdsa',
        'pbkdf2',
        'requests',
        'qrcode',
        # 'protobuf',
        # 'dnspython',
        # 'jsonrpclib',
        # 'PySocks>=1.6.6',
    ],
    packages=[
        'electrumq',
        'electrumq.db',
        'electrumq.message',
        'electrumq.tests',
        'electrumq.UI',
        'electrumq.utils',
        'electrumq.wallet',
    ],
    package_dir={
        'electrumq': 'electrumq',
    },
    package_data={
        # 'electrum': [
        #     'currencies.json',
        #     'www/index.html',
        #     'wordlist/*.txt',
        #     'locale/*/LC_MESSAGES/electrum.mo',
        # ]
    },
    scripts=[],
    data_files=data_files,
    description="Lightweight Bitcoin Wallet",
    author="Zhou Qi",
    author_email="bitwolaiye@gmail.com",
    license="MIT Licence",
    url="https://zhouqi.work",
    long_description="""Lightweight Bitcoin Wallet"""
)
