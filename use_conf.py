# -*- coding: utf-8 -*-
__author__ = 'zhouqi'


import ConfigParser, os

config = ConfigParser.ConfigParser()
# config.readfp(open('defaults.cfg'))
# config.read(['site.cfg', os.path.expanduser('~/.myapp.cfg')])

config.add_section('Section1')
config.set('Section1', 'an_int', '15')
config.set('Section1', 'a_bool', 'true')
config.set('Section1', 'a_float', '3.1415')
config.set('Section1', 'baz', 'fun')
config.set('Section1', 'bar', 'Python')
config.set('Section1', 'foo', '%(bar)s is %(baz)s!')
config.set('Section1', 'foo2', {'a': 2})
print config.get('Section1', 'an_int1')

with open('example.cfg', 'wb') as configfile:
    config.write(configfile)