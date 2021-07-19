import json

from typing import Union

from . import _tip

def parse_ret(ret):
    ret = json.loads(ret)
    if 'error' in ret:
        raise Exception(ret['error'])
    return ret['data']

def say_hello():
    _tip.say_hello()
