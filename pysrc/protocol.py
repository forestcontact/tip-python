from typing import List, Any, Union
import json

import threading
import concurrent.futures

from . import _tip
from .tip import parse_ret

class Protocol:

    def __init__(self, key, nonce, signers: List[Any]):
        self.key = key
        self.nonce = nonce
        self.signers = signers
        ret = _tip.protocol_new(len(signers)//3*2+1, key, nonce, json.dumps(signers))
        ret = parse_ret(ret)
        self.ptr = int(ret)

    def deal(self):
        ret = _tip.protocol_deal(self.ptr, self.nonce)
        ret = parse_ret(ret)
        return bytes.fromhex(ret)

    def response(self):
        ret = _tip.protocol_response(self.ptr)
        ret = parse_ret(ret)
        return bytes.fromhex(ret)

    def justif(self):
        ret = _tip.protocol_justif(self.ptr)
        ret = parse_ret(ret)
        return ret

    def finish(self):
        ret = _tip.protocol_finish(self.ptr)
        ret = parse_ret(ret)
        return ret

    def on_deal(self, new_deal: bytes):
        ret = _tip.protocol_on_deal(self.ptr, new_deal)
        return parse_ret(ret)

    def on_response(self, response: bytes):
        ret = _tip.protocol_on_response(self.ptr, response)
        return parse_ret(ret)

    def on_justification(self, justification: bytes):
        ret = _tip.protocol_on_justification(self.ptr, justification)
        return parse_ret(ret)

def on_message(msg_type: int, msg: bytes):
    ret = _tip.protocol_on_message(msg_type, msg, None)

def setup(index: int, key: Union[bytes, str], signers: list, nonce: int, timeout: int, send_message_fn):
    ret = _tip.protocol_setup(index, key, signers, nonce, timeout, send_message_fn)
    ret = parse_ret(ret)
    return ret

def setup_in_thread(index: int, key: Union[bytes, str], signers: list, nonce: int, timeout: int, send_message_fn):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(setup, index, key, signers, nonce, timeout, send_message_fn)
        ret = future.result()
        return ret
