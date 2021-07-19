from typing import Union
import os
import io
import time
import pickle
import logging
from enum import Enum

from . import _tip
from . import crypto
from . import panic
from .tip import parse_ret

logger = logging.getLogger(__name__)

class KeyType(Enum):
	PolyGroup  = "POLY#GROUP"
	PolyPublic = "POLY#PUBLIC"
	PolyShare  = "POLY#SHARE"

	PrefixAssignee = "ASSIGNEE#"
	PrefixAssignor = "ASSIGNOR#"
	PrefixLimit    = "LIMIT#"
	PrefixNonce    = "NONCE#"

maxUint64               = 0xffffffffffffffff

def db_open(db_path: str):
    return _tip.store_open(db_path)

def db_close(ptr: int):
    return _tip.store_close(ptr)

def db_get(ptr: int, key: Union[bytes, str]):
    return _tip.store_get(ptr, key)

def db_set(ptr: int, key: Union[bytes, str], val: Union[bytes, str], ttl: int = 0):
    return _tip.store_set(ptr, key, val, ttl)

def db_find(ptr: int, prefix: Union[bytes, str]):
    return _tip.store_find(ptr, prefix)

def db_filter(ptr: int, prefix: Union[bytes, str], fn):
    return _tip.store_filter(ptr, prefix, fn)

def db_guard(db_index: int, priv: str, identity: str, signature: str, data: str):
    ret = _tip.store_guard(db_index, priv, identity, signature, data)
    return parse_ret(ret)

class DB(object):

    def __init__(self, db_path: str):
        self.share = None
        self.public = None
        self.ptr = db_open(db_path)        

    def close(self):
        db_close(self.ptr)

    def get(self, key: Union[str, bytes]):
        return db_get(self.ptr, key)
    
    def set(self, key: Union[str, bytes], value: Union[str, bytes]):
        return db_set(self.ptr, key, value)

    def find(self, prefix: Union[str, bytes]):
        return db_find(self.ptr, prefix)

    def filter(self, prefix, fn):
        return db_filter(self.ptr, prefix, fn)

    def check_limit(self, key: bytes, window: int, quota: int, increase: bool):
        available = quota
        self.find(KeyType.PrefixLimit.value + key)
        pass

    def write_poly(self, public: bytes, share: bytes):
        self.set(KeyType.PolyPublic.value, public)
        self.set(KeyType.PolyShare.value, share)

    def read_poly_share(self):
        if self.share:
            return self.share

        r = self.get(KeyType.PolyShare.value)
        if not r:
            return
        index = int.from_bytes(r[:4], 'big')
        key = r[4:]
        self.share = (index, key.hex())
        return self.share

    def read_poly_public(self):
        if self.public:
            return self.public

        pub = self.get(KeyType.PolyPublic.value)
        if not pub:
            return None

        self.public = []
        for i in range(len(pub)//128):
            self.public.append(crypto.public_key_from_bytes(pub[i*128:(i+1)*128]))
        return self.public
    
    def check_poly_group(self, group_id):
        val = self.get(KeyType.PolyGroup.value)
        if not val:
            return self.set(KeyType.PolyGroup.value, group_id)

        if not group_id == val:
            panic.panic(f'Group check failed. expetc {group_id}, got {val}')
        logger.info('check poly group passed!')
        return True

    def rotate_ephemeral_nonce(self, key: bytes, ephemeral: bytes, nonce: int):
        now = int(time.time() * 1e9)
        buf = io.BytesIO()
        buf.write(now.to_bytes(8, 'big'))
        buf.write(ephemeral)
        buf.write(nonce.to_bytes(8, 'big'))
        self.set(KeyType.PrefixNonce.value.encode() + key, buf.getvalue())

    def check_rotate_ephemeral_nonce(self, key: bytes, ephemeral: bytes, nonce: int, grace: int):
        db_key = KeyType.PrefixNonce.value.encode() + key
        val = self.get(db_key)
        if not val:
            self.rotate_ephemeral_nonce(key, ephemeral, nonce)
            return True

        buf = io.BytesIO(val)
        now = buf.read(8)
        now = int.from_bytes(now, 'big')
        if now + grace < int(time.time() * 1e9):
            self.rotate_ephemeral_nonce(key, ephemeral, nonce)
            return True

        ephemeral_old = buf.read(val-8-8)
        if not ephemeral == ephemeral_old:
            return False

        nonce_old = buf.read(8)
        nonce_old = int.from_bytes(nonce, 'big')
        if nonce_old >= nonce:
            return False
        
        self.rotate_ephemeral_nonce(key, ephemeral, nonce)
        return True
    
    def guard(self, priv: str, identity: str, signature: str, data: str):
        return db_guard(self.ptr, priv, identity, signature, data)
