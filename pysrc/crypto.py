from typing import Union, NewType, List
import json
import hashlib

import base58

from . import _tip

PublicKey = NewType('PublicKey', str)
PrivateKey = NewType('Privatekey', str)

def parse_ret(ret):
    ret = json.loads(ret)
    if 'error' in ret:
        raise Exception(ret['error'])
    return ret['data']

def gen_key():
    ret = _tip.gen_key()
    return parse_ret(ret)

def get_public_key(key: Union[str, str]) -> str:
    '''
        key: bytes or hex string representation of private key
    return:
        base58 encoded public key
    '''
    if isinstance(key, bytes):
        key = key.hex()
    ret = _tip.crypto_get_public_key(key)
    return parse_ret(ret)

def sign(scalar: Union[bytes, str], msg: bytes) -> bytes:
    if isinstance(scalar, str):
        scalar = bytes.fromhex(scalar)
    ret = _tip.crypto_sign(scalar, msg)
    return ret

def verify(pub: str, msg: bytes, sig: Union[bytes, str]):
    if isinstance(sig, str):
        sig = bytes.fromhex(sig)
    ret = _tip.crypto_verify(pub, msg, sig)
    return ret

def public_key_from_base58(pub: str):
    ret = _tip.crypto_public_key_from_base58(pub)
    return parse_ret(ret)

def encrypt(pub: str, priv: str, msg: Union[bytes, str]) -> bytes:
    return _tip.crypto_encrypt(pub, priv, msg)

def decrypt(pub: str, priv: str, msg: Union[bytes, str]) -> bytes:
    return _tip.crypto_decrypt(pub, priv, msg)

def tbls_sign(index: int, priv: PrivateKey, identity: PublicKey):
    ret = _tip.tbls_sign(index, priv, identity)
    return parse_ret(ret)

def tbls_recover(key: PrivateKey, partials: List[str], commitments: List[PublicKey], total_signers: int):
    ret = _tip.tbls_recover(key, json.dumps(partials), json.dumps(commitments), total_signers)
    return parse_ret(ret)

def public_key_bytes(pub: Union[str, bytes]):
    ret = _tip.crypto_public_key_bytes(pub)
    ret = parse_ret(ret)
    return bytes.fromhex(ret)

def base64_encode(msg: Union[bytes, str]):
    ret = _tip.crypto_base64_encode(msg)
    return parse_ret(ret)

def public_key_from_bytes(pub: bytes):
    pub = b'T' + pub
    h = hashlib.sha256(pub).digest()
    h = hashlib.sha256(h).digest()
    pub += h[:4]
    return base58.b58encode(pub).decode()
