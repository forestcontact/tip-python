from typing import List, Dict, Tuple, Union
import io
import time
import math
import logging

from dataclasses import dataclass
from enum import Enum

import base58

from .bundle import Decoder, Encoder
from .structs import Scalar, uint64
from . import kyber
from . import dkg
from . import share
from . import crypto

logger = logging.getLogger(__name__)

class EnumMessage(Enum):
    ActionSetup       = 7000
    ActionDKGDeal     = 7001
    ActionDKGResponse = 7002
    ActionDKGJustify  = 7003

    SetupPeriodSeconds = 300

@dataclass
class Message:
    action:    int = 0
    sender:    str = None
    data:      bytes = None
    signature: bytes = b''

@dataclass
class SetupBundle:
    nonce:          int = 0#uint64
    time_stamp:     int = 0 #time.Time

def encode_setup_bundle(sb: SetupBundle) -> bytes:
    enc = Encoder()
    enc.write_uint64(sb.nonce)
    enc.write_uint64(sb.time_stamp)
    return enc.get_bytes()

def decode_setup_bundle(b: bytes) -> SetupBundle:
    sb = SetupBundle()
    dec = Decoder(b)

    no = dec.read_uint64()
    sb.nonce = no

    ts = dec.read_uint64()
    sb.time_stamp = ts
    return sb

def make_setup_message(key: str, nonce: uint64) -> bytes:
    data = encode_setup_bundle(SetupBundle(nonce, int(time.time()*1000000000)))
    return make_message(key, EnumMessage.ActionSetup.value, data)

def make_message(key: Union[str, bytes], action: int, data: bytes) -> bytes:
    public = crypto.get_public_key(key)
    msg = Message(action, public, data)
    b = encode_message(msg)
    sig = crypto.sign(key, b)
    msg.signature = sig
    return encode_message(msg)

def encode_message(m: Message) -> bytes:
    enc = Encoder()
    enc.write_int(m.action)
    enc.write_fixed_bytes(m.sender.encode())
    enc.write_fixed_bytes(m.data)
    enc.write_fixed_bytes(m.signature)
    return enc.get_bytes()

def decode_message(b: bytes) -> Message:
    msg = Message()
    dec = Decoder(b)

    an = dec.read_int()
    msg.action = an

    sender = dec.read_bytes()
    msg.sender = sender.decode()

    data = dec.read_bytes()
    msg.data = data

    sig = dec.read_bytes()
    msg.signature = sig
    
    logger.info(len(sig))

    # signature generate from encoded same message with empty signature
    # equal to:
    # msg = Message(msg.action, msg.sender, msg.data)
    # raw_msg = encode_message(msg)
    raw_msg = b[:-68] + b'\x00\x00\x00\x00'
    if not crypto.verify(msg.sender, raw_msg, msg.signature):
        raise Exception('bad signature')

    return msg

def verify_message(msg: Message):
    _msg = Message(msg.action, msg.sender, msg.data)
    data = encode_message(_msg)
    return crypto.verify(msg.sender, data, msg.signature)
