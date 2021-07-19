import io
from typing import NewType, Tuple
from . import dkg

from .structs import ResponseBundle, Response
from .structs import Deal, DealBundle
from .structs import Point
from .structs import uint64
from . import crypto

class Decoder:
    def __init__(self, bs: bytes):
        self.buf = io.BytesIO(bs)

    def read(self, n: int):
        data = self.buf.read(n)
        assert len(data) == n
        return data

    def read_byte(self):
        return self.read(1)

    def read_bool(self):
        b = self.read(1)
        return b == b'0x01'

    def read_int(self):
        n = self.read(4)
        return int.from_bytes(n, 'big')

    def read_uint32(self):
        n = self.read(4)
        return int.from_bytes(n, 'big')

    def read_uint64(self):
        n = self.read(8)
        return int.from_bytes(n, 'big')

    def read_bytes(self):
        n = self.read_int()
        return self.read(n)

class Encoder:
    
    def __init__(self):
        self.enc = io.BytesIO()

    def get_bytes(self) -> bytes:
        return self.enc.getvalue()

    def write(self, b: bytes):
        self.enc.write(b)

    def write_bool(self, b: bool):
        if b:
            self.write(b'\x01')
        else:
            self.write(b'\x00')

    def write_int(self, n: int):
        bs = n.to_bytes(4, 'big')
        self.enc.write(bs)

    def write_uint32(self, n: int):
        bs = n.to_bytes(4, 'big')
        self.enc.write(bs)

    def write_uint64(self, n: int):
        bs = n.to_bytes(8, 'big')
        self.enc.write(bs)

    def write_fixed_bytes(self, bs: bytes):
        self.write_uint32(len(bs))
        self.write(bs)

def uint32_to_bytes(n: int):
    return n.to_bytes(4, 'big')

def uint64_to_bytes(d: int):
    return d.to_bytes(8, 'big')


def encode_justification_bundle(jb: dkg.JustificationBundle) -> bytes:
    enc = Encoder()
    enc.write_uint32(jb.dealer_index)

    enc.write_uint32(len(jb.justifications))
    for j in jb.justifications:
        enc.write_uint32(j.share_index)
        enc.write_fixed_bytes(j.share)

    enc.write_fixed_bytes(jb.session_id)
    enc.write_fixed_bytes(jb.signature)

    return enc.buf.getvalue()

def decode_justification_bundle(b: bytes) -> dkg.JustificationBundle:
    dec = Decoder(b)

    di = dec.read_uint32()
    # jb.DealerIndex = di

    jl = dec.read_uint32()
    justifications = []
    for i in range(jl):
        si = dec.read_uint32()
        scalar = dec.read_bytes()
        justifications.append(dkg.Justification(si, scalar))
    sid = dec.read_bytes()

    # jb.SessionID = sid
    sig = dec.read_bytes()

    # jb.Signature = sig
    return dkg.JustificationBundle(di, justifications, sid, sig)

def encode_response_bundle(rb: ResponseBundle) -> bytes:
    enc = Encoder()
    enc.write_uint32(rb.share_index)

    enc.write_int(len(rb.responses))
    for r in rb.responses:
        enc.write_uint32(r.dealer_index)
        enc.write_bool(r.status)

    enc.write_fixed_bytes(rb.session_id)
    enc.write_fixed_bytes(rb.signature)

    return enc.get_bytes()

def decode_response_bundle(b: bytes) -> ResponseBundle:
    rb = ResponseBundle()
    dec = Decoder(b)

    si = dec.read_uint32()
    rb.share_index = si

    rl = dec.read_uint32()
    for _ in range(rl):
        di = dec.read_uint32()
        ss = dec.read_bool()
        rb.responses.append(Response(di,ss))

    sid = dec.read_bytes()
    rb.session_id = sid
    sig = dec.read_bytes()
    rb.signature = sig
    return rb

def encode_deal_bundle(db: DealBundle, nonce: uint64) -> bytes:
    enc = Encoder()
    enc.write_uint64(nonce)
    enc.write_uint32(db.dealer_index)

    enc.write_int(len(db.deals))
    for d in db.deals:
        enc.write_uint32(d.share_index)
        enc.write_fixed_bytes(d.encrypted_share)

    enc.write_int(len(db.public))
    for p in db.public:
        b = crypto.public_key_bytes(p)
        enc.write_fixed_bytes(b)

    enc.write_fixed_bytes(db.session_id)
    enc.write_fixed_bytes(db.signature)

    return enc.get_bytes()

def decode_deal_bundle(b: bytes) -> Tuple[uint64, DealBundle]:
    db = DealBundle()
    dec = Decoder(b)

    nonce = dec.read_uint64()
    di = dec.read_uint32()
    db.dealer_index = di

    dl = dec.read_int()
    for _ in range(dl):
        si = dec.read_uint32()
        es = dec.read_bytes()
        db.deals.append(Deal(si, es))

    pl = dec.read_int()
    for _ in range(pl):
        pb = dec.read_bytes()
        db.public.append(crypto.public_key_from_bytes(pb))

    sid = dec.read_bytes()
    db.session_id = sid
    sig = dec.read_bytes()
    db.signature = sig

    return nonce, db

