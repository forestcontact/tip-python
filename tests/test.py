from typing import List
import os
import time
import toml
import shlex
import json
import logging

import httpx

from dataclasses import dataclass, field

from tip import app
from tip import crypto
from tip import store
from tip import message
from tip import structs
from tip import bundle

test_dir = os.path.dirname(__file__)

logger = logging.getLogger(__name__)

@dataclass
class MessengerConfig:
    user: str
    session: str
    key: str
    buffer: int
    conversation: str

@dataclass
class NodeConfig:
    key: str
    signers: List[str]
    timeout: int


@dataclass
class TipConfig:
    api: dict
    store: dict
    messenger: dict
    node: dict

@dataclass
class Scalar:
    s: str

@dataclass
class Point:
    s: str


def test_gen_key():
    key = crypto.gen_key()
    print(key)

def test_crypto_public_key():
    ret = crypto.get_public_key('4228cc5caf1eb37ab44343f0e7ea872dcc0f27d1d795e08e93e34ea6b28ef2f6')
    print(ret)
    assert ret

def test_crypto():
    scalar = '4228cc5caf1eb37ab44343f0e7ea872dcc0f27d1d795e08e93e34ea6b28ef2f6'
    signature = crypto.sign(scalar, b'hello,world')
    print('+++signature:', signature)

    pub = '5HNVXE3VjPihbXETswQP9VstqVtAcUZCqN5wM319PuzoHvkLGqnJGRUQeQQ3K1dFTmQLA2wBH8x555K1eE7ZJ8mSTi6fuCyhbGVtBikLx7Vvyr8o2G8i6G9LnsiCKdEW5Cus8bYUm8Y8b97ANGyqJpw13NtcR8yBMV6ZheemHytK6qFZbzkCi6'
    ret = crypto.verify(pub, b'hello,world', signature)
    print('+++verify:', ret)

def load_toml():
    config = toml.load(os.path.join(test_dir, 'example.toml'))
    return TipConfig(**config)

def test_toml():
    config = load_toml()
    print(config.api['port'])

    print(config.store['dir'])

    print('messenger:')
    print('+++user:', config.messenger['user'])
    print('+++key:', config.messenger['key'])
    print('+++conversation:', config.messenger['conversation'])

    print('node:')
    print(config.node['key'])
    for i, signer in enumerate(config.node['signers']):
        print(i, signer)

def test_encrpt_decrypt():
    priv1 = '4e9b393adc87d501e65bbd6ef7b4b85c2708f12c290419c67feb0ee9068d843e'
    pub1 = '5J8AiBRnmn2LZNW6BogGjBCkY3E9gzMcAQ9Rh9cHVw4NfB2msUUELkbxh6jj3TvcrHqY5UpiM1M3Q63pak9vRMGsxo8CDTHNTUgkzkdwZetVonmyJwFLpSi6T1Gwi59nG9XLoCE3rCmqBGBYkRg4yPGzMzyiLHP7W4KhPmJR3eQHvR8PWwpyrk'

    priv2 = '4228cc5caf1eb37ab44343f0e7ea872dcc0f27d1d795e08e93e34ea6b28ef2f6'
    pub2 = '5HNVXE3VjPihbXETswQP9VstqVtAcUZCqN5wM319PuzoHvkLGqnJGRUQeQQ3K1dFTmQLA2wBH8x555K1eE7ZJ8mSTi6fuCyhbGVtBikLx7Vvyr8o2G8i6G9LnsiCKdEW5Cus8bYUm8Y8b97ANGyqJpw13NtcR8yBMV6ZheemHytK6qFZbzkCi6'

    msg = b'hello,world'
    encrypted_msg = crypto.encrypt(pub2, priv1, msg)
    print(encrypted_msg)

    decrypted_msg = crypto.decrypt(pub1, priv2, encrypted_msg)
    print(decrypted_msg)
    assert decrypted_msg == msg

def test_signer():
    commitments = [
        '5J61MdMyYtddtbJ1mN3CaXPQWT4wCJXsU9NAVDDrNmvzE1maT1nwiXbPryLqNMAUX3dkRiEYdbASi29zNBnopSNLuzXs36RzJ9cUYq7qUbN9tbDZsou2mjZCtmRPjJU8c3zwosbWj51QURvtoiiJ4riBVUn2Hh1B47Tn8ALVgsbYb9kJwHcJY4',
        '5JhTjbpGV9kwB6PHiVB6Dm3YuZNRC4yRSZm2jNFX45PPLVBkckFZpggW72uDQ33jM79VDnUCeqWVZomuMfNWibwg6rQ9MGvFUqu4A1o7ivnLiW8ix3LL7hQHyZW6ucUA4AVi8eypKhtUQvRzMXBQDJQ6ytUAsQ1oykeRP6X59P7oRySHeFW2f7',
        '5Job7Vk6aETNhtR3TijZjrQQ7Jr4X6Z4k3GT5bDxTwDrBrSRZ3qHhJLwdAwPEiX7HR6Wsqr71sXmrRQPzPGK1Auw5GocdZAx1Ax6nuL9YtZucYeyfThqLL3BRYmrbb1UPZYYEnsFBwjdJywv5wXgkoUQ2e273SJPSviHjpduNb582QbsPq82wh'
    ]

    priv_share = '0000000379844e977c73e60e107ddbf33a9fe7f942d3949c184455a68d3b40c94a1c8d54'
    store.write_poly(commitments, priv_share)
    argv = '-c tmp/helloworld1.toml sign'
    argv = shlex.split(argv)
    app.Main(argv)
    logger.info('++++hellooooooooooooo')

def test_api():
    commitments = [
        '5JWJPXYLrZgiearqe4gERzdsHxFz1xAvBhfZ5Km47kmi9XZbXSgLDwkP4b5xaeaaMT7ZxqfY89ofe21yEzcjfGdSg7WqcCJT8B7sUy8faDrw5U8HQZSS2my7Rgriy91jpBCZzEKfA1d3aoHZFEtvXe63wT6Jnn7mWK66cRAUnRCwSKJK5BVyaB',
        '5JhBB5xceoNmJvcW8UZpsUcgVWBYjfPKixhs8ce5GSAReYdhGMY3UU9EmigWzw71LkPnvh31mB992sTucHJ3UcTur4KUGZojGD3ahxTaCG8LAgowSSHyvRRtEeDVNba7SKtKG9EVvY6NTpyjoJ1CZn69bTBwz9grxNJsr1YsXF39fKMorLhWd5',
        '5JQyqMtJZBn9fUDBNPKJ18LYYEDRUwDx9f1N1JQk2i5b42mi3zmQW35yq2iUmbq4WDoGUjGD9htprZT7MycVSB4cacCfk3x28Bje4Mt5N6QAxtztZVayRBgC7u5Wy4g7gi7ztKb2AjVkJnc9SztwQfRGvWSTwe7vsqeeEazhzTKZ2wDBJta6bg'
    ]

    priv_share = '0000000379844e977c73e60e107ddbf33a9fe7f942d3949c184455a68d3b40c94a1c8d54'
    store.write_poly(commitments, priv_share)
    argv = '-c tmp/helloworld1.toml api'
    argv = shlex.split(argv)
    app.Main(argv)
    logger.info('++++hellooooooooooooo')

def test_store():
    ptr = store.db_open('/tmp/tip1')
    
    r = store.db_get(ptr, store.KeyType.PolyShare.value)
    logger.info(r)
    index = int.from_bytes(r[:4], 'big')
    key = r[4:]
    logger.info('%s %s', index, key.hex())
    
    r = store.db_get(ptr, store.KeyType.PolyPublic.value)
    logger.info(len(r))
    for i in range(len(r)//128):
        logger.info(r[i*128:(i+1)*128])

    store.db_set(ptr, 'a', 'b')
    store.db_set(ptr, 'a', 'bb')
    store.db_set(ptr, 'aa', 'bb')
    assert store.db_get(ptr, 'aa') == b'bb'

    logger.info(store.db_get(ptr, 'a'))

    r = store.db_find(ptr, 'a')
    logger.info(r)

    pub = crypto.get_public_key('7799')
    # logger.info(pub)
    pub = crypto.public_key_bytes(pub)
    # logger.info(pub)

    prefix = b'LIMIT#' + bytes.fromhex(pub) + b'EPHEMERAL'
    logger.info(prefix)

    r = store.db_find(ptr, prefix)
    for v in r:
        logger.info(v)

        key = v[0]
        now = key[len(prefix):]
        logger.info(now)
        now = int.from_bytes(now, 'big')
        now = 0xffffffffffffffff - now
        logger.info(time.gmtime(now/1e9))

def test_2store():
    ptr = store.db_open('/tmp/tip1')
    key = 'a1'
    if 0:
        pass
        store.db_set(ptr, key, key)
    else:
        logger.info(store.db_get(ptr, key))
    # import sys;sys.exit(-1)


def test_3store():
    for i in range(10):
        db_index = store.db_open('/tmp/tip1')
        store.db_set(db_index, 'aa', i.to_bytes(5, 'little'))
        value = store.db_get(db_index, 'aa')
        logger.info(value)
        store.db_close(db_index)

def test_key_filter():
    def fn(k, v):
        logger.info('%s %s', k, v)
        return 1

    ptr =  store.db_open('/tmp/tip1')
    store.db_set(ptr, 'a', 'b')
    store.db_filter(ptr, 'a', fn)

def test_key_compare():
    pub = crypto.get_public_key('4499')
    logger.info(pub)

    pub = b'+B\x13>\xc7+\xa7\x96\xaaF!\x8b%e\xab\xcb\x19\xf6\xfc\x94\xa7\xe9?s/D\xccK\x9c\x18\xd4\xdf @\xe2S\t\x8b\x01\x1b!\\~\x8a\x08\x9f\x01\xc2F,\x85\x8f\x7f\xae\xe4sMr?4;\xf3\xe5\x034<\xf7\x12\x95\x96l\xf5g\xcec\xe7\xee]\xd4\xe0iX<\xba\x96\x12\x05\xc1\x81\x94\x1b\x01\xb5\x04TGK|\x02r\xc0\xadK\xe4\x93\xb2 \xb3\xc6\x7f\xf1A\x0f\x191\xcam\x1e\xbe\x99\x12\xbb"\x86\xb3g;*'
    # pub = bytes.fromhex(pub)
    pub = crypto.public_key_from_bytes(pub)
    logger.info(pub)

    # store.db_close()

def test_message():
    r = message.make_message('aabb', 111, b"hello,world")
    assert r.hex() == '0000006f000000b6354a6235326678324c4c456663524467314e514b4d41785563424e7a335172734359637774616135764259476e4d37446f6f4439633435776d356f7a4e7374585a736236417672577158424d61694676757a6f4435743844347753456867565a7a7677343245654171687336556957704335367732365766657148447a4b38413265314c547659577437615576736e74396269774e6f645978784445426f796b39733673634d61395558745a6b724e796f4d463747360000000b68656c6c6f2c776f726c64000000402c55fc64d5a757989e12e81e3e06fe1b86fb17f5d278f6e567f9514c262d8fb7532419237f84bbf24c59771493578f92b14e4f2ce455ad07f36021c345120c2b'
    msg = message.decode_message(r)
    assert msg.sender == crypto.get_public_key('aabb')
    assert msg.action == 111
    assert msg.data == b'hello,world'
    assert msg.signature == r[-64:]

    r = message.make_message('ccdd', 222, b"goodbye,world")
    assert r.hex() == '000000de000000b6354a48544b7462323576576d506e7a59463259554a43455444394a6677796a6f68693662745278325854615a57505241366d78334c4776756847613835567a717a6f3639545457545754444172585878506f487474367677436d513562625159744b727461424278776d317766646a474d424336736e314135677257376834594539464b6d3244626f77433250516b4751366f59317479596f693462376550334533633462624d73357151457a7250556b47534141350000000d676f6f646279652c776f726c64000000404a1f12fa577998616fbd13590fc6e127c95d0dcb62e9bb229f6b5bf789f4a9fd68aa3581afc13d5a1bf5abe60149deb965a14c3805d27d452a5cbcca30753d84'
    msg = message.decode_message(r)
    assert msg.sender == crypto.get_public_key('ccdd')
    assert msg.action == 222
    assert msg.data == b'goodbye,world'
    assert msg.signature == r[-64:]

    sb = message.SetupBundle(111, 10000000001)
    data = message.encode_setup_bundle(sb)
    assert data.hex() == '000000000000006f00000002540be401'

    msg = message.decode_setup_bundle(data)
    assert msg.nonce == 111
    assert msg.time_stamp == 10000000001

def test_gen_config():
    urls = {
        'http://127.0.0.1:7001',
        'http://127.0.0.1:7002',
        'http://127.0.0.1:7003',
        'http://127.0.0.1:7004'
    }
    config = {
        'commitments': None,
        'signers': []
    }
    for url in urls:
        r = httpx.get(url)
        r = r.json()
        r = r['data']
        if not config['commitments']:
            config['commitments'] = r['commitments']

        index = 0
        for signer in r['signers']:
            if signer['identity'] == r['identity']:
                index = signer['index']
        config['signers'].append({'identity': r['identity'], 'api': url, 'index': index})
    config['signers'].sort(key=lambda x: x['index'])
    logger.info(json.dumps(config, indent='    '))

def test_deal_bundle():
    d = structs.Deal(3344, b'hello,world')
    pub = crypto.get_public_key('aabb')
    d = structs.DealBundle(1122, [d], [pub], b'', b'')
    b = bundle.encode_deal_bundle(d, 1122)
    logger.info(b.hex())
    assert b.hex() == '0000000000000462000004620000000100000d100000000b68656c6c6f2c776f726c640000000100000080728648ce7bb1387bf3e763a4d245efab55e0ffec22881095d79d973580f81ca34c0deb1354538ccc5ba328077102ce79087d74a576414b8786e41b7611fc43e88434b52c108c7575f077d8dd0c65b5e948560249b023124498ceeda9e0f3d103650fed682920b565b660807ef7c9bf4bdd5307d86a522ae2463a75914240434b0000000000000000'
# 0000000000000462000004620000000100000d100000000b68656c6c6f2c776f726c640000000100000080728648ce7bb1387bf3e763a4d245efab55e0ffec22881095d79d973580f81ca34c0deb1354538ccc5ba328077102ce79087d74a576414b8786e41b7611fc43e88434b52c108c7575f077d8dd0c65b5e948560249b023124498ceeda9e0f3d103650fed682920b565b660807ef7c9bf4bdd5307d86a522ae2463a75914240434b000000000000000
# 0000000000000462000004620000000100000d100000000b68656c6c6f2c776f726c640000000100000080728648ce7bb1387bf3e763a4d245efab55e0ffec22881095d79d973580f81ca34c0deb1354538ccc5ba328077102ce79087d74a576414b8786e41b7611fc43e88434b52c108c7575f077d8dd0c65b5e948560249b023124498ceeda9e0f3d103650fed682920b565b660807ef7c9bf4bdd5307d86a522ae2463a75914240434b000000000000000
    d = bundle.decode_deal_bundle(b)
    logger.info(d)

from json import JSONEncoder
class MyEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__  

@dataclass
class A:
    a: int = 1122

def test_1a():
    a = A()
    a = json.dumps([a], cls=MyEncoder)
    logger.info(a)
