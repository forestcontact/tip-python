from typing import Any
import io
import sys
import json
import base64
import hashlib
import argparse
import asyncio

import httpx
import logging

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(module)s %(lineno)d %(message)s')
logger = logging.getLogger(__name__)

from . import tip
from . import crypto
from .tipconfig import TipConfig, NodeConfig
from .node import Node
from . import message

def gen_key(args):
    k = crypto.gen_key()
    print(k['scalar'])
    print(k['public'])

def gen_request(key, nonce, ephemeral, rotate, node_id):
    grace = 1 * 60 * 60 * int(1e9) * 24 * 128 # 128 days
    esum = ephemeral + node_id
    esum = hashlib.sha3_256(esum.encode()).digest()

    msg = io.BytesIO()
    pkey = crypto.get_public_key(key)
    raw_pkey = crypto.public_key_bytes(pkey)
    msg.write(raw_pkey)
    msg.write(esum)
    msg.write(nonce.to_bytes(8, 'big'))
    msg.write(grace.to_bytes(8, 'big'))

    # print({
    #         'key': key,
    #         'ephemeral': ephemeral,
    #         'rotate': rotate,
    #         'nonce': nonce
    #     }
    # )

    data = {
        "identity":  crypto.get_public_key(key),
        "ephemeral": esum.hex(),
        "nonce":     nonce,
        "grace":     grace
    }

    if rotate:
        rsum = rotate + node_id
        rsum = rsum.encode()
        rsum = hashlib.sha3_256(rsum).digest()
        msg.write(rsum)
        data['rotate'] = rsum.hex()
    data = dict(sorted(data.items(), key=lambda item: item[0]))
    raw_data = json.dumps(data, separators=(',', ':'))
    cipher = crypto.encrypt(node_id, key, raw_data)
    sig = crypto.sign(key, msg.getvalue())
    return {
        'identity': pkey,
        'data': base64.urlsafe_b64encode(cipher).rstrip(b'=').decode(),
        'signature': sig.hex()
    }

def run_sign(args: Any):
    config = args.config
    with open(config, 'r') as f:
        config = json.load(f)

    partials = {}
    for signer in config['signers']:
        logger.info(signer)
        node_id = signer['identity']
        request = gen_request(args.key, args.nonce, args.ephemeral, args.rotate, node_id)

        url = signer['api']
        print(url)
        r = httpx.post(url, json=request)
        print(r)
        r = r.json()
        # logger.info(r)
        if 'error' in r:
            logger.info(r)
            continue
        print(r)
        partial = r['data']['cipher']
        partial = bytes.fromhex(partial)
        dec = partial = crypto.decrypt(node_id, args.key, partial)
        print("partial", partial, len(partial), 128+66+8)
        partial, assignee = dec[8:74], dec[74:]
        print("assignee", assignee)
        nonce = int.from_bytes(dec[:8], 'big')
        index = int.from_bytes(dec[8:10], 'big')
        logger.info("index: %s nonce: %s partial: %s", index, nonce, partial)
        partials[index] = partial.hex()
        print(index, len(partial))

    try:
        r = crypto.tbls_recover(assignee.hex(), list(partials.values()), config['commitments'], len(config['signers']))
        logger.info('++++signature:%s', r)
        return r
    except Exception as e:
        logger.info(e)

def request_setup(args):
    logger.info('+++request_setup: %s', args)
    nonce = args.nonce
    if nonce < 1024:
        raise Exception("nonce too small")
    config = TipConfig(args.config)
    logger.info(config)
    logger.info(config.node_config.key)

    messenger = config.messenger_config
    bot_config = {
        "client_id": messenger.user,
        "pin": "",
        "session_id": messenger.session,
        "pin_token": "",
        "private_key": messenger.key
    }
    async def run():
        data = message.make_setup_message(config.node_config.key, args.nonce)
        data = base64.urlsafe_b64encode(data).rstrip(b'=')
        # logger.info(data)
        r = await bot.send_text_message(messenger.conversation, data)
        # logger.info(r)
    r = asyncio.run(run())
    logger.info(r)

def run_signer(args):
    logger.info('+++run_signer: %s', args)
    config = TipConfig(args.config)
    node = Node(config)
    node.run_signer()

def gen_config(args):
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

def parse_args(argv):
    parser = argparse.ArgumentParser(description='tip')
    parser.add_argument('-c', '--config', type=str, help='config file')

    subparsers = parser.add_subparsers(help='sub command help')
    parser_key = subparsers.add_parser('key', help='generate a key pair')
    parser_key.set_defaults(func=gen_key)

    parser_sign = subparsers.add_parser('sign', help='request a signature')
    parser_sign.add_argument('--key', type=str, help='The identity key')
    parser_sign.add_argument('--ephemeral', type=str, help='The ephemeral seed')
    parser_sign.add_argument('--rotate', type=str, help='The ephemeral rotation')
    parser_sign.add_argument('--nonce', type=int, help='The nonce')
    parser_sign.set_defaults(func=run_sign, sub='sign')

    parser_setup = subparsers.add_parser('setup', help='request a setup')
    parser_setup.add_argument('--nonce', type=int, help='nonce')
    parser_setup.set_defaults(func=request_setup, sub='setup')

    parser_api = subparsers.add_parser('gen-config', help='generate a key pair')
    parser_api.set_defaults(func=gen_config, sub='gen_config')

    parser_sign = subparsers.add_parser('signer', help='request a signature')
    parser_sign.set_defaults(func=run_signer, sub='signer')

    parser_api = subparsers.add_parser('api', help='generate a key pair')
    parser_api.set_defaults(sub='api')

    args = parser.parse_args(argv)
    return args

def Main(argv):
    args = parse_args(argv)
    args.func(args)

if __name__ == '__main__':
    Main(sys.argv[1:])
# print(config)
