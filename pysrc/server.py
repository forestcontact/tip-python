from typing import Optional, Union
import sys
import logging
import base64
from dataclasses import asdict
import asyncio
import concurrent.futures

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import crypto
from . import json
from . import message
from . import protocol

from .app import parse_args
from .tipconfig import TipConfig, NodeConfig
from .node import Node
from .protocol import Protocol

from starlette.responses import Response

from mixin.mixin_bot_api import MixinBotApi
from mixin.mixin_ws_api import MixinWSApi

class SignatureRequest(BaseModel):
    identity: str
    data: str
    signature: str

logger = logging.getLogger(__name__)

class MyApp(FastAPI):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def start(self):
        self.setup_actions = {}
        self.setup_start = False
        self.p = None #Protocol object
        self.loop = asyncio.get_running_loop()

        args = parse_args(sys.argv[1:])
        self.config = TipConfig(args.config)
        self._node = Node(self.config)
        if args.sub == 'api':
            self.run_api(args)
        else:
            assert False

    @property
    def node(self):
        return self._node

    def run_api(self, args):
        self.get('/')(self.info)
        self.post('/')(self.sign)

    def info(self):
        node = self.node
        key = node.get_key()

        signers = []
        for signer in node.signers:
            signers.append({'identity': signer['public'], 'index': signer['index']})

        info = {
            "commitments": node.get_poly(),
            "identity":    crypto.get_public_key(key),
            "signers":     signers,
	    }

        sig = crypto.sign(key, json.Marshal(info))
        ret= {
            'data': info,
            'signature': sig.hex()
        }
        logger.info(ret)
        return ret

    def sign(self, req: SignatureRequest):
        # TODO implementing Guard
        r = self.node.db.guard(self.node.key, req.identity, req.signature, req.data)
        logger.info(r)
        if not r or r['available'] < 1:
            logger.info('Too Many Requestss')
            return {'error': {'code': 429, 'description': 'Too Many Requestss'}}

        logger.info('+++++node.index %s %s', self.node.index, self.node.key)
        index, share_private = self.node.get_share()
        partial = crypto.tbls_sign(index, share_private, req.identity)
        partial = bytes.fromhex(partial)
        data = base64.urlsafe_b64decode(req.data+'===')
        data = crypto.decrypt(req.identity, self.node.key, data)
        data = json.Unmarshal(data)
        partial = data['nonce'].to_bytes(8, 'big') + partial
        partial = crypto.encrypt(req.identity, self.node.key, partial)

        partial = {'partial': partial.hex()}
        _partial = json.Marshal(partial)
        sig = crypto.sign(self.node.key, _partial)
        logger.info(partial)
        ret = dict(data=partial, signature=sig.hex())
        logger.info(ret)
        return ret

    def close(self):
        self.node.close()

app = MyApp(default_response_class=JSONResponse)

@app.on_event("startup")
async def startup_event():
    app.start()

@app.on_event("shutdown")
def shutdown_event():
    app.close()

@app.post('/abc')
def abc(req: dict):
    return app.sign(req)

