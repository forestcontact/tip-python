import io
import math
from typing import List, Dict, Union

import copy
import hashlib
import base58
import base64
import logging
import asyncio
import concurrent.futures

from mixin.mixin_bot_api import MixinBotApi
from mixin.mixin_ws_api import MixinWSApi


from . import message
from . import tip
from . import kyber
from . import dkg
from . import share
from . import crypto
from . import store
from . import protocol
from .tipconfig import TipConfig


logger = logging.getLogger(__name__)

class Node:
    def __init__(self, conf: TipConfig):
        self.config = conf
        self.conversation = conf.get_messenger_config().conversation

        self.share = None
        self.public = None

        self.db = store.DB(conf.store_config.dir)
        self.index = -1
        self.setup_actions = []
        self.key = conf.node_config.key
        self.identity = crypto.get_public_key(conf.node_config.key)
        # conf.signers.sort()

        self.signers = []
        group = io.BytesIO()
        signers = copy.copy(conf.node_config.signers)
        signers.sort()
        for i, v in enumerate(signers):
            # self.signers.append(dkg.Node(i, v))
            self.signers.append({'index': i, 'public': v})
            pub = crypto.public_key_from_base58(v)
            pub = bytes.fromhex(pub)
            group.write(pub)
            if self.identity == v:
                self.index = i

        assert self.index >= 0
        group_id = hashlib.sha3_256(group.getvalue()).digest()
        self.db.check_poly_group(group_id)
        self.period = int(conf.node_config.timeout * 1e9)

        self.poly = self.db.read_poly_public()
        self.share = self.db.read_poly_share()
        logger.info('+++%s %s', self.poly, self.share)

    def handle_setup_message(self, msg: message.Message):
        sb = message.decode_setup_bundle(msg.data)
        expired = []
        for k in self.setup_actions:
            v = self.setup_actions[k]
            if sb.nonce < v.nonce:
                return

            if math.abs(sb.time_stamp - v.time_stamp)/1e9 > 300: # > 300 seconds
                return
            if sb.nonce > v.nonce:
                expired.append(k)

        for  k  in expired:
            del self.setup_actions[k]

        self.setup_actions[msg.sender] = sb
        if len(self.setup_actions) >= self.threshold():
            self.setup(sb.nonce)

    def verify_message(self, msg: message.Message):
        sender = self.check_signer(msg.sender)
        if not sender:
            raise  Exception(f"unauthorized sender {msg.sender}")

        b = message.encode_message(msg)
        return crypto.verify(sender, b, msg.signature)

    def check_signer(self, sender: str) -> kyber.Point:
        for  s in self.signers:
            if s['public'] == sender:
                return s['public']
        return None

    def get_key(self) -> kyber.Scalar:
        return self.key

    def get_signers(self) -> List[dict]:
        return self.signers

    def get_share(self) -> share.PriShare:
        return self.share

    def get_poly(self) -> List[kyber.Point]:
        return self.poly

    # def Run(ctx context.Context) error {
    #     if node.share != nil || node.poly != nil {
    #         return nil
    #     }
    #     for {
    #         b, err := node.messenger.ReceiveMessage(ctx)
    #         logger.Infof("+++++++++ReceiveMessage")
    #         if err != nil {
    #             return err
    #         }
    #         msg, err := decodeMessage(b)
    #         if err != nil {
    #             logger.Errorf("msg decode error %d %s", len(b), err)
    #             continue
    #         }
    #         err = node.verifyMessage(msg)
    #         if err != nil {
    #             logger.Errorf("msg verify error %d %s", len(b), err)
    #             continue
    #         }
    #         switch msg.Action {
    #         case MessageActionSetup:
    #             err = node.handleSetupMessage(ctx, msg)
    #             logger.Verbose("SETUP", err)
    #         case MessageActionDKGDeal:
    #             nonce, db, err := decodeDealBundle(msg.Data)
    #             logger.Verbose("DEAL", nonce, err)
    #             if err != nil {
    #                 continue
    #             }
    #             if !node.dkgStarted {
    #                 node.setup(ctx, nonce)
    #             }
    #             node.board.deals <- *db
    #         case MessageActionDKGResponse:
    #             rb, err := decodeResponseBundle(msg.Data)
    #             logger.Verbose("RESPONSE", err)
    #             if err == nil && node.board != nil {
    #                 node.board.resps <- *rb
    #             }
    #         case MessageActionDKGJustify:
    #             jb, err := decodeJustificationBundle(msg.Data)
    #             logger.Verbose("JUSTIFICATION", err)
    #             if err == nil && node.board != nil {
    #                 node.board.justs <- *jb
    #             }
    #         }
    #     }
    # }

    @property
    def threshold(self) -> int:
        return len(self.signers)*2//3 + 1

    def close(self):
        self.db.close()

    def run_signer(self):
        asyncio.run(self.start_signer(), debug=True)

    async def start_signer(self):
        self.setup_actions = {}
        self.setup_start = False
        self.p = None #Protocol object
        self.loop = asyncio.get_running_loop()

        self.setup_actions = {}
        messenger = self.config.messenger_config
        bot_config = {
            "client_id": messenger.user,
            "pin": "",
            "session_id": messenger.session,
            "pin_token": "",
            "private_key": messenger.key
        }
        logger.info(bot_config)

        async def on_message(msg):
            try:
                await self.on_message(msg)
            except Exception as e:
                logger.exception(e)

        self.bot = MixinBotApi(bot_config)
        self.mixin_ws = MixinWSApi(bot_config, on_message=on_message)
        async def start():
            logger.info('mixin_ws starting...')
            try:
                await self.mixin_ws.run()
            except Exception as e:
                logger.exception(e)
        task = asyncio.create_task(start())
        await asyncio.gather(task)

    async def run_setup(self, index: int, key: Union[bytes, str], signers: list, nonce: int, timeout: int, send_message_fn):
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            result = await loop.run_in_executor(
                pool,
                protocol.setup,
                index, key, signers, nonce, timeout, send_message_fn
            )
            priv, pub = result
            priv = bytes.fromhex(priv)
            pub = bytes.fromhex(pub)
            self.db.write_poly(pub, priv)
            logger.info(result)

        await self.mixin_ws.ws.close()
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)    
        # self.loop.stop()
        logger.info('Done')
        #exit all async tasks

    async def start_setup(self, index: int, key: Union[bytes, str], signers: list, nonce: int, timeout: int, send_message_fn):
        # logger.info('%s', (index, key, signers, nonce, timeout, send_message_fn))
        if self.setup_start:
            return
        self.setup_start = True
        def send_message(msg_type, msg):
            return send_message_fn(msg_type, msg)
        setup_task = asyncio.create_task(self.run_setup(index, key, signers, nonce, timeout, send_message))
        await asyncio.sleep(1.0) #sleep a while to make sure setup go routine has started

    def send_message(self, msg_type: int, msg: bytes):
        loop = self.loop
        assert loop
        logger.info('+++msg_type:%s', msg_type)
        async def coro(msg_type, data):
            conversation = self.config.get_messenger_config().conversation
            data = base64.urlsafe_b64encode(data).rstrip(b'=')
            # logger.info(data)
            return await self.bot.send_text_message(conversation, data)
        fut = asyncio.run_coroutine_threadsafe(coro(msg_type, msg), loop)
        fut.result()

    async def on_message(self, msg):
        # logger.info(msg)
        if 'error' in msg:
            return
        action = msg["action"]
        if not action in ["ACKNOWLEDGE_MESSAGE_RECEIPT", "CREATE_MESSAGE", "LIST_PENDING_MESSAGES"]:
            logger.info("unknow action %s", action)
            return

        if action == "ACKNOWLEDGE_MESSAGE_RECEIPT":
            return

        if not action == "CREATE_MESSAGE":
            return

        data = msg["data"]
        msgid = data["message_id"]
        typeindata = data["type"]
        categoryindata = data["category"]
        user_id = data["user_id"]
        conversation_id = data["conversation_id"]
        if not conversation_id == self.config.get_messenger_config().conversation:
            return

        created_at = data["created_at"]
        # updated_at = data["updated_at"]

        await self.mixin_ws.echoMessage(msgid)

        logger.info('user_id %s', user_id)
        logger.info("created_at %s",created_at)

        if 'error' in msg:
            return

        if not categoryindata == "PLAIN_TEXT" and typeindata == "message":
            return

        data = data["data"]
        # logger.info(data)
        data = base64.b64decode(data)
        # logger.info('++++on_message:cmd %s', data)
        data = base64.urlsafe_b64decode(data+b'===')
        # logger.info(data)
        msg = message.decode_message(data)
        logger.info(msg.sender)
        if msg.action == message.EnumMessage.ActionSetup.value:
            logger.info('receive setup message')
            setup = message.decode_setup_bundle(msg.data)
            logger.info(setup)
            self.setup_actions[msg.sender] = setup
            logger.info('+++len(self.setup_actions): %s', len(self.setup_actions))
            self.nonce = setup.nonce
            if len(self.setup_actions) >= self.threshold:
                await self.start_setup(self.index, self.key, self.signers, setup.nonce, self.config.node_config.timeout, self.send_message)
        elif msg.action == message.EnumMessage.ActionDKGDeal.value:
            if not self.setup_start:
                nonce = int.from_bytes(msg.data[:8], 'big')
                await self.start_setup(self.index, self.key, self.signers, nonce, self.config.node_config.timeout, self.send_message)
            logger.info('+++++++ActionDKGDeal %s', self.setup_start)
            protocol.on_message(0, msg.data)
        elif msg.action == message.EnumMessage.ActionDKGResponse.value:
            logger.info('+++++++ActionDKGResponse')
            if self.setup_start:
                protocol.on_message(1, msg.data)
        elif msg.action == message.EnumMessage.ActionDKGJustify.value:
            logger.info('+++++++ActionDKGJustify')
            if self.setup_start:
                protocol.on_message(2, msg.data)

    async def setup_protocol(self):
        logger.info('setup start...')
        # await asyncio.sleep(30)
        # logger.info('+++finish')
        # r = self.p.finish()
        # logger.info('++++finish')
        # logger.info(r)
        # return
        
        conversation = self.config.get_messenger_config().conversation

        msg = self.p.deal()
        msg = message.make_message(self.key, message.EnumMessage.ActionDKGDeal.value, msg)
        data = base64.urlsafe_b64encode(msg).rstrip(b'=')
        r = await self.bot.send_text_message(conversation, data)
        logger.info('+++deal')
        await asyncio.sleep(self.config.node_config.timeout)

        logger.info('+++response')
        msg = self.p.response()
        if msg:
            msg = message.make_message(self.key, message.EnumMessage.ActionDKGResponse.value, msg)
            data = base64.urlsafe_b64encode(msg).rstrip(b'=')
            r = await self.bot.send_text_message(conversation, data)

        logger.info('+++response')
        await asyncio.sleep(self.config.node_config.timeout)

        logger.info('+++justif')
        msg = self.p.justif()
        logger.info(msg)
        if msg['just']:
            just = msg['just']
            just = bytes.fromhex(just)
            msg = message.make_message(self.key, message.EnumMessage.ActionDKGJustify.value, msg)
            data = base64.urlsafe_b64encode(msg).rstrip(b'=')
            r = await self.bot.send_text_message(conversation, data)

        logger.info('+++justif')
        await asyncio.sleep(self.config.node_config.timeout)

        logger.info('+++finish')
        r = self.p.finish()
        logger.info('++++finish')
        logger.info(r)