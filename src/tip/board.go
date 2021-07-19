package main

import (
	"unsafe"

	"github.com/MixinNetwork/tip/signer"
	"github.com/drand/kyber"
	"github.com/drand/kyber/share/dkg"
)

/*
typedef void (*send_message)(int type, void *data, size_t length, void *userdata);

static void call_send_message(send_message fn, int type, void *data, size_t length, void *userdata) {
	fn(type, data, length, userdata);
}
*/
import "C"

const (
	MsgDeal     = 0
	MsgResponse = 1
	MsgJustify  = 2
)

type PythonBoard struct {
	nonce        uint64
	deals        chan dkg.DealBundle
	resps        chan dkg.ResponseBundle
	justs        chan dkg.JustificationBundle
	key          kyber.Scalar
	userdata     unsafe.Pointer
	send_message unsafe.Pointer
}

func NewPythonBoard(key kyber.Scalar, signers []dkg.Node, nonce uint64, userdata unsafe.Pointer, send_message_fn unsafe.Pointer) *PythonBoard {
	n := len(signers)
	return &PythonBoard{
		nonce:        nonce,
		deals:        make(chan dkg.DealBundle, n),
		resps:        make(chan dkg.ResponseBundle, n),
		justs:        make(chan dkg.JustificationBundle, n),
		key:          key,
		userdata:     userdata,
		send_message: send_message_fn,
	}
}

func (t *PythonBoard) PushDeals(db *dkg.DealBundle) {
	data := encodeDealBundle(db, t.nonce)
	msg := makeMessage(t.key, signer.MessageActionDKGDeal, data)
	t.SendMessage(MsgDeal, msg)
	// err := t.messenger.SendMessage(t.ctx, msg)
	// logger.Verbose("PushDeals", len(msg), err)
}

func (t *PythonBoard) IncomingDeal() <-chan dkg.DealBundle {
	return t.deals
}

func (t *PythonBoard) PushResponses(rb *dkg.ResponseBundle) {
	data := encodeResponseBundle(rb)
	msg := makeMessage(t.key, signer.MessageActionDKGResponse, data)
	t.SendMessage(MsgResponse, msg)
	// err := t.messenger.SendMessage(t.ctx, msg)
	// logger.Verbose("PushResponses", len(msg), err)
}

func (t *PythonBoard) IncomingResponse() <-chan dkg.ResponseBundle {
	return t.resps
}

func (t *PythonBoard) PushJustifications(jb *dkg.JustificationBundle) {
	data := encodeJustificationBundle(jb)
	msg := makeMessage(t.key, signer.MessageActionDKGJustify, data)
	t.SendMessage(MsgJustify, msg)
	// err := t.messenger.SendMessage(t.ctx, msg)
	// logger.Verbose("PushJustifications", len(msg), err)
}

func (t *PythonBoard) IncomingJustification() <-chan dkg.JustificationBundle {
	return t.justs
}

func (t *PythonBoard) SendMessage(msg_type int, msg []byte) {
	C.call_send_message(C.send_message(unsafe.Pointer(t.send_message)), C.int(msg_type), C.CBytes(msg), C.size_t(len(msg)), t.userdata)
}

func (t *PythonBoard) OnMessage(msg_type int, msg []byte) error {
	if msg_type == MsgDeal {
		_, bundle, err := decodeDealBundle(msg)
		if err != nil {
			return err
		}
		t.deals <- *bundle
		return err
	} else if msg_type == MsgResponse {
		bundle, err := decodeResponseBundle(msg)
		if err != nil {
			return err
		}
		t.resps <- *bundle
		return err
	} else if msg_type == MsgJustify {
		bundle, err := decodeJustificationBundle(msg)
		if err != nil {
			return err
		}
		t.justs <- *bundle
		return err
	}
	return nil
}
