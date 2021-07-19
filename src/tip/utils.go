package main

import (
	"encoding/binary"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/signer"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/mod"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
)

func PrivateKeyFromBytes(seed []byte) (kyber.Scalar, error) {
	suite := bn256.NewSuiteG2()
	scalar := suite.Scalar().SetBytes(seed)
	return scalar, nil
}

func unmarshalCommitments(b []byte) []kyber.Point {
	var commits []kyber.Point
	for i, l := 0, len(b)/128; i < l; i++ {
		point, err := crypto.PubKeyFromBytes(b[i*128 : (i+1)*128])
		if err != nil {
			panic(err)
		}
		commits = append(commits, point)
	}
	return commits
}

func marshalCommitments(commits []kyber.Point) []byte {
	var data []byte
	for _, p := range commits {
		b := crypto.PublicKeyBytes(p)
		data = append(data, b...)
	}
	return data
}

func unmarshalPrivShare(b []byte) *share.PriShare {
	var ps share.PriShare
	ps.V = mod.NewInt64(0, bn256.Order).SetBytes(b[4:])
	ps.I = int(binary.BigEndian.Uint32(b[:4]))
	return &ps
}

func marshalPrivShare(ps *share.PriShare) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(ps.I))
	b := crypto.PrivateKeyBytes(ps.V)
	return append(buf[:], b...)
}

func makeMessage(key kyber.Scalar, action int, data []byte) []byte {
	point := crypto.PublicKey(key)
	msg := &signer.Message{
		Action: action,
		Sender: crypto.PublicKeyString(point),
		Data:   data,
	}
	b := encodeMessage(msg)
	sig, err := crypto.Sign(key, b)
	if err != nil {
		panic(err)
	}
	msg.Signature = sig
	return encodeMessage(msg)
}

func encodeMessage(m *signer.Message) []byte {
	enc := NewEncoder()
	enc.WriteInt(m.Action)
	enc.WriteFixedBytes([]byte(m.Sender))
	enc.WriteFixedBytes(m.Data)
	enc.WriteFixedBytes(m.Signature)
	return enc.buf.Bytes()
}

func MarshalKey(ps *share.PriShare, commits []kyber.Point) ([]byte, []byte) {
	priv := marshalPrivShare(ps)
	pub := marshalCommitments(commits)
	return priv, pub
}
