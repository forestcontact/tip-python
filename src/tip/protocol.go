package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/bls"
	"golang.org/x/crypto/sha3"
)

// Phaser must signal on its channel when the protocol should move to a next
// phase. Phase must be sequential: DealPhase (start), ResponsePhase,
// JustifPhase and then FinishPhase.
// Note that if the dkg protocol finishes before the phaser sends the
// FinishPhase, the protocol will not listen on the channel anymore. This can
// happen if there is no complaints, or if using the "FastSync" mode.
// Most of the times, user should use the TimePhaser when using the network, but
// if one wants to use a smart contract as a board, then the phaser can tick at
// certain blocks, or when the smart contract tells it.
type Phaser interface {
	NextPhase() chan dkg.Phase
}

// TimePhaser is a phaser that sleeps between the different phases and send the
// signal over its channel.
type TimePhaser struct {
	out   chan dkg.Phase
	sleep func(dkg.Phase)
}

func NewTimePhaser(p time.Duration) *TimePhaser {
	return NewTimePhaserFunc(func(dkg.Phase) { time.Sleep(p) })
}

func NewTimePhaserFunc(sleepPeriod func(dkg.Phase)) *TimePhaser {
	return &TimePhaser{
		out:   make(chan dkg.Phase, 4),
		sleep: sleepPeriod,
	}
}

func (t *TimePhaser) Start() {
	t.out <- dkg.DealPhase
	// log.Printf("++++DealPhase")
	t.sleep(dkg.DealPhase)
	t.out <- dkg.ResponsePhase
	// log.Printf("++++ResponsePhase")
	t.sleep(dkg.ResponsePhase)
	t.out <- dkg.JustifPhase
	// log.Printf("++++JustifPhase")
	t.sleep(dkg.JustifPhase)
	t.out <- dkg.FinishPhase
	// log.Printf("++++FinishPhase")
}

func (t *TimePhaser) NextPhase() chan dkg.Phase {
	return t.out
}

// Protocol contains the logic to run a DKG protocol over a generic broadcast
// channel, called Board. It handles the receival of packets, ordering of the
// phases and the termination. A protocol can be ran over a network, a smart
// contract, or anything else that is implemented via the Board interface.
type Protocol struct {
	dkg       *dkg.DistKeyGenerator
	canIssue  bool
	res       chan OptionResult
	skipVerif bool
	c         *dkg.Config

	deals   *set
	resps   *set
	justifs *set
}

// XXX TO DELETE
func printNodes(list []dkg.Node) string {
	var arr []string
	for _, node := range list {
		arr = append(arr, fmt.Sprintf("[%d : %s]", node.Index, node.Public))
	}
	return strings.Join(arr, "\n")
}

func NewProtocol(c *dkg.Config, skipVerification bool) (*Protocol, error) {
	dkg, err := dkg.NewDistKeyHandler(c)
	if err != nil {
		return nil, err
	}

	v := reflect.ValueOf(*dkg)
	y := v.FieldByName("canIssue")
	canIssue := y.Bool()

	p := &Protocol{
		dkg:       dkg,
		canIssue:  canIssue,
		res:       make(chan OptionResult, 1),
		skipVerif: skipVerification,
		c:         c,
	}

	p.deals = newSet()
	p.resps = newSet()
	p.justifs = newSet()

	return p, nil
}

func (p *Protocol) Deal(nonce uint64) ([]byte, error) {
	if !p.canIssue {
		return nil, nil
	}
	bundle, err := p.dkg.Deals()
	if err != nil {
		return nil, err
	}
	return encodeDealBundle(bundle, nonce), nil
}

func (p *Protocol) Response() ([]byte, error) {
	// log.Printf("++++Response")
	deals := p.deals.ToDeals()
	// log.Printf("++++Response %v", p.deals)
	bundle, err := p.dkg.ProcessDeals(deals)
	// log.Printf("++++Response %v, %v", bundle, err)
	if err != nil {
		return nil, err
	}

	if bundle == nil {
		return nil, nil
	}
	return encodeResponseBundle(bundle), err
}

func (p *Protocol) Justif() (*map[string]string, []byte, error) {
	res, just, err := p.dkg.ProcessResponses(p.resps.ToResponses())

	var _res map[string]string
	_res = nil
	if res != nil {
		commits := marshalCommitments(res.Key.Commits)
		share := marshalPrivShare(res.Key.Share)
		_res = map[string]string{"commits": hex.EncodeToString(commits), "share": hex.EncodeToString(share)}
	}

	if err != nil {
		return &_res, nil, err
	}

	if just != nil {
		return &_res, encodeJustificationBundle(just), err
	}
	return &_res, nil, err
}

func (p *Protocol) Finish() (commits []byte, share []byte, err error) {
	just := p.justifs.ToJustifications()
	// log.Printf("+++++++++++++Finish just: %d", len(just))
	res, err := p.dkg.ProcessJustifications(just)
	// log.Printf("+++++++++++++Finish res: %v %v", res.Key, err)
	if err != nil {
		return nil, nil, err
	}
	commits = marshalCommitments(res.Key.Commits)
	share = marshalPrivShare(res.Key.Share)
	// log.Printf("+++++++++++++Finish: %v %v", commits, share)
	return commits, share, err
}

func (p *Protocol) OnDeal(newDeal []byte) error {
	_, bundle, err := decodeDealBundle(newDeal)
	if err != nil {
		return err
	}
	err = p.verify(bundle)
	// log.Printf("++++++OnDeal err: %v", err)
	if err == nil {
		p.deals.Push(bundle)
	}
	return nil
}

func (p *Protocol) OnResponse(newResp []byte) error {
	bundle, err := decodeResponseBundle(newResp)
	if err != nil {
		return err
	}
	if err := p.verify(bundle); err == nil {
		p.resps.Push(bundle)
	}
	return nil
}

func (p *Protocol) OnJustification(newJust []byte) error {
	bundle, err := decodeJustificationBundle(newJust)
	if err != nil {
		return err
	}
	if err := p.verify(bundle); err == nil {
		p.justifs.Push(bundle)
	}
	return nil
}

func (p *Protocol) verify(packet dkg.Packet) error {
	if p.skipVerif {
		return nil
	}

	return dkg.VerifyPacketSignature(p.c, packet)
}

func (p *Protocol) finish(justifs []*dkg.JustificationBundle) {
	res, err := p.dkg.ProcessJustifications(justifs)
	p.res <- OptionResult{
		Error:  err,
		Result: res,
	}
}

type OptionResult struct {
	Result *dkg.Result
	Error  error
}

type set struct {
	vals map[dkg.Index]dkg.Packet
	bad  []dkg.Index
}

func newSet() *set {
	return &set{
		vals: make(map[dkg.Index]dkg.Packet),
	}
}

func (s *set) Push(p dkg.Packet) {
	hash := p.Hash()
	idx := p.Index()
	if s.isBad(idx) {
		// already misbehaved before
		return
	}
	prev, present := s.vals[idx]
	if present {
		if !bytes.Equal(prev.Hash(), hash) {
			// bad behavior - we evict
			delete(s.vals, idx)
			s.bad = append(s.bad, idx)
		}
		// same packet just rebroadcasted - all good
		return
	}
	s.vals[idx] = p
}

func (s *set) isBad(idx dkg.Index) bool {
	for _, i := range s.bad {
		if idx == i {
			return true
		}
	}
	return false
}

func (s *set) ToDeals() []*dkg.DealBundle {
	deals := make([]*dkg.DealBundle, 0, len(s.vals))
	for _, p := range s.vals {
		deals = append(deals, p.(*dkg.DealBundle))
	}
	return deals
}

func (s *set) ToResponses() []*dkg.ResponseBundle {
	resps := make([]*dkg.ResponseBundle, 0, len(s.vals))
	for _, p := range s.vals {
		resps = append(resps, p.(*dkg.ResponseBundle))
	}
	return resps
}

func (s *set) ToJustifications() []*dkg.JustificationBundle {
	justs := make([]*dkg.JustificationBundle, 0, len(s.vals))
	for _, p := range s.vals {
		justs = append(justs, p.(*dkg.JustificationBundle))
	}
	return justs
}

func (s *set) Len() int {
	return len(s.vals)
}

type SignerNode struct {
	Index  uint32 `json:"index"`
	Public string `json:"public"`
}

var protocols []*Protocol

func getNonce(signers []dkg.Node, nonce uint64) []byte {
	var data []byte
	for _, s := range signers {
		b := crypto.PublicKeyBytes(s.Public)
		data = append(data, b...)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], nonce)
	data = append(data, buf[:]...)
	sum := sha3.Sum256(data)
	return sum[:]
}

func ProtocolNew(threshold int, key string, nonce uint64, signers string) (int, error) {
	_key, err := crypto.PrivateKeyFromHex(key)
	if err != nil {
		return 0, err
	}

	_signers := []SignerNode{}
	err = json.Unmarshal([]byte(signers), &_signers)
	if err != nil {
		return 0, err
	}

	__signers := []dkg.Node{}
	for _, v := range _signers {
		pub, err := crypto.PubKeyFromBase58(v.Public)
		if err != nil {
			return 0, err
		}
		__signers = append(__signers, dkg.Node{Index: v.Index, Public: pub})
	}

	suite := bn256.NewSuiteG2()
	conf := &dkg.Config{
		Suite:     suite,
		Threshold: int(threshold),
		Longterm:  _key,
		Nonce:     getNonce(__signers, uint64(nonce)),
		Auth:      bls.NewSchemeOnG1(suite),
		FastSync:  false,
		NewNodes:  __signers,
	}

	if len(protocols) == 0 {
		protocols = append(protocols, nil)
	}
	protocol, err := NewProtocol(conf, false)
	if err != nil {
		return 0, err
	}
	protocols = append(protocols, protocol)
	return len(protocols) - 1, nil
}

func ProtocolDeal(index int, nonce uint64) ([]byte, error) {
	p := protocols[int(index)]
	bundle, err := p.Deal(uint64(nonce))
	if err != nil {
		return bundle, err
	}
	return bundle, err
}

func ProtocolResponse(index int) ([]byte, error) {
	p := protocols[int(index)]
	bundle, err := p.Response()
	return bundle, err
}

func ProtocolJustif(index int) (map[string]interface{}, error) {
	p := protocols[int(index)]
	res, just, err := p.Justif()
	if err != nil {
		return nil, err
	}

	ret := map[string]interface{}{}
	ret["res"] = res
	ret["just"] = hex.EncodeToString(just)
	return ret, nil
}

func ProtocolFinish(index int) (*[2]string, error) {
	p := protocols[int(index)]
	commits, share, err := p.Finish()
	if err != nil {
		return nil, err
	}
	arr := [2]string{hex.EncodeToString(commits), hex.EncodeToString(share)}
	return &arr, nil
}

func ProtocolOnDeal(index int, new_deal []byte) (bool, error) {
	p := protocols[int(index)]
	err := p.OnDeal(new_deal)
	if err != nil {
		return false, err
	}
	return true, nil
}

func ProtocolOnResponse(index int, new_resp []byte) (bool, error) {
	p := protocols[int(index)]
	err := p.OnResponse(new_resp)
	if err != nil {
		return false, err
	}
	return true, nil
}

func ProtocolOnJustification(index int, new_justif []byte) (bool, error) {
	p := protocols[int(index)]
	err := p.OnJustification(new_justif)
	if err != nil {
		return false, err
	}
	return true, nil
}
