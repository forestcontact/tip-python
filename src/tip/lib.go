package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/keeper"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/sign/tbls"
	"github.com/drand/kyber/util/random"
)

/*
struct ret_value {
	void *data;
	int len;
	int error;
};

struct buffer {
	void *data;
	int len;
};

struct pair {
	struct buffer key;
	struct buffer value;
};

static void set_value(void *pp, int index, void* v) {
	((void **)pp)[index] = v;
}

typedef int (*db_filter)(char* key, int key_len, char* value, int value_len, void* extra);

static int call_filter(db_filter fn, void* key, int key_len, void* value, int value_len, void* extra) {
	return fn((char*)key, key_len, (char*)value, value_len, extra);
}

typedef int (*callback)(void* extra);

static int call_function(callback fn, void* extra) {
	return fn(extra);
}

typedef void (*send_message)(int type, const char *data, size_t length, void *userdata);

static void call_send_message(send_message fn, int type, const char *data, size_t length, void *userdata) {
	fn(type, data, length, userdata);
}

*/
import "C"

//export init_
func init_() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func get_return_value(val []byte) *C.struct_ret_value {
	ret := (*C.struct_ret_value)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_ret_value{}))))
	if val != nil {
		ret.data = C.CBytes(val)
		ret.len = C.int(len(val))
	} else {
		ret.data = unsafe.Pointer(uintptr(0))
		ret.len = 0
	}

	ret.error = 0
	return ret
}

func get_return_success() *C.struct_ret_value {
	ret := (*C.struct_ret_value)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_ret_value{}))))
	ret.data = unsafe.Pointer(uintptr(0))
	ret.len = 0
	ret.error = 0
	return ret
}

func get_return_error(err error) *C.struct_ret_value {
	ret := (*C.struct_ret_value)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_ret_value{}))))
	pc, fn, line, _ := runtime.Caller(1)
	error := fmt.Sprintf("[error] in %s[%s:%d] %v", runtime.FuncForPC(pc).Name(), fn, line, err)
	data := map[string]interface{}{"error": error}
	_data, _ := json.Marshal(data)

	ret.data = C.CBytes(_data)
	ret.len = C.int(len(_data))
	ret.error = 1
	return ret
}

func build_return_value(keys [][]byte, values [][]byte) *C.struct_ret_value {
	ret := (*C.struct_ret_value)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_ret_value{}))))
	ret2 := (**C.struct_pair)(C.malloc(C.size_t(len(keys)) * 8))

	for i, v := range keys {
		pair := (*C.struct_pair)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_pair{}))))
		pair.key.data = C.CBytes(v)
		pair.key.len = C.int(len(v))

		value := values[i]
		pair.value.data = C.CBytes(value)
		pair.value.len = C.int(len(value))
		C.set_value(unsafe.Pointer(ret2), C.int(i), unsafe.Pointer(pair))
	}

	ret.data = unsafe.Pointer(ret2)
	ret.len = C.int(len(values))
	ret.error = 0
	return ret
}

func build_return_array(arr [][]byte) *C.struct_ret_value {
	ret := (*C.struct_ret_value)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_ret_value{}))))
	ret2 := (**C.void)(C.malloc(C.size_t(len(arr)) * 8))

	for i, v := range arr {
		C.set_value(unsafe.Pointer(ret2), C.int(i), unsafe.Pointer(C.CBytes(v)))
	}

	ret.data = unsafe.Pointer(ret2)
	ret.len = C.int(len(arr))
	ret.error = 0
	return ret
}

func renderData(data interface{}) *C.char {
	ret := map[string]interface{}{"data": data}
	result, _ := json.Marshal(ret)
	return C.CString(string(result))
}

func renderError(err error) *C.char {
	pc, fn, line, _ := runtime.Caller(1)
	error := fmt.Sprintf("[error] in %s[%s:%d] %v", runtime.FuncForPC(pc).Name(), fn, line, err)
	ret := map[string]interface{}{"error": error}
	result, _ := json.Marshal(ret)
	return C.CString(string(result))
}

//export say_hello_
func say_hello_() {
	fmt.Println("hello,world from go lang")
}

//export gen_key_
func gen_key_() *C.char {
	suite := bn256.NewSuiteG2()
	scalar := suite.Scalar().Pick(random.New())
	point := suite.Point().Mul(scalar, nil)

	msg := []byte("tip")
	scheme := bls.NewSchemeOnG1(suite)
	sig, err := scheme.Sign(scalar, msg)
	if err != nil {
		return renderError(err)
	}

	err = scheme.Verify(point, msg, sig)
	if err != nil {
		return renderError(err)
	}

	pub := crypto.PublicKeyString(point)
	data := map[string]interface{}{"scalar": scalar.String(), "public": pub}
	return renderData(data)
}

//export crypto_get_public_key_
func crypto_get_public_key_(scalar *C.char) *C.char {
	_scalar := C.GoString(scalar)
	__scalar, err := crypto.PrivateKeyFromHex(_scalar)
	if err != nil {
		return renderError(err)
	}
	pub := crypto.PublicKey(__scalar)
	return renderData(crypto.PublicKeyString(pub))
}

//export crypto_public_key_from_bytes_
func crypto_public_key_from_bytes_(pub *C.char, pub_len C.int) *C.char {
	_pub, err := crypto.PubKeyFromBytes(C.GoBytes(unsafe.Pointer(pub), pub_len))
	if err != nil {
		return renderError(err)
	}
	return renderData(crypto.PublicKeyString(_pub))
}

//export crypto_public_key_bytes_
func crypto_public_key_bytes_(pub *C.char) *C.char {
	_pub, err := crypto.PubKeyFromBase58(C.GoString(pub))
	if err != nil {
		return renderError(err)
	}

	__pub := crypto.PublicKeyBytes(_pub)
	if err != nil {
		return renderError(err)
	}
	return renderData(hex.EncodeToString(__pub))
}

//export crypto_sign_
func crypto_sign_(scalar *C.char, scalar_length C.int, msg *C.char, msg_length C.int) *C.struct_ret_value {
	_scalar := C.GoBytes(unsafe.Pointer(scalar), scalar_length)
	__scalar, err := PrivateKeyFromBytes(_scalar)
	if err != nil {
		return get_return_error(err)
	}

	_msg := C.GoBytes(unsafe.Pointer(msg), msg_length)
	scheme := bls.NewSchemeOnG1(bn256.NewSuiteG2())
	ret, err := scheme.Sign(__scalar, _msg)
	if err != nil {
		return get_return_error(err)
	}
	// fmt.Printf("++++sign: %v\n", ret)
	return get_return_value(ret)
}

//export crypto_public_key_from_base58_
func crypto_public_key_from_base58_(pub *C.char) *C.char {
	_pub := C.GoString(pub)
	__pub, err := crypto.PubKeyFromBase58(_pub)
	if err != nil {
		return renderError(err)
	}
	___pub := crypto.PublicKeyBytes(__pub)
	return renderData(hex.EncodeToString(___pub))
}

//export crypto_verify_
func crypto_verify_(pub *C.char, msg *C.char, msg_length C.int, sig *C.char, sig_length C.int) *C.struct_ret_value {
	_pub := C.GoString(pub)
	__pub, err := crypto.PubKeyFromBase58(_pub)
	if err != nil {
		return get_return_error(err)
	}

	_msg := C.GoBytes(unsafe.Pointer(msg), msg_length)
	_sig := C.GoBytes(unsafe.Pointer(sig), sig_length)

	scheme := bls.NewSchemeOnG1(bn256.NewSuiteG2())
	err = scheme.Verify(__pub, _msg, _sig)
	if err != nil {
		return get_return_value([]byte("fail"))
	} else {
		return get_return_value([]byte("success"))
	}
}

//export crypto_encrypt_
func crypto_encrypt_(pub *C.char, priv *C.char, msg *C.char, msg_len C.int) *C.struct_ret_value {
	_pub, err := crypto.PubKeyFromBase58(C.GoString(pub))
	if err != nil {
		return (*C.struct_ret_value)(unsafe.Pointer(uintptr(0)))
	}

	_priv, err := crypto.PrivateKeyFromHex(C.GoString(priv))
	if err != nil {
		return (*C.struct_ret_value)(unsafe.Pointer(uintptr(0)))
	}

	_msg := C.GoBytes(unsafe.Pointer(msg), msg_len)
	__msg := crypto.Encrypt(_pub, _priv, _msg)
	return get_return_value(__msg)
}

//export crypto_decrypt_
func crypto_decrypt_(pub *C.char, priv *C.char, msg *C.char, msg_len C.int) *C.struct_ret_value {
	_pub, err := crypto.PubKeyFromBase58(C.GoString(pub))
	if err != nil {
		return (*C.struct_ret_value)(unsafe.Pointer(uintptr(0)))
	}

	_priv, err := crypto.PrivateKeyFromHex(C.GoString(priv))
	if err != nil {
		return (*C.struct_ret_value)(unsafe.Pointer(uintptr(0)))
	}

	_msg := C.GoBytes(unsafe.Pointer(msg), msg_len)
	__msg := crypto.Decrypt(_pub, _priv, _msg)

	return get_return_value(__msg)
}

//export tbls_sign_
func tbls_sign_(index C.int, priv *C.char, identity *C.char) *C.char {
	_priv, err := crypto.PrivateKeyFromHex(C.GoString(priv))
	if err != nil {
		return renderError(err)
	}
	__priv := share.PriShare{I: int(index), V: _priv}

	scheme := tbls.NewThresholdSchemeOnG1(bn256.NewSuiteG2())
	partial, err := scheme.Sign(&__priv, []byte(C.GoString(identity)))
	if err != nil {
		panic(err)
	}
	return renderData(hex.EncodeToString(partial))
}

//export tbls_recover_
func tbls_recover_(key *C.char, partials *C.char, commitments *C.char, total_signers C.int) *C.char {
	var _partials []string
	var _commitments []string

	err := json.Unmarshal([]byte(C.GoString(partials)), &_partials)
	if err != nil {
		return renderError(err)
	}

	__partials := make([][]byte, len(_partials))
	for i, s := range _partials {
		partial, err := hex.DecodeString(s)
		if err != nil {
			return renderError(err)
		}
		__partials[i] = partial
	}

	err = json.Unmarshal([]byte(C.GoString(commitments)), &_commitments)
	if err != nil {
		return renderError(err)
	}

	__commitments := make([]kyber.Point, len(_commitments))
	for i, s := range _commitments {
		commitment, err := crypto.PubKeyFromBase58(s)
		if err != nil {
			return renderError(err)
		}
		__commitments[i] = commitment
	}

	_key, err := crypto.PrivateKeyFromHex(C.GoString(key))
	if err != nil {
		return renderError(err)
	}

	suite := bn256.NewSuiteG2()
	id := crypto.PublicKeyString(crypto.PublicKey(_key))
	scheme := tbls.NewThresholdSchemeOnG1(bn256.NewSuiteG2())
	poly := share.NewPubPoly(suite, suite.Point().Base(), __commitments)
	sig, err := scheme.Recover(poly, []byte(id), __partials, len(__commitments), int(total_signers))
	if err != nil {
		return renderError(err)
	}
	return renderData(hex.EncodeToString(sig))
}

//export crypto_base64_encode_
func crypto_base64_encode_(msg *C.char, msg_len C.int) *C.char {
	_msg := base64.RawURLEncoding.EncodeToString(C.GoBytes(unsafe.Pointer(msg), msg_len))
	return renderData(string(_msg))
}

var gDbArray []*BadgerStorage

//export store_open_
func store_open_(db_path *C.char) C.int {
	var err error
	index := 0

	_db_path := C.GoString(db_path)
	g_db, err := OpenBadger(nil, &BadgerConfiguration{Dir: _db_path})
	if err != nil {
		return C.int(-1)
	}

	//let index start from 1
	if len(gDbArray) == 0 {
		gDbArray = append(gDbArray, nil)
	}

	for i, v := range gDbArray[1:] {
		if v == nil {
			index = i
			break
		}
	}

	if index == 0 {
		gDbArray = append(gDbArray, nil)
		index = len(gDbArray) - 1
	}

	gDbArray[index] = g_db

	return C.int(index)
}

//export store_close_
func store_close_(db_index C.int) {
	gDbArray[int(db_index)].Close()
	gDbArray[int(db_index)] = nil
}

//export store_get_
func store_get_(db_index C.int, key *C.char, key_len C.int) *C.struct_ret_value {
	_key := C.GoBytes(unsafe.Pointer(key), key_len)
	val, err := gDbArray[int(db_index)].Get(_key)
	if err != nil {
		return get_return_error(err)
	}
	return get_return_value(val)
}

//export store_set_
func store_set_(db_index C.int, key *C.char, key_len C.int, val *C.char, val_len C.int, ttl C.long) *C.struct_ret_value {
	_key := C.GoBytes(unsafe.Pointer(key), key_len)
	_val := C.GoBytes(unsafe.Pointer(val), val_len)
	err := gDbArray[int(db_index)].Set(_key, _val, int64(ttl))
	if err != nil {
		return get_return_error(err)
	}
	return get_return_value(nil)
}

//export store_find_
func store_find_(db_index C.int, prefix *C.char, prefix_len C.int) *C.struct_ret_value {
	keys, values, err := gDbArray[int(db_index)].Find(C.GoBytes(unsafe.Pointer(prefix), prefix_len))
	if err != nil {
		fmt.Printf("++++++++find, err %v\n", err)
		return get_return_error(err)
	}
	return build_return_value(keys, values)
}

//export store_filter_
func store_filter_(db_index C.int, prefix *C.char, prefix_len C.int, filter C.db_filter, extra *C.void) *C.char {
	_prefix := C.GoBytes(unsafe.Pointer(prefix), prefix_len)
	err := gDbArray[int(db_index)].Filter(_prefix, func(key []byte, value []byte) bool {
		ret := C.call_filter(filter, C.CBytes(key), C.int(len(key)), C.CBytes(value), C.int(len(value)), unsafe.Pointer(extra))
		if C.int(ret) == 0 {
			return false
		} else {
			return true
		}
	})

	if err != nil {
		return renderError(err)
	}
	return renderData(true)
}

//export store_guard_
func store_guard_(db_index C.int, priv *C.char, identity *C.char, signature *C.char, data *C.char) *C.char {
	s := gDbArray[int(db_index)]
	_priv, err := crypto.PrivateKeyFromHex(C.GoString(priv))
	if err != nil {
		return renderError(err)
	}
	resp, err := keeper.Guard(s, _priv, C.GoString(identity), C.GoString(signature), C.GoString(data))
	if err != nil {
		return renderError(err)
	}

	if resp == nil {
		return renderData(nil)
	}

	r := map[string]interface{}{}
	r["available"] = resp.Available
	r["nonce"] = resp.Nonce
	r["identity"] = crypto.PublicKeyString(resp.Identity)
	return renderData(r)
}

//export callback_test_
func callback_test_(filter C.callback, extra *C.void) {
	// C.call_function(filter, unsafe.Pointer(extra))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		// time.Sleep(time.Second * 1)
		// _gstate := python.PyGILState_Ensure()
		C.call_function(filter, unsafe.Pointer(extra))
		// python.PyGILState_Release(_gstate)
		log.Printf("%v", unsafe.Pointer(extra))
		wg.Done()
	}()

	go func() {
		// time.Sleep(time.Second * 1)
		// _gstate := python.PyGILState_Ensure()
		C.call_function(filter, unsafe.Pointer(extra))
		// python.PyGILState_Release(_gstate)
		log.Printf("%v", unsafe.Pointer(extra))
		wg.Done()
	}()
	wg.Wait()
}

//export protocol_new_
func protocol_new_(threshold C.int, key *C.char, nonce C.ulong, signers *C.char) *C.char {
	index, err := ProtocolNew(int(threshold), C.GoString(key), uint64(nonce), C.GoString(signers))
	if err != nil {
		return renderError(err)
	}
	return renderData(strconv.Itoa(index))
}

//export protocol_deal_
func protocol_deal_(index C.int, nonce C.ulong) *C.char {
	bundle, err := ProtocolDeal(int(index), uint64(nonce))
	if err != nil {
		return renderError(err)
	}
	return renderData(hex.EncodeToString(bundle))
}

//export protocol_response_
func protocol_response_(index C.int) *C.char {
	bundle, err := ProtocolResponse(int(index))
	if err != nil {
		return renderError(err)
	}
	if bundle == nil {
		return renderData([]byte{})
	}
	return renderData(hex.EncodeToString(bundle))
}

//export protocol_justif_
func protocol_justif_(index C.int) *C.char {
	m, err := ProtocolJustif(int(index))
	if err != nil {
		return renderError(err)
	}
	return renderData(m)
}

//export protocol_finish_
func protocol_finish_(index C.int) *C.char {
	arr, err := ProtocolFinish(int(index))
	if err != nil {
		return renderError(err)
	}
	return renderData(arr)
}

//export protocol_on_deal_
func protocol_on_deal_(index C.int, new_deal *C.char, new_deal_len C.int) *C.char {
	b, err := ProtocolOnDeal(int(index), C.GoBytes(unsafe.Pointer(new_deal), new_deal_len))
	if err != nil {
		return renderError(err)
	}
	return renderData(b)
}

//export protocol_on_response_
func protocol_on_response_(index C.int, new_resp *C.char, new_resp_len C.int) *C.char {
	b, err := ProtocolOnResponse(int(index), C.GoBytes(unsafe.Pointer(new_resp), new_resp_len))
	if err != nil {
		return renderError(err)
	}
	return renderData(b)
}

//export protocol_on_justification_
func protocol_on_justification_(index C.int, new_justif *C.char, new_justif_len C.int) *C.char {
	b, err := ProtocolOnJustification(int(index), C.GoBytes(unsafe.Pointer(new_justif), new_justif_len))
	if err != nil {
		return renderError(err)
	}
	return renderData(b)
}

var gBoard *PythonBoard

func getBoard(userdata *C.void) *PythonBoard {
	return gBoard
}

//export protocol_on_message_
func protocol_on_message_(msg_type C.int, msg *C.char, length C.size_t, userdata *C.void) *C.char {
	board := getBoard(userdata)
	// log.Printf("+++++++++board: %v", board)
	err := board.OnMessage(int(msg_type), C.GoBytes(unsafe.Pointer(msg), C.int(length)))
	// log.Printf("+++++++++board: err %v", err)
	if err != nil {
		return renderError(err)
	}
	return renderData(true)
}

func protocol_setup(index int, key kyber.Scalar, signers []dkg.Node, nonce uint64, timeout int, userdata *C.void, send_message_fn *C.void) (priv []byte, pub []byte, err error) {
	suite := bn256.NewSuiteG2()
	conf := &dkg.Config{
		Suite:     suite,
		Threshold: len(signers)*2/3 + 1,
		Longterm:  key,
		Nonce:     getNonce(signers, nonce),
		Auth:      bls.NewSchemeOnG1(suite),
		FastSync:  false,
		NewNodes:  signers,
	}

	gBoard = NewPythonBoard(key, signers, nonce, unsafe.Pointer(userdata), unsafe.Pointer(send_message_fn))

	phaser := dkg.NewTimePhaserFunc(func(dkg.Phase) {
		time.Sleep(time.Second * time.Duration(timeout))
	})
	protocol, err := dkg.NewProtocol(conf, gBoard, phaser, false)
	if err != nil {
		return nil, nil, err
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		phaser.Start()
		// wg.Done()
	}()

	go func() error {
		resCh := protocol.WaitEnd()
		optRes := <-resCh
		log.Printf("++++++++++++WaitEnd return")
		if optRes.Error != nil {
			err = optRes.Error
			return err
		}
		res := optRes.Result
		if i := res.Key.PriShare().I; i != index {
			err = fmt.Errorf("private share index malformed %d %d", index, i)
			return err
		}
		priv, pub = MarshalKey(res.Key.PriShare(), res.Key.Commitments())
		log.Printf("%v %v", hex.EncodeToString(priv), hex.EncodeToString(pub))
		wg.Done()
		return nil
	}()
	wg.Wait()
	return priv, pub, err
}

//export protocol_setup_
func protocol_setup_(index C.int, key *C.char, signers *C.char, nonce C.ulong, timeout C.int, userdata *C.void, send_message_fn *C.void) *C.char {
	_key, err := crypto.PrivateKeyFromHex(C.GoString(key))
	if err != nil {
		return renderError(err)
	}

	_signers := []SignerNode{}
	err = json.Unmarshal([]byte(C.GoString(signers)), &_signers)
	if err != nil {
		return renderError(err)
	}

	__signers := []dkg.Node{}
	for _, signer := range _signers {
		pub, err := crypto.PubKeyFromBase58(signer.Public)
		if err != nil {
			return renderError(err)
		}
		__signers = append(__signers, dkg.Node{Index: uint32(signer.Index), Public: pub})
	}
	priv, pub, err := protocol_setup(int(index), _key, __signers, uint64(nonce), int(timeout), userdata, send_message_fn)
	if err != nil {
		return renderError(err)
	}
	return renderData([]interface{}{hex.EncodeToString(priv), hex.EncodeToString(pub)})
}
