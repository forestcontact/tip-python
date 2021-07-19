# cython: c_string_type=str, c_string_encoding=utf8

from cython.operator cimport dereference as deref, preincrement as inc
from cpython.bytes cimport PyBytes_AS_STRING
from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.map cimport map
from libcpp cimport bool
from libc.stdlib cimport malloc, free

from typing import Union
import json

cdef extern from * :
    ctypedef long long int64_t
    ctypedef unsigned long long uint64_t

cdef extern from "<Python.h>":
    ctypedef long long PyLongObject

    object PyBytes_FromStringAndSize(const char* str, int size)
    int _PyLong_AsByteArray(PyLongObject* v, unsigned char* bytes, size_t n, int little_endian, int is_signed)

cdef extern from "libtip.h" nogil:

    cdef struct ret_value:
        void *data;
        int len;
        int error;

    cdef struct buffer:
        void *data;
        int len;

    cdef struct pair:
        buffer key;
        buffer value;

    void init_()
    char* gen_key_()
    char* crypto_get_public_key_(char* scalar)

    ret_value* crypto_sign_(char* scalar, int scalar_length, char* msg, int msg_length);
    ret_value* crypto_verify_(char* pub, char* msg, int msg_length, char* sig, int sig_length)
    char* crypto_public_key_from_base58_(char* pub)

    ret_value* crypto_encrypt_(char* pub, char* priv, char* msg, int msg_len)
    ret_value* crypto_decrypt_(char* pub, char* priv, char* msg, int msg_len)

    char* tbls_recover_(char* key, char* partials, char* commitments, int total_signers)
    char* tbls_sign_(int index, char* priv, char* identity)

    char* crypto_public_key_bytes_(char *pub)
    char* crypto_base64_encode_(char* msg, int msg_len)

    int store_open_(char* db_path);
    void store_close_(int);
    ret_value* store_get_(int ptr, char* key, int key_len);
    ret_value* store_set_(int ptr, char* key, int key_len, char* val, int val_len, int64_t ttl);

    ret_value* store_find_(int ptr, char* prefix, int prefix_len)

    char* store_guard_(int db_index, char* priv, char* identity, char* signature, char* data);

    char* protocol_new_(int threshold, char* key, long unsigned int nonce, char* signers);
    char* protocol_deal_(int index, long unsigned int nonce);
    char* protocol_response_(int index);
    char* protocol_justif_(int index);
    char* protocol_finish_(int index);
    char* protocol_on_deal_(int index, char* new_deal, int new_deal_len);
    char* protocol_on_response_(int index, char* new_resp, int new_resp_len);
    char* protocol_on_justification_(int index, char* new_justif, int new_justif_len);

    char* protocol_setup_(int index, char* key, char* signers, long unsigned int nonce, int timeout, void* userdata, void* send_message_fn)
    char* protocol_on_message_(int msg_type, char* msg, size_t length, void* userdata);

cdef extern from "libtip.h":
    ctypedef int (*db_filter)(char* key, int key_len, char* value, int value_len, void* extra)
    char* store_filter_(int ptr, char* prefix, int prefix_len, db_filter filter, void* extra) with gil

    ctypedef int (*callback)(void* extra)
    void callback_test_(callback filter, void* extra) nogil

    void Py_INCREF(object)


cdef int call_python_func(void *extra) with gil:
    obj = <object>extra
    print('++++++++=extra:', obj)
    func = obj[0]
    args = obj[1]
    func(args)
    return 1



cdef int python_send_message(int message_type, const void *data, size_t length, void *userdata) with gil:
    fn = <object>userdata
    _data = PyBytes_FromStringAndSize(<char *>data, length)
    fn(message_type, _data)
    return 1

def init():
    return init_()

cdef int db_filter_(char* key, int key_len, char* value, int value_len, void *extra):
    call_back = <object>extra
    _key = PyBytes_FromStringAndSize(key, key_len)
    _value = PyBytes_FromStringAndSize(value, value_len)
    return call_back(_key, _value)

cdef object _(char *_ret):
    ret = <object>_ret
    free(_ret)
    return ret

cdef parse_ret(ret_value* ret):
    if <void *>ret == <void *>0:
        return None

    ret2 = None
    if not <void *>ret.data == <void *>0:
        ret2 = PyBytes_FromStringAndSize(<char *>ret.data, ret.len)
        free(<void *>ret.data)
    else:
        pass
    error = ret.error
    free(<void *>ret)
    if error:
        raise Exception(ret2)
    return ret2

cdef build_buffer(buffer* buf):
    if <void *>buf[0].data == <void *>0 or buf[0].len == 0:
        return None
    return PyBytes_FromStringAndSize(<char *>buf.data, buf.len)

cdef parse_return_array(ret_value* ret):
    cdef pair **pairs
    cdef pair *tmp

    if <void *>ret == <void *>0:
        return None

    error = ret.error
    if error:
        ret2 = None
        if not <void *>ret.data == <void *>0:
            ret2 = PyBytes_FromStringAndSize(<char *>ret.data, ret.len)
            free(<void *>ret.data)
        else:
            pass
        free(<void *>ret)
        raise Exception(ret2)

    python_pairs = []
    pairs = <pair **>ret.data
    for i in range(ret.len):
        tmp = pairs[i]
        print(tmp[0].key.len, tmp[0].value.len)
        key = build_buffer(&tmp[0].key)
        value = build_buffer(&tmp[0].value)
        python_pairs.append((key, value))

        if tmp.key.len:
            free(<void *>tmp.key.data)
        if tmp.value.len:
            free(<void *>tmp.value.data)

    if ret.len:
        free(<void *>ret.data)
    return python_pairs

def gen_key():
    cdef char *ret
    ret = gen_key_()
    return _(ret)

def crypto_get_public_key(scalar: Union[bytes, str]):
    cdef char* ret
    ret = crypto_get_public_key_(scalar)
    return _(ret)

def crypto_sign(scalar: bytes, msg: Union[bytes, str]):
    cdef ret_value* ret
    ret = crypto_sign_(scalar, len(scalar), msg, len(msg))
    return parse_ret(ret)

def crypto_verify(char* pub, msg: bytes,  sig: Union[bytes, str]):
    cdef ret_value* ret
    ret = crypto_verify_(pub, msg, len(msg), sig, len(sig))
    r = parse_ret(ret)
    if r == b'success':
        return True
    return False

def crypto_public_key_from_base58(char* pub):
    cdef char* ret
    ret = crypto_public_key_from_base58_(pub)
    return _(ret)

def crypto_encrypt(char* pub, char* priv, msg: Union[bytes, str]) -> bytes:
    cdef ret_value* ret
    ret = crypto_encrypt_(pub, priv, msg, len(msg))
    return parse_ret(ret)

def crypto_decrypt(char* pub, char* priv, msg: Union[bytes, str]) -> bytes:
    cdef ret_value* ret
    ret = crypto_decrypt_(pub, priv, msg, len(msg))
    return parse_ret(ret)

def tbls_recover(char* key, char* partials, char* commitments, int total_signers):
    cdef char* ret
    ret = tbls_recover_(key, partials, commitments, total_signers)
    return _(ret)

def tbls_sign(int index, char* priv, char* identity):
    cdef char* ret
    ret = tbls_sign_(index, priv, identity)
    return _(ret)

def crypto_public_key_bytes(char *pub):
    cdef char *ret
    ret = crypto_public_key_bytes_(pub)
    return _(ret)

# char* crypto_base64_encode_(char* msg, int msg_len)
def crypto_base64_encode(msg: Union[bytes, str]):
    cdef char *ret
    ret = crypto_base64_encode_(msg, len(msg))
    return _(ret)

def store_open(char* db_path):
    cdef ret_value* ret
    return store_open_(db_path)

def store_close(int ptr):
    store_close_(ptr)

def store_get(int ptr, key: Union[bytes, str]):
    cdef ret_value* ret
    ret = store_get_(ptr, key, len(key))
    return parse_ret(ret)

def store_set(int ptr, key: Union[bytes, str], val: Union[bytes, str], ttl: int):
    cdef ret_value* ret
    ret = store_set_(ptr, key, len(key), val, len(val), ttl)
    return parse_ret(ret)

def store_find(int ptr, prefix: Union[bytes, str]):
    cdef ret_value* ret
    ret = store_find_(ptr, prefix, len(prefix))
    return parse_return_array(ret)

def store_filter(int ptr, prefix: Union[bytes, str], fn):
    cdef char *ret
    ret = store_filter_(ptr, prefix, len(prefix), <db_filter>db_filter_, <void *><object>fn)
    return _(ret)

def store_guard(int db_index, char* priv, char* identity, char* signature, char* data):
    cdef char *ret
    ret = store_guard_(db_index, priv, identity, signature, data)
    return _(ret)

def protocol_new(int threshold, char* key, long unsigned int nonce, char* signers):
    cdef char* ret
    ret = protocol_new_(threshold, key, nonce, signers)
    return _(ret)

def protocol_deal(int ptr, nonce):
    cdef char* ret
    ret = protocol_deal_(ptr, nonce)
    return _(ret)

def protocol_response(int ptr):
    cdef char* ret
    ret = protocol_response_(ptr)
    return _(ret)

def protocol_justif(int ptr):
    cdef char* ret
    ret = protocol_justif_(ptr)
    return _(ret)

def protocol_finish(int ptr):
    cdef char* ret
    ret = protocol_finish_(ptr)
    return _(ret)

def protocol_on_deal(int ptr, new_deal: bytes):
    cdef char* ret
    ret = protocol_on_deal_(ptr, new_deal, len(new_deal))
    return _(ret)

def protocol_on_response(int ptr, response: bytes):
    cdef char* ret
    ret = protocol_on_response_(ptr, response, len(response))
    return _(ret)

def protocol_on_justification(int ptr, justification: bytes):
    cdef char* ret
    ret = protocol_on_justification_(ptr, justification, len(justification))
    return _(ret)

def protocol_setup(index: int, key: Union[bytes, str], signers, nonce: int, timeout: int, fn):
    cdef char* ret
    cdef void *_fn
    cdef int _index
    cdef char *_key
    cdef char *_signers
    cdef uint64_t _nonce
    cdef int _timeout

    print('+++args:', index, key, type(signers), signers, nonce, timeout, fn)

    _index = index
    _key = key
    signers = json.dumps(signers)
    _signers = signers
    _nonce = nonce
    _timeout = timeout
    _fn = <void *><object>fn

    with nogil:
        ret = protocol_setup_(_index, _key, _signers, _nonce, _timeout, _fn, <void *>python_send_message)
    return _(ret)

def callback_test(obj):
    cdef callback cb
    cdef void* o
    cb = <callback>call_python_func
    print('++++++++callback_test:', obj)
    o = <void*><object>obj
    with nogil:
        callback_test_(cb, o)

def protocol_on_message(msg_type: int, msg: bytes, userdata):
    cdef char *ret
    ret = protocol_on_message_(msg_type, msg, len(msg), <void *>userdata)
    return _(ret)
