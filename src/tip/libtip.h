/* Code generated by cmd/cgo; DO NOT EDIT. */

/* package tip-python */


#line 1 "cgo-builtin-export-prolog"

#include <stddef.h> /* for ptrdiff_t below */

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif

/* Start of preamble from import "C" comments.  */


#line 26 "lib.go"

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


#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif

extern void init_();
extern void say_hello_();
extern char* gen_key_();
extern char* crypto_get_public_key_(char* scalar);
extern char* crypto_public_key_from_bytes_(char* pub, int pub_len);
extern char* crypto_public_key_bytes_(char* pub);
extern struct ret_value* crypto_sign_(char* scalar, int scalar_length, char* msg, int msg_length);
extern char* crypto_public_key_from_base58_(char* pub);
extern struct ret_value* crypto_verify_(char* pub, char* msg, int msg_length, char* sig, int sig_length);
extern struct ret_value* crypto_encrypt_(char* pub, char* priv, char* msg, int msg_len);
extern struct ret_value* crypto_decrypt_(char* pub, char* priv, char* msg, int msg_len);
extern char* tbls_sign_(int index, char* priv, char* identity);
extern char* tbls_recover_(char* key, char* partials, char* commitments, int total_signers);
extern char* crypto_base64_encode_(char* msg, int msg_len);
extern int store_open_(char* db_path);
extern void store_close_(int db_index);
extern struct ret_value* store_get_(int db_index, char* key, int key_len);
extern struct ret_value* store_set_(int db_index, char* key, int key_len, char* val, int val_len, long int ttl);
extern struct ret_value* store_find_(int db_index, char* prefix, int prefix_len);
extern char* store_filter_(int db_index, char* prefix, int prefix_len, db_filter filter, void* extra);
extern char* store_guard_(int db_index, char* priv, char* identity, char* signature, char* data);
extern void callback_test_(callback filter, void* extra);
extern char* protocol_new_(int threshold, char* key, long unsigned int nonce, char* signers);
extern char* protocol_deal_(int index, long unsigned int nonce);
extern char* protocol_response_(int index);
extern char* protocol_justif_(int index);
extern char* protocol_finish_(int index);
extern char* protocol_on_deal_(int index, char* new_deal, int new_deal_len);
extern char* protocol_on_response_(int index, char* new_resp, int new_resp_len);
extern char* protocol_on_justification_(int index, char* new_justif, int new_justif_len);
extern char* protocol_on_message_(int msg_type, char* msg, size_t length, void* userdata);
extern char* protocol_setup_(int index, char* key, char* signers, long unsigned int nonce, int timeout, void* userdata, void* send_message_fn);

#ifdef __cplusplus
}
#endif