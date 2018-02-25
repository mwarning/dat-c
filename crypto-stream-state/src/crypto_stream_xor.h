#ifndef CRYPTO_STREAM_XOR_H
#define CRYPTO_STREAM_XOR_H 1


#include <sodium.h>
#include "crypto_stream_xsalsa20_xor.h"

#ifdef __cplusplus
extern "C" {
#endif

#define crypto_stream_xor_KEYBYTES crypto_stream_KEYBYTES
#define crypto_stream_xor_NONCEBYTES crypto_stream_NONCEBYTES

typedef crypto_stream_xsalsa20_xor_state crypto_stream_xor_state;

size_t
crypto_stream_xor_keybytes(void);

size_t
crypto_stream_xor_noncebytes(void);

size_t
crypto_stream_xor_statebytes(void);

int
crypto_stream_xor_init(crypto_stream_xor_state *state,
                       unsigned const char nonce[crypto_stream_NONCEBYTES],
                       unsigned const char key[crypto_stream_KEYBYTES]);

int
crypto_stream_xor_update(crypto_stream_xor_state *state,
                         unsigned char *c, const unsigned char *m,
                         unsigned long long mlen);

int
crypto_stream_xor_final(crypto_stream_xor_state *state);

#ifdef __cplusplus
}
#endif

#endif
