#ifndef CRYPTO_STREAM_CHACHA20_XOR_H
#define CRYPTO_STREAM_CHACHA20_XOR_H 1

#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

#define crypto_stream_chacha20_xor_KEYBYTES crypto_stream_chacha20_KEYBYTES
#define crypto_stream_chacha20_xor_NONCEBYTES crypto_stream_chacha20_NONCEBYTES

#define crypto_stream_chacha20_BLOCKBYTES 64

// Packing? Alignment?

typedef struct crypto_stream_chacha20_xor_state {
    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
    uint8_t key[crypto_stream_chacha20_KEYBYTES];
    uint8_t next_block[crypto_stream_chacha20_BLOCKBYTES];
    uint8_t remainder;
    uint64_t block_counter;
} crypto_stream_chacha20_xor_state;

size_t
crypto_stream_chacha20_xor_keybytes(void);

size_t
crypto_stream_chacha20_xor_noncebytes(void);

size_t
crypto_stream_chacha20_xor_statebytes(void);

int
crypto_stream_chacha20_xor_init(crypto_stream_chacha20_xor_state *state,
                                unsigned const char nonce[crypto_stream_chacha20_NONCEBYTES],
                                unsigned const char key[crypto_stream_chacha20_KEYBYTES]);

int
crypto_stream_chacha20_xor_update(crypto_stream_chacha20_xor_state *state,
                                  unsigned char *c, const unsigned char *m,
                                  unsigned long long mlen);

int
crypto_stream_chacha20_xor_final(crypto_stream_chacha20_xor_state *state);

#ifdef __cplusplus
}
#endif

#endif
