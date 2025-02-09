// See LICENSE file for copyright and license details.

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>


struct text {
    uint8_t init_vector[16], text[32];
    size_t length; // number of valid bytes in plaintext, encrypted if text is
};


uint32_t little_endian_bytes_to_word(const uint8_t bytes[4]);
void little_endian_word_to_bytes(uint32_t word, uint8_t bytes[4]);

void chacha20_keystream(const uint8_t key[32], const uint8_t init_vector[16],
    uint8_t keystream[64]);

uint32_t murmur3_hash(const uint8_t key[], size_t length, uint32_t seed);
void murmur3_chained_hash(const uint8_t key[], size_t key_length, uint32_t seed,
    uint8_t hash[], size_t hash_length);

void text_symmetric_encryption(const struct text src, int encrypt,
    const uint8_t key[], size_t key_length, struct text *dest);

#endif // CRYPTO_H
