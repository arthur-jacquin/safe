// See LICENSE file for copyright and license details.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto.h"


#define WORD_ROTATE_LEFT(X, N)      (((X) << (N)) | ((X) >> (32 - (N))))
#define CHACHA_QUARTER_ROUND(A, B, C, D) ( \
    (A) += (B), (D) ^= (A), (D) = WORD_ROTATE_LEFT((D), 16), \
    (C) += (D), (B) ^= (C), (B) = WORD_ROTATE_LEFT((B), 12), \
    (A) += (B), (D) ^= (A), (D) = WORD_ROTATE_LEFT((D), 8), \
    (C) += (D), (B) ^= (C), (B) = WORD_ROTATE_LEFT((B), 7))


uint32_t
little_endian_bytes_to_word(const uint8_t bytes[4])
{
    return (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];
}

void
little_endian_word_to_bytes(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = word >> (8*0);
    bytes[1] = word >> (8*1);
    bytes[2] = word >> (8*2);
    bytes[3] = word >> (8*3);
}

void
chacha20_keystream(const uint8_t key[32], const uint8_t init_vector[16],
    uint8_t keystream[64])
{
    static const uint8_t CHACHA_CONSTANT[16] = "expand 32-byte k";
    uint32_t initial_state[16], state[16];

    // initialize state
    for (int i = 0; i < 4; i++)
        state[0 + i] = little_endian_bytes_to_word(CHACHA_CONSTANT + 4*i);
    for (int i = 0; i < 8; i++)
        state[4 + i] = little_endian_bytes_to_word(key + 4*i);
    for (int i = 0; i < 4; i++)
        state[12 + i] = little_endian_bytes_to_word(init_vector + 4*i);
    memcpy(initial_state, state, sizeof(initial_state));

    // scramble state
    for (int r = 0; r < 20; r += 2) {
        CHACHA_QUARTER_ROUND(state[0], state[4], state[8], state[12]);
        CHACHA_QUARTER_ROUND(state[1], state[5], state[9], state[13]);
        CHACHA_QUARTER_ROUND(state[2], state[6], state[10], state[14]);
        CHACHA_QUARTER_ROUND(state[3], state[7], state[11], state[15]);
        CHACHA_QUARTER_ROUND(state[0], state[5], state[10], state[15]);
        CHACHA_QUARTER_ROUND(state[1], state[6], state[11], state[12]);
        CHACHA_QUARTER_ROUND(state[2], state[7], state[8], state[13]);
        CHACHA_QUARTER_ROUND(state[3], state[4], state[9], state[14]);
    }

    // add resulting state and initial state to get the result
    for (int i = 0; i < 16; i++)
        little_endian_word_to_bytes(state[i] + initial_state[i],
            keystream + 4*i);
}

uint32_t
murmur3_hash(const uint8_t key[], size_t length, uint32_t seed)
{
    static const uint32_t C1 = 0xcc9e2d51, C2 = 0x1b873593, C3 = 0x85ebca6b,
        C4 = 0xc2b2ae35, M = 5, N = 0xe6546b64;
    static const uint8_t R1 = 15, R2 = 13, S1 = 16, S2 = 13;

    uint8_t buffer[4] = {0};
    uint32_t hash = seed, k;
    size_t remaining_length = length;

    for (; remaining_length >= 4; key += 4, remaining_length -= 4) {
        k = little_endian_bytes_to_word(key) * C1;
        hash ^= WORD_ROTATE_LEFT(k, R1) * C2;
        hash = WORD_ROTATE_LEFT(hash, R2) * M + N;
    }
    if (remaining_length) {
        for (size_t i = 0; i < remaining_length; i++) buffer[i] = key[i];
        k = little_endian_bytes_to_word(buffer) * C1;
        hash ^= WORD_ROTATE_LEFT(k, R1) * C2;
    }
    hash ^= length;
    hash = (hash ^ (hash >> S1)) * C3;
    hash = (hash ^ (hash >> S2)) * C4;
    hash = (hash ^ (hash >> S1));
    return hash;
}

void
murmur3_chained_hash(const uint8_t key[], size_t key_length, uint32_t seed,
    uint8_t hash[], size_t hash_length)
{
    // produce a hash of arbitrary length by repeateadly hashing key with
    // derived seed

    uint8_t buffer[4] = {0};
    size_t remaining_length = hash_length;

    for (; remaining_length >= 4; hash += 4, remaining_length -= 4) {
        seed = murmur3_hash(key, key_length, seed);
        little_endian_word_to_bytes(seed, hash);
    }
    if (remaining_length) {
        seed = murmur3_hash(key, key_length, seed);
        little_endian_word_to_bytes(seed, buffer);
        for (size_t i = 0; i < remaining_length; i++) hash[i] = buffer[i];
    }
}

void
text_symmetric_encryption(const struct text src, int encrypt,
    const uint8_t key[], size_t key_length, struct text *dest)
{
    // combination of a noncryptographic hash (selected for its good dispersion
    // and avalanche properties) and a cryptographically secure stream cipher:
    // variable length key --hash--> fixed-length key --cipher--> keystream

    size_t sum = 0;
    uint8_t chacha_key[32], keystream[64];
    const uint8_t *plaintext = encrypt ? src.text : dest->text;

    memcpy(dest->init_vector, src.init_vector, sizeof(dest->init_vector));
    murmur3_chained_hash(key, key_length, little_endian_bytes_to_word(
        src.init_vector + 12), chacha_key, sizeof(chacha_key));
    chacha20_keystream(chacha_key, src.init_vector, keystream);
    for (size_t i = 0; i < sizeof(dest->text); i++)
        dest->text[i] = src.text[i] ^ keystream[i + (i < 16 ? 0 : 32)];
    for (size_t i = 0; i < sizeof(src.text); i++)
        sum += plaintext[i];
    dest->length = (src.length + (encrypt ? 32 - (sum % 32) : (sum % 32))) % 32;
}
