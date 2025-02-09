// See LICENSE file for copyright and license details.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "random.h"


void
random_bytes(uint8_t dest[], size_t length)
{
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom) goto failure;
    size_t read = fread(dest, 1, length, urandom);
    if (fclose(urandom) == EOF) goto failure;
    if (read < length) goto failure;
    return;

failure: exit(EXIT_FAILURE);
}

void
random_bytes_bounded(uint8_t dest[], size_t length, uint8_t max)
{
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom) goto failure;
    uint8_t threshold = max * (256 / max);
    for (size_t i = 0; i < length; i++) {
        do {
            if (fread(dest + i, 1, 1, urandom) < 1) goto failure;
        } while (dest[i] >= threshold);
        dest[i] %= max;
    }
    if (fclose(urandom) == EOF) goto failure;
    return;

failure: exit(EXIT_FAILURE);
}
