// See LICENSE file for copyright and license details.

#ifndef RANDOM_H
#define RANDOM_H

#include <stddef.h>
#include <stdint.h>


void random_bytes(uint8_t dest[], size_t length);
void random_bytes_bounded(uint8_t dest[], size_t length, uint8_t max);

#endif // RANDOM_H
