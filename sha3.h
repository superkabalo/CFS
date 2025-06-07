#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define SHA3_256_DIGEST_LENGTH 32  // SHA3-256 produces a 256-bit (32-byte) hash

void sha3_256_hash(const unsigned char *data, size_t data_len, unsigned char *output_hash);

void print_hash(unsigned char* buf);