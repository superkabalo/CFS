#pragma once

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define AES_KEYLEN 32 // 256 bits
#define AES_IVLEN 16 // 128 bits
#define AES_KEY_SIZE 256
#define AES_IV_SIZE 128

int aes_256_encrypt(const unsigned char *plaintext, int plaintext_len, 
                    const unsigned char *key, const unsigned char *iv, 
                    unsigned char **ciphertext, int *ciphertext_len);


unsigned char *get_user_key();

unsigned char *get_user_iv();

int aes_256_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char **plaintext, int *plaintext_len);