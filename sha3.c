#include "sha3.h"

// Function to compute SHA3-256 hash
void sha3_256_hash(const unsigned char *data, size_t data_len, unsigned char *output_hash) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();  // Create a new OpenSSL digest context
    if (mdctx == NULL) {
        fprintf(stderr, "Error initializing OpenSSL context\n");
        return;
    }

    // Initialize the hashing operation with SHA3-256
    if (EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) != 1) {
        fprintf(stderr, "Error initializing SHA3-256 digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Provide the data to be hashed
    if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
        fprintf(stderr, "Error updating SHA3-256 digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Finalize the hashing operation
    if (EVP_DigestFinal_ex(mdctx, output_hash, NULL) != 1) {
        fprintf(stderr, "Error finalizing SHA3-256 digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Clean up OpenSSL digest context
    EVP_MD_CTX_free(mdctx);
}

void print_hash(unsigned char* buf)
{
    for (int i = 0; i < SHA3_256_DIGEST_LENGTH; i++)
    {
        printf("%o", buf[i]);
    }

    printf("\n\n");
}