#define CFS_FILE_SIGNATURE_SIZE 3  // string length + 1 for null terminator
#define CFS_FILE_SIGNATURE "CFS"
#include "sha3.h"

typedef struct file_headers
{
    // CFS file signature
    char signature[CFS_FILE_SIGNATURE_SIZE];
    // key and iv hash
    unsigned char key_hash[SHA3_256_DIGEST_LENGTH];
    unsigned char iv_hash[SHA3_256_DIGEST_LENGTH];
    // length of the ciphertext
    int ciphertext_len;
} file_headers;

int checkFileSignature(char* buf);