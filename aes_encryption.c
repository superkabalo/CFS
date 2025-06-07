#include "aes_encryption.h"

// Function to encrypt plaintext using AES-256-CBC
int aes_256_encrypt(const unsigned char *plaintext, int plaintext_len, 
                    const unsigned char *key, const unsigned char *iv, 
                    unsigned char **ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int final_len;

    // Allocate memory for ciphertext (it will be larger than plaintext)
    *ciphertext = malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    if (*ciphertext == NULL) {
        fprintf(stderr, "Memory allocation failed for ciphertext\n");
        return -1;
    }

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
        free(*ciphertext);
        return -1;
    }

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Encryption initialization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext);
        return -1;
    }

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Encryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext);
        return -1;
    }
    *ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &final_len) != 1) {
        fprintf(stderr, "Encryption finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext);
        return -1;
    }
    *ciphertext_len += final_len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return 0; // Success
}
unsigned char *get_user_key() {
    static unsigned char key[AES_KEYLEN] = {0}; // Zero-initialized key buffer
    char key_input[AES_KEYLEN * 2 + 2]; // Max 64 hex chars (128 hex digits), +1 for null terminator

    printf("Enter a hexadecimal key (up to 64 characters, will be zero-padded if shorter): ");
    
    // Read user input
    if (fgets(key_input, sizeof(key_input), stdin) == NULL) {
        fprintf(stderr, "Error reading key input.\n");
        return NULL;
    }

    // Remove newline if present
    size_t input_len = strcspn(key_input, "\n");
    key_input[input_len] = '\0';

    // Check if input is empty
    if (input_len == 0) {
        fprintf(stderr, "Error: Key cannot be empty.\n");
        return NULL;
    }

    // Validate that all characters are hexadecimal
    for (size_t i = 0; i < input_len; i++) {
        if (!isxdigit(key_input[i])) {
            fprintf(stderr, "Invalid key format. Must be hexadecimal (0-9, a-f, A-F).\n");
            return get_user_key();
        }
    }

    // Pad input with zeroes if it is shorter than 64 hex chars (32 bytes)
    if (input_len < AES_KEYLEN * 2) {
        size_t pad_len = (AES_KEYLEN * 2) - input_len; // Calculate how much padding is needed
        memset(key_input + input_len, '0', pad_len);  // Pad with '0' up to 64 chars
        key_input[AES_KEYLEN * 2] = '\0'; // Null-terminate the string
        input_len = AES_KEYLEN * 2; // New input length is 64 hex chars
    }

    // Convert hex string to binary (32 bytes for AES-256 key)
    for (size_t i = 0; i < AES_KEYLEN; i++) {
        if (sscanf(&key_input[i * 2], "%2hhx", &key[i]) != 1) {
            fprintf(stderr, "Invalid key conversion.\n");
            return NULL;
        }
    }

    printf("Key successfully set. Using %d bytes (zero-padded if needed).\n", AES_KEYLEN);
    return key;
}
unsigned char *get_user_iv() {
    static unsigned char iv[AES_IVLEN] = {0}; // Zero-initialized IV buffer
    char iv_input[AES_IVLEN * 2 + 2]; // Max 32 hex chars (64 hex digits), +1 for null terminator

    printf("Enter a hexadecimal IV (up to 32 characters, will be zero-padded if shorter): ");
    
    // Read user input
    if (fgets(iv_input, sizeof(iv_input), stdin) == NULL) {
        fprintf(stderr, "Error reading IV input.\n");
        return NULL;
    }

    // Remove newline if present
    size_t input_len = strcspn(iv_input, "\n");
    iv_input[input_len] = '\0';

    // Check if input is empty
    if (input_len == 0) {
        fprintf(stderr, "Error: IV cannot be empty.\n");
        return NULL;
    }

    // Validate that all characters are hexadecimal
    for (size_t i = 0; i < input_len; i++) {
        if (!isxdigit(iv_input[i])) {
            fprintf(stderr, "Invalid IV format. Must be hexadecimal (0-9, a-f, A-F).\n");
            return get_user_iv();
        }
    }

    // Pad input with zeroes if it is shorter than 32 hex chars (16 bytes)
    if (input_len < AES_IVLEN * 2) {
        size_t pad_len = (AES_IVLEN * 2) - input_len; // Calculate how much padding is needed
        memset(iv_input + input_len, '0', pad_len);  // Pad with '0' up to 32 chars
        iv_input[AES_IVLEN * 2] = '\0'; // Null-terminate the string
        input_len = AES_IVLEN * 2; // New input length is 32 hex chars
    }

    // Convert hex string to binary (16 bytes for AES-IV)
    for (size_t i = 0; i < AES_IVLEN; i++) {
        if (sscanf(&iv_input[i * 2], "%2hhx", &iv[i]) != 1) {
            fprintf(stderr, "Invalid IV conversion.\n");
            return NULL;
        }
    }

    printf("IV successfully set. Using %d bytes (zero-padded if needed).\n", AES_IVLEN);
    return iv;
}

// Function to decrypt ciphertext using AES-256-CBC
int aes_256_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char **plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len, final_len;

    // Allocate memory for plaintext (it will be at most the size of ciphertext)
    *plaintext = malloc(ciphertext_len);
    if (*plaintext == NULL) {
        fprintf(stderr, "Memory allocation failed for plaintext\n");
        return -1;
    }

    // Create and initialize the decryption context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
        free(*plaintext);
        return -1;
    }

    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Decryption initialization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "Decryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }
    *plaintext_len = len;

    // Finalize decryption (handles padding)
    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &final_len) != 1) {
        fprintf(stderr, "Decryption finalization failed (wrong key or corrupted data?)\n");
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }
    *plaintext_len += final_len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return 0; // Success
}
