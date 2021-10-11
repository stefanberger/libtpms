#ifndef SM4_HELPER_FP
#define SM4_HELPER_FP
#if ALG_SM4
#include <openssl/evp.h>
typedef EVP_CIPHER_CTX* SM4_KEY;
#define SM4_ENCRYPT 1
#define SM4_DECRYPT 0
#define SM4_SUCCESS 1
#define SM4_FAIL 0

int SM4_set_encrypt_key(const uint8_t *key, SM4_KEY *ks);
int SM4_set_decrypt_key(const uint8_t *key, SM4_KEY *ks);
void SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);
void SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);
void SM4_final(const SM4_KEY *ks);
#endif
#endif