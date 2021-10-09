#ifndef SM3_HELPER_FP
#define SM3_HELPER_FP
#include <openssl/evp.h>

typedef EVP_MD_CTX* SM3_TPM_CTX;
#define SM3_SUCCESS 1
#define SM3_FAIL 0
# define SM3_DIGEST_LENGTH 32
# define SM3_WORD unsigned int

# define SM3_CBLOCK      64
# define SM3_LBLOCK      (SM3_CBLOCK/4)

typedef struct SM3state_st {
   SM3_WORD A, B, C, D, E, F, G, H;
   SM3_WORD Nl, Nh;
   SM3_WORD data[SM3_LBLOCK];
   unsigned int num;
} SM3_CTX;
int sm3_init(SM3_TPM_CTX *c);
int sm3_update(SM3_TPM_CTX *c, const void *data, size_t len);
int sm3_final(unsigned char *md, SM3_TPM_CTX *c);
#endif