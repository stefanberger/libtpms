/********************************************************************************/
/*										*/
/*			       OpenSSL helper functions				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2019					*/
/*										*/
/********************************************************************************/

#include "Tpm.h"
#include "ExpDCache_fp.h"
#include "Helpers_fp.h"
#include "BnToOsslMath_fp.h"
#include "TpmMath_Util_fp.h"

#include "config.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/core_names.h>
# include <openssl/param_build.h>
#endif

#if USE_OPENSSL_FUNCTIONS_SSKDF
# include <openssl/kdf.h>
# include <openssl/core_names.h>
#endif

typedef const EVP_CIPHER *(*evpfunc)(void);

/* to enable RSA_check_key() on private keys set to != 0 */
#ifndef DO_RSA_CHECK_KEY
#define DO_RSA_CHECK_KEY 0
#endif


// Prototypes for older and newer OpenSSL implementation support
#if USE_OPENSSL_FUNCTIONS_RSA
static int
BuildRSAKey(EVP_PKEY **ppkey, // OUT
            const BIGNUM *N, const BIGNUM *E, const BIGNUM *D,
            const BIGNUM *P, const BIGNUM *Q,
            const BIGNUM *DP, const BIGNUM *DQ, const BIGNUM *QInv);
#endif

#if USE_OPENSSL_FUNCTIONS_SYMMETRIC

#if ALG_TDES
TPM_RC
OpenSSLCryptGenerateKeyDes(
                           TPMT_SENSITIVE *sensitive    // OUT: sensitive area
                          )
{
    TPM_RC         retVal = TPM_RC_SUCCESS;
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return TPM_RC_MEMORY;

    pAssert(sizeof(sensitive->sensitive.sym.t.buffer) >= 3 * sizeof(DES_cblock));

    if (EVP_CipherInit_ex(ctx, EVP_des_ede3(), NULL, NULL, NULL, 0) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_RAND_KEY, 0,
                            sensitive->sensitive.sym.t.buffer) != 1)
        ERROR_EXIT(TPM_RC_NO_RESULT);

 Exit:
    EVP_CIPHER_CTX_free(ctx);

    return retVal;
}
#endif // ALG_TDES

#define __NUM_ALGS      4 /* AES, TDES, Camellia, SM4 */
#define __NUM_MODES     5 /* CTR, OFB, CBC, CFB, ECB */
#define __NUM_KEYSIZES  3 /* 128, 192, 256 */

static const EVP_CIPHER *evp_cipher_cache[__NUM_ALGS][__NUM_MODES][__NUM_KEYSIZES] = {
    { { NULL, } },
};

static const EVP_CIPHER *
GetCachedEVPCipher(
                   evpfunc       evpFunc,      // IN
                   size_t        algIdx,       // IN algorithm Index for the cache
                   TPM_ALG_ID    mode,         // IN mode
                   size_t        keySizeIdx    // IN
                   )
{
    size_t modeIdx = mode - ALG_CTR_VALUE;
    const EVP_CIPHER *evp_cipher;

    pAssert(algIdx < __NUM_ALGS &&
	    modeIdx < __NUM_MODES &&
	    keySizeIdx < __NUM_KEYSIZES);

    evp_cipher = evp_cipher_cache[algIdx][modeIdx][keySizeIdx];
    if (evp_cipher == NULL) {
	evp_cipher = evpFunc();
	evp_cipher_cache[algIdx][modeIdx][keySizeIdx] = evp_cipher;
    }

    return evp_cipher;
}

#undef __NUM_KEYSIZES
#undef __NUM_MODES
#undef __NUM_ALGS

const EVP_CIPHER *
GetEVPCipher(TPM_ALG_ID    algorithm,       // IN
             UINT16        keySizeInBits,   // IN
             TPM_ALG_ID    mode,            // IN
             const BYTE   *key,             // IN
             BYTE         *keyToUse,        // OUT same as key or stretched key
             UINT16       *keyToUseLen      // IN/OUT
             )
{
    int i;
    UINT16 keySizeInBytes = keySizeInBits / 8;
    evpfunc evpfn = NULL;
    size_t algIdx;

    // key size to array index: 128 -> 0, 192 -> 1, 256 -> 2
    i = (keySizeInBits >> 6) - 2;
    if (i < 0 || i > 2)
        return NULL;

    pAssert(*keyToUseLen >= keySizeInBytes);
    memcpy(keyToUse, key, keySizeInBytes);

    switch (algorithm) {
#if ALG_AES
    case TPM_ALG_AES:
        algIdx = 0;
        *keyToUseLen = keySizeInBytes;

        switch (mode) {
#if ALG_CTR
        case TPM_ALG_CTR:
            evpfn = (evpfunc []){EVP_aes_128_ctr, EVP_aes_192_ctr,
                                 EVP_aes_256_ctr}[i];
            break;
#endif
#if ALG_OFB
        case TPM_ALG_OFB:
            evpfn = (evpfunc[]){EVP_aes_128_ofb, EVP_aes_192_ofb,
                                EVP_aes_256_ofb}[i];
            break;
#endif
#if ALG_CBC
        case TPM_ALG_CBC:
            evpfn = (evpfunc[]){EVP_aes_128_cbc, EVP_aes_192_cbc,
                                EVP_aes_256_cbc}[i];
            break;
#endif
#if ALG_CFB
        case TPM_ALG_CFB:
            evpfn = (evpfunc[]){EVP_aes_128_cfb, EVP_aes_192_cfb,
                                EVP_aes_256_cfb}[i];
            break;
#endif
#if ALG_ECB
        case TPM_ALG_ECB:
            evpfn = (evpfunc[]){EVP_aes_128_ecb, EVP_aes_192_ecb,
                                EVP_aes_256_ecb}[i];
            break;
#endif
        }
        break;
#endif
#if ALG_TDES
    case TPM_ALG_TDES:
        algIdx = 1;
        if (keySizeInBits == 128) {
            pAssert(*keyToUseLen >= BITS_TO_BYTES(192));
            // stretch the key
            memcpy(&keyToUse[16], &keyToUse[0], 8);
            *keyToUseLen = BITS_TO_BYTES(192);
        }

        switch (mode) {
#if ALG_CTR
        case TPM_ALG_CTR:
            evpfn = (evpfunc[]){EVP_des_ede3, EVP_des_ede3, NULL}[i];
            break;
#endif
#if ALG_OFB
        case TPM_ALG_OFB:
            evpfn = (evpfunc[]){EVP_des_ede3_ofb, EVP_des_ede3_ofb, NULL}[i];
            break;
#endif
#if ALG_CBC
        case TPM_ALG_CBC:
            evpfn = (evpfunc[]){EVP_des_ede3_cbc, EVP_des_ede3_cbc, NULL}[i];
            break;
#endif
#if ALG_CFB
        case TPM_ALG_CFB:
            evpfn = (evpfunc[]){EVP_des_ede3_cfb64, EVP_des_ede3_cfb64, NULL}[i];
            break;
#endif
#if ALG_ECB
        case TPM_ALG_ECB:
            evpfn = (evpfunc[]){EVP_des_ede3_ecb, EVP_des_ede3_ecb, NULL}[i];
            break;
#endif
        }
        break;
#endif

#if ALG_SM4
    case TPM_ALG_SM4:
        algIdx = 2;
        *keyToUseLen = keySizeInBytes;

        switch (mode) {
#if ALG_CTR
        case TPM_ALG_CTR:
            evpfn = (evpfunc[]){EVP_sm4_ctr, NULL, NULL}[i];
            break;
#endif
#if ALG_OFB
        case TPM_ALG_OFB:
            evpfn = (evpfunc[]){EVP_sm4_ofb, NULL, NULL}[i];
            break;
#endif
#if ALG_CBC
        case TPM_ALG_CBC:
            evpfn = (evpfunc[]){EVP_sm4_cbc, NULL, NULL}[i];
            break;
#endif
#if ALG_CFB
        case TPM_ALG_CFB:
            evpfn = (evpfunc[]){EVP_sm4_cfb, NULL, NULL}[i];
            break;
#endif
#if ALG_ECB
        case TPM_ALG_ECB:
            evpfn = (evpfunc[]){EVP_sm4_ecb, NULL, NULL}[i];
            break;
#endif
        }
        break;
#endif

#if ALG_CAMELLIA
    case TPM_ALG_CAMELLIA:
        algIdx = 3;
        *keyToUseLen = keySizeInBytes;

        switch (mode) {
#if ALG_CTR
        case TPM_ALG_CTR:
            evpfn = (evpfunc []){EVP_camellia_128_ctr, EVP_camellia_192_ctr,
                                 EVP_camellia_256_ctr}[i];
            break;
#endif
#if ALG_OFB
        case TPM_ALG_OFB:
            evpfn = (evpfunc[]){EVP_camellia_128_ofb, EVP_camellia_192_ofb,
                                EVP_camellia_256_ofb}[i];
            break;
#endif
#if ALG_CBC
        case TPM_ALG_CBC:
            evpfn = (evpfunc[]){EVP_camellia_128_cbc, EVP_camellia_192_cbc,
                                EVP_camellia_256_cbc}[i];
            break;
#endif
#if ALG_CFB
        case TPM_ALG_CFB:
            evpfn = (evpfunc[]){EVP_camellia_128_cfb, EVP_camellia_192_cfb,
                                EVP_camellia_256_cfb}[i];
            break;
#endif
#if ALG_ECB
        case TPM_ALG_ECB:
            evpfn = (evpfunc[]){EVP_camellia_128_ecb, EVP_camellia_192_ecb,
                                EVP_camellia_256_ecb}[i];
            break;
#endif
        }
        break;
#endif
    }

    if (evpfn == NULL) {
        MemorySet(keyToUse, 0, *keyToUseLen);
        return NULL;
    }

    /* get cached result of evpfn() */
    return GetCachedEVPCipher(evpfn, algIdx, mode, i);
}

TPM_RC DoEVPGetIV(
                  EVP_CIPHER_CTX    *ctx,    // IN: required context
                  unsigned char     *iv,     // IN: pointer to buffer for IV
                  size_t             iv_len  // IN: size of the buffer
                  )
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_ptr(OSSL_CIPHER_PARAM_UPDATED_IV, &iv, iv_len),
        OSSL_PARAM_END
    };
    if (EVP_CIPHER_CTX_get_params(ctx, params) != 1)
        return TPM_RC_FAILURE;
#else
    const unsigned char *c_iv;

    c_iv = EVP_CIPHER_CTX_iv(ctx);
    if (!c_iv)
        return TPM_RC_FAILURE;
    memcpy(iv, c_iv, iv_len);
#endif // OPENSSL_VERSION_NUMBER

    return 0;
}

#endif // USE_OPENSSL_FUNCTIONS_SYMMETRIC

#if USE_OPENSSL_FUNCTIONS_EC
BOOL
OpenSSLEccGetPrivate(
                     bigNum             dOut,  // OUT: the qualified random value
                     const EC_GROUP    *G,     // IN:  the EC_GROUP to use
                     const UINT32       requestedBits // IN: if not 0, then dOut must have that many bits
                    )
{
    BOOL           OK = FALSE;
    const BIGNUM  *D;
    EC_KEY        *eckey = EC_KEY_new();
    UINT32         requestedBytes = BITS_TO_BYTES(requestedBits);
    int            repeats = 0;
    int            maxRepeats;
    int            numBytes;

    pAssert(G != NULL);

    if (!eckey)
        return FALSE;

    if (EC_KEY_set_group(eckey, G) != 1)
        goto Exit;

    maxRepeats = 8;
    // non-byte boundary order'ed curves, like NIST P521, need more loops to
    // have a result with topmost byte != 0
    if (requestedBits & 7)
        maxRepeats += (9 - (requestedBits & 7));

    while (true) {
        if (EC_KEY_generate_key(eckey) == 1) {
            D = EC_KEY_get0_private_key(eckey);
            // if we need a certain amount of bytes and we are below a threshold
            // of loops, check the number of bytes we have, otherwise take the
            // result
            if ((requestedBytes != 0) && (repeats < maxRepeats)) {
                numBytes = BN_num_bytes(D);
                if ((int)requestedBytes != numBytes) {
                    // result does not have enough bytes
                    repeats++;
                    continue;
                }
                // result is sufficient
            }
            OK = OsslToTpmBn(dOut, D);
        }
        break;
    }

 Exit:
    EC_KEY_free(eckey);

    return OK;
}
#endif // USE_OPENSSL_FUNCTIONS_EC

#if USE_OPENSSL_FUNCTIONS_RSA

static const struct hnames {
    const char *name;
    TPM_ALG_ID hashAlg;
} hnames[HASH_COUNT + 1] = {
    {
#if ALG_SHA1
        .name     = "sha1",
        .hashAlg  = ALG_SHA1_VALUE,
    }, {
#endif
#if ALG_SHA256
        .name     = "sha256",
        .hashAlg  = ALG_SHA256_VALUE,
    }, {
#endif
#if ALG_SHA384
        .name     = "sha384",
        .hashAlg  = ALG_SHA384_VALUE,
    }, {
#endif
#if ALG_SHA512
        .name     = "sha512",
        .hashAlg  = ALG_SHA512_VALUE,
    }, {
#endif
        .name     = NULL,
    }
};
#if HASH_COUNT != ALG_SHA1 + ALG_SHA256 + ALG_SHA384 + ALG_SHA512
# error Missing entry in hnames array!
#endif

LIB_EXPORT const char *
GetDigestNameByHashAlg(const TPM_ALG_ID hashAlg)
{
    unsigned i;

    for (i = 0; i < HASH_COUNT; i++) {
        if (hashAlg == hnames[i].hashAlg)
            return hnames[i].name;
    }
    return NULL;
}

static BOOL
ComputePrivateExponentD_Euler(
		       const BIGNUM   *P,      // IN: first prime (size is 1/2 of bnN)
		       const BIGNUM   *Q,      // IN: second prime (size is 1/2 of bnN)
		       const BIGNUM   *E,      // IN: the public exponent
		       const BIGNUM   *N,      // IN: the public modulus
		       BIGNUM        **D       // OUT:
                       )
{
    BOOL    pOK = FALSE;
    BIGNUM *phi;
    BN_CTX *ctx;
    //
    // compute Phi = (p - 1)(q - 1) = pq - p - q + 1 = n - p - q + 1
    phi = BN_dup(N);
    ctx = BN_CTX_new();
    if (phi && ctx) {
        pOK = BN_sub(phi, phi, P);
        pOK = pOK && BN_sub(phi, phi, Q);
        pOK = pOK && BN_add_word(phi, 1);
        // Compute the multiplicative inverse d = 1/e mod Phi
        BN_set_flags(phi, BN_FLG_CONSTTIME); // phi is secret
        pOK = pOK && (*D = BN_mod_inverse(NULL, E, phi, ctx)) != NULL;
    }
    BN_CTX_free(ctx);
    BN_clear_free(phi);

    return pOK;
}

static BOOL
ComputePrivateExponentD_Carmichael(
			    const BIGNUM   *P,      // IN: first prime (size is 1/2 of bnN)
			    const BIGNUM   *Q,      // IN: second prime (size is 1/2 of bnN)
			    const BIGNUM   *E,      // IN: the public exponent
			    BIGNUM        **D       // OUT:
                           )
{
    BOOL   pOK = FALSE;
    BN_CTX *ctx;
    BIGNUM *pm1, *qm1, *pm1qm1, *gcd, *lcm;

    ctx = BN_CTX_new();
    if (!ctx)
        return FALSE;

    BN_CTX_start(ctx);
    pm1 = BN_CTX_get(ctx);
    qm1 = BN_CTX_get(ctx);
    pm1qm1 = BN_CTX_get(ctx);
    gcd = BN_CTX_get(ctx);
    lcm = BN_CTX_get(ctx);
    if (pm1 && qm1 && pm1qm1 && gcd && lcm) {
        BN_set_flags(pm1, BN_FLG_CONSTTIME);
        BN_set_flags(qm1, BN_FLG_CONSTTIME);
        BN_set_flags(pm1qm1, BN_FLG_CONSTTIME);
        BN_set_flags(gcd, BN_FLG_CONSTTIME);
        BN_set_flags(lcm, BN_FLG_CONSTTIME);

        /* Carmichael */
        pOK = BN_sub(pm1, P, BN_value_one());
        pOK = pOK && BN_sub(qm1, Q, BN_value_one());
        pOK = pOK && BN_mul(pm1qm1, pm1, qm1, ctx);
        pOK = pOK && BN_gcd(gcd, pm1, qm1, ctx);
        pOK = pOK && BN_div(lcm, NULL, pm1qm1, gcd, ctx);
        pOK = pOK && (*D = BN_mod_inverse(NULL, E, lcm, ctx)) != NULL;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return pOK;
}

static BOOL
ComputePrivateExponentD(
			const BIGNUM   *P,      // IN: first prime (size is 1/2 of bnN)
			const BIGNUM   *Q,      // IN: second prime (size is 1/2 of bnN)
			const BIGNUM   *E,      // IN: the public exponent
			const BIGNUM   *N,      // IN: the public modulus
			BIGNUM        **D       // OUT:
                       )
{
    int nbits = BN_num_bits(N);
    /* like OpenSSL:
     *  < 2048 bits               : Euler totient function
     * >= 2048 bits & e >= 0x10000: Carmichael function
     */
    if (nbits >= 2048 && BN_num_bits(E) > 16) {
       if (ComputePrivateExponentD_Carmichael(P, Q, E, D) == FALSE)
           return FALSE;
       /* D too small? A key generated following SP800-56B rev 1
        * 6.3.1.1 step 3 should not exist -> fall back to Euler
        */
       if (BN_num_bits(*D) <= (nbits >> 1))
           return ComputePrivateExponentD_Euler(P, Q, E, N, D);
       return TRUE;
    } else {
       return ComputePrivateExponentD_Euler(P, Q, E, N, D);
    }
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

/* Build an RSA key from the given BIGUMs. The caller must always free
 * the passed BIGNUMs.
 */
static int
BuildRSAKey(EVP_PKEY **ppkey,
            const BIGNUM *N, const BIGNUM *E, const BIGNUM *D,
            const BIGNUM *P, const BIGNUM *Q,
            const BIGNUM *DP, const BIGNUM *DQ, const BIGNUM *QInv)
{
    OSSL_PARAM_BLD *bld = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM *params = NULL;
    int selection;
    int ret = 0;

    if (N && E && D) {
        selection = EVP_PKEY_KEYPAIR;
    } else if (N && E) {
        selection = EVP_PKEY_PUBLIC_KEY;
    } else {
        return 0;
    }

    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) == NULL ||
        (bld = OSSL_PARAM_BLD_new()) == NULL)
        goto error;

    if (N && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, N) != 1)
        goto error;
    if (E && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, E) != 1)
        goto error;
    if (D && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, D) != 1)
        goto error;
    if (P && Q && DP && DQ && QInv &&
        (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, P) != 1 ||
         OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, Q) != 1 ||
         OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, DP) != 1 ||
         OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, DQ) != 1 ||
         OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, QInv) != 1))
        goto error;

    if ((params = OSSL_PARAM_BLD_to_param(bld)) == NULL ||
        EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, ppkey, selection, params) != 1)
        goto error;

    ret = 1;

error:
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}

#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

/* Build an RSA key from the given BIGUMs. The caller must always free
 * the passed BIGNUMs.
 */
static int
BuildRSAKey(EVP_PKEY **ppkey, // OUT
            const BIGNUM *N, const BIGNUM *E, const BIGNUM *D,
            const BIGNUM *P, const BIGNUM *Q,
            const BIGNUM *DP, const BIGNUM *DQ, const BIGNUM *QInv)
{
    BIGNUM *p, *q, *dP, *dQ, *qInv;
    BIGNUM *n = BN_dup(N);
    BIGNUM *e = BN_dup(E);
    BIGNUM *d = BN_dup(D);
    RSA *rsa;

    if ((N && !n) || (E && !e) || (D && !d))
        goto error_free_ned;

    if (P && Q && DP && DQ && QInv) {
        p = BN_dup(P);
        q = BN_dup(Q);
        dP = BN_dup(DP);
        dQ = BN_dup(DQ);
        qInv = BN_dup(QInv);
        if (!p || !q || !dP || !dQ || !qInv)
            goto error_free_bn;
    } else {
        p = q = dP = dQ = qInv = NULL;
    }

    rsa = RSA_new();
    if (!rsa)
        goto error_free_bn;

    if (RSA_set0_key(rsa, n, e, d) != 1)
        goto error;

    n = e = d = NULL;

    if (p) {
        if (RSA_set0_factors(rsa, p, q) != 1)
            goto error_free_rsa;
        p = q = NULL;

        if (RSA_set0_crt_params(rsa, dP, dQ, qInv) != 1)
            goto error_free_rsa;
        dP = dQ = qInv = NULL;
    }

    *ppkey = EVP_PKEY_new();
    if (*ppkey == NULL ||
        EVP_PKEY_assign_RSA(*ppkey, rsa) != 1)
        goto error;

    return 1;

error:
    EVP_PKEY_free(*ppkey);
    *ppkey = NULL;

error_free_rsa:
    RSA_free(rsa);

error_free_bn:
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(dP);
    BN_clear_free(dQ);
    BN_clear_free(qInv);

error_free_ned:
    BN_free(n);
    BN_free(e);
    BN_clear_free(d);

    return 0;
}

#endif /* ! OPENSSL_VERSION_NUMBER >= 0x30000000L */

static int
ObjectGetPublicParameters(OBJECT      *key,     // IN
                          BIGNUM     **N,       // OUT
                          BIGNUM     **E        // OUT
                         )
{
    BN_ULONG eval;

    *E = BN_new();
    if (*E == NULL)
        return 0;

    if(key->publicArea.parameters.rsaDetail.exponent != 0)
        eval = key->publicArea.parameters.rsaDetail.exponent;
    else
        eval = RSA_DEFAULT_PUBLIC_EXPONENT;

    if (BN_set_word(*E, eval) != 1)
        goto error;

    *N = BN_bin2bn(key->publicArea.unique.rsa.b.buffer,
                   key->publicArea.unique.rsa.b.size, NULL);
    if (*N == NULL)
        goto error;

    return 1;

error:
    BN_free(*E);
    *E = NULL;

    return 0;
}

LIB_EXPORT TPM_RC
InitOpenSSLRSAPublicKey(OBJECT      *key,     // IN
                        EVP_PKEY   **pkey     // OUT
                       )
{
    TPM_RC      retVal;
    BIGNUM     *N = NULL;
    BIGNUM     *E = NULL;

    if (ObjectGetPublicParameters(key, &N, &E) != 1 ||
        BuildRSAKey(pkey, N, E, NULL, NULL, NULL, NULL, NULL, NULL) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    retVal = TPM_RC_SUCCESS;

 Exit:
    BN_free(N);
    BN_free(E);

    if (retVal != TPM_RC_SUCCESS) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return retVal;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

static void DoRSACheckKey(const BIGNUM *P LIBTPMS_ATTR_UNUSED,
                          const BIGNUM *Q LIBTPMS_ATTR_UNUSED,
                          const BIGNUM *N, const BIGNUM *E, const BIGNUM *D)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    static int disp;
    int ret;

    if (!DO_RSA_CHECK_KEY)
        return;
    if (!disp) {
        fprintf(stderr, "RSA key checking is enabled (OSSL 3)\n");
        disp = 1;
    }

    if (BuildRSAKey(&pkey, N, E, D, NULL, NULL, NULL, NULL, NULL) != 1)
        goto error;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);

    if ((ret = EVP_PKEY_public_check(ctx)) != 1) {
        fprintf(stderr, "Detected bad public RSA key. STOP. ret=%d\n", ret);
        while (1);
    }

    if ((ret = EVP_PKEY_private_check(ctx)) != 1) {
        fprintf(stderr, "Detected bad private RSA key. STOP. ret=%d\n", ret);
        while (1);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return;

error:
    fprintf(stderr, "Could not construct RSA key. STOP.\n");
    while (1);
}

#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

static void DoRSACheckKey(const BIGNUM *P, const BIGNUM *Q, const BIGNUM *N,
                          const BIGNUM *E, const BIGNUM *D)
{
    RSA *mykey;
    static int disp;

    if (!DO_RSA_CHECK_KEY)
        return;
    if (!disp) {
        fprintf(stderr, "RSA key checking is enabled\n");
        disp = 1;
    }

    mykey = RSA_new();
    RSA_set0_factors(mykey, BN_dup(P), BN_dup(Q));
    RSA_set0_key(mykey, BN_dup(N), BN_dup(E), BN_dup(D));
    if (RSA_check_key(mykey) != 1) {
        fprintf(stderr, "Detected bad RSA key. STOP.\n");
        while (1);
    }
    RSA_free(mykey);
}

#endif /* ! OPENSSL_VERSION_NUMBER >= 0x30000000L */

LIB_EXPORT TPM_RC
InitOpenSSLRSAPrivateKey(OBJECT     *rsaKey,   // IN
                         EVP_PKEY  **ppkey     // OUT
                        )
{
    BIGNUM       *N = NULL;
    BIGNUM       *E = NULL;
    BIGNUM       *P = NULL;
    BIGNUM       *Q = NULL;
    BIGNUM       *Qr = NULL;
    BIGNUM       *D = NULL;
    /* for CRT format: dP, dQ, qInv */
    BIGNUM       *dP = BN_new();
    BIGNUM       *dQ = BN_new();
    BIGNUM       *qInv = BN_new();
    BN_CTX       *ctx = NULL;
    TPM_RC        retVal;

    if (ObjectGetPublicParameters(rsaKey, &N, &E) != 1)
        return TPM_RC_FAILURE;

    if(!rsaKey->attributes.privateExp)
        CryptRsaLoadPrivateExponent(&rsaKey->publicArea, &rsaKey->sensitive,
                                    rsaKey);

    P = BN_bin2bn(rsaKey->sensitive.sensitive.rsa.t.buffer,
                  rsaKey->sensitive.sensitive.rsa.t.size, NULL);
    if (P == NULL)
        ERROR_EXIT(TPM_RC_FAILURE);

    D = ExpDCacheFind(P, N, E, &Q);
    if (D == NULL) {
        ctx = BN_CTX_new();
        Q = BN_new();
        Qr = BN_new();
        if (ctx == NULL || Q == NULL || Qr == NULL)
            ERROR_EXIT(TPM_RC_FAILURE);
        /* Q = N/P; no remainder */
        BN_set_flags(P, BN_FLG_CONSTTIME); // P is secret
        if (!BN_div(Q, Qr, N, P, ctx) || !BN_is_zero(Qr))
            ERROR_EXIT(TPM_RC_BINDING);
        BN_set_flags(Q, BN_FLG_CONSTTIME); // Q is secret

        if (ComputePrivateExponentD(P, Q, E, N, &D) == FALSE)
            ERROR_EXIT(TPM_RC_FAILURE);
        ExpDCacheAdd(P, N, E, Q, D);
    }

    DoRSACheckKey(P, Q, N, E, D);

    /* CRT parameters are not absolutely needed but may speed up ops */
    dP = BigInitialized(dP, (bigConst)&rsaKey->privateExponent.dP);
    dQ = BigInitialized(dQ, (bigConst)&rsaKey->privateExponent.dQ);
    qInv = BigInitialized(qInv, (bigConst)&rsaKey->privateExponent.qInv);
    if (dP == NULL || dQ == NULL || qInv == NULL)
        ERROR_EXIT(TPM_RC_FAILURE);

    if (BuildRSAKey(ppkey, N, E, D, P, Q, dP, dQ, qInv) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    retVal = TPM_RC_SUCCESS;

 Exit:
    BN_CTX_free(ctx);
    BN_clear_free(P);
    BN_clear_free(Q);
    BN_free(Qr);
    BN_free(N);
    BN_free(E);
    BN_clear_free(D);
    BN_clear_free(dP);
    BN_clear_free(dQ);
    BN_clear_free(qInv);

    if (retVal != TPM_RC_SUCCESS) {
        EVP_PKEY_free(*ppkey);
        *ppkey = NULL;
    }

    return retVal;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

LIB_EXPORT TPM_RC
OpenSSLCryptRsaGenerateKey(
		    OBJECT              *rsaKey,            // IN/OUT: The object structure in which
		    //          the key is created.
		    UINT32               e,
		    int                  keySizeInBits
		    )
{
    TPMT_PUBLIC         *publicArea = &rsaKey->publicArea;
    TPMT_SENSITIVE      *sensitive = &rsaKey->sensitive;
    TPM_RC               retVal = TPM_RC_SUCCESS;
    BIGNUM              *bnP = NULL;
    BIGNUM              *bnN = NULL;
    BIGNUM              *bnE = BN_new();
    EVP_PKEY_CTX        *ctx = NULL;
    OSSL_PARAM_BLD      *bld = NULL;
    OSSL_PARAM          *params = NULL;
    EVP_PKEY            *pkey = NULL;
    CRYPT_RSA_VAR(tmp);

    if (bnE == NULL || BN_set_word(bnE, e) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) == NULL ||
        EVP_PKEY_keygen_init(ctx) != 1 ||
        (bld = OSSL_PARAM_BLD_new()) == NULL ||
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bnE) != 1 ||
        OSSL_PARAM_BLD_push_uint(bld, "bits", keySizeInBits) != 1 ||
        (params = OSSL_PARAM_BLD_to_param(bld)) == NULL ||
        EVP_PKEY_CTX_set_params(ctx, params) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    if (EVP_PKEY_generate(ctx, &pkey) != 1)
        ERROR_EXIT(TPM_RC_NO_RESULT);

    if (EVP_PKEY_get_bn_param(pkey,  OSSL_PKEY_PARAM_RSA_N, &bnN) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    OsslToTpmBn((bigNum)tmp, bnN);
    TpmMath_IntTo2B(tmp, &publicArea->unique.rsa.b, 0);

    if (EVP_PKEY_get_bn_param(pkey,  OSSL_PKEY_PARAM_RSA_FACTOR1, &bnP) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    OsslToTpmBn((bigNum)tmp, bnP);
    TpmMath_IntTo2B(tmp, &sensitive->sensitive.rsa.b, 0);

    // CryptRsaGenerateKey calls ComputePrivateExponent; we have to call
    // it via CryptRsaLoadPrivateExponent
    retVal = CryptRsaLoadPrivateExponent(&rsaKey->publicArea, &rsaKey->sensitive,
                                         rsaKey);

 Exit:
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_free(bnE);
    BN_free(bnN);
    BN_clear_free(bnP);

    return retVal;
}

#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

LIB_EXPORT TPM_RC
OpenSSLCryptRsaGenerateKey(
		    OBJECT              *rsaKey,            // IN/OUT: The object structure in which
		    //          the key is created.
		    UINT32               e,
		    int                  keySizeInBits
		    )
{
    TPMT_PUBLIC         *publicArea = &rsaKey->publicArea;
    TPMT_SENSITIVE      *sensitive = &rsaKey->sensitive;
    TPM_RC               retVal = TPM_RC_SUCCESS;
    int                  rc;
    RSA                 *rsa = NULL;
    const BIGNUM        *bnP = NULL;
    const BIGNUM        *bnN = NULL;
    BIGNUM              *bnE = BN_new();
    CRYPT_RSA_VAR(tmp);

    if (bnE == NULL || BN_set_word(bnE, e) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    rsa = RSA_new();
    if (rsa == NULL)
        ERROR_EXIT(TPM_RC_FAILURE);

    rc = RSA_generate_key_ex(rsa, keySizeInBits, bnE, NULL);
    if (rc == 0)
        ERROR_EXIT(TPM_RC_NO_RESULT);

    RSA_get0_key(rsa, &bnN, NULL, NULL);
    RSA_get0_factors(rsa, &bnP, NULL);

    OsslToTpmBn((bigNum)tmp, bnN);
    TpmMath_IntTo2B(tmp, &publicArea->unique.rsa.b, 0);

    OsslToTpmBn((bigNum)tmp, bnP);
    TpmMath_IntTo2B(tmp, &sensitive->sensitive.rsa.b, 0);

    // CryptRsaGenerateKey calls ComputePrivateExponent; we have to call
    // it via CryptRsaLoadPrivateExponent
    retVal = CryptRsaLoadPrivateExponent(&rsaKey->publicArea, &rsaKey->sensitive,
                                         rsaKey);

 Exit:
    BN_free(bnE);
    RSA_free(rsa);

    return retVal;
}
#endif /* ! OPENSSL_VERSION_NUMBER >= 0x30000000L */

#endif // USE_OPENSSL_FUNCTIONS_RSA

#if ALG_SM4
static int SetSM4Key(const uint8_t *key, SM4_KEY *ks, int direction)
{
    int rc = 0;
    UINT8 iv[MAX_SM4_BLOCK_SIZE_BYTES] = { 0 };
    const EVP_CIPHER *sm4Cipher = EVP_sm4_ecb();

    *ks = EVP_CIPHER_CTX_new();
    if (*ks == NULL) {
        return 0;
    }
    if (direction == SM4_ENCRYPT) {
        rc = EVP_EncryptInit_ex(*ks, sm4Cipher, NULL, key, iv);
    } else {
        rc = EVP_DecryptInit_ex(*ks, sm4Cipher, NULL, key, iv);
    }
    if (rc != 1) {
        return 0;
    }
    return 1;
}

int SM4_set_encrypt_key(const uint8_t *key, SM4_KEY *ks)
{
    return SetSM4Key(key, ks, SM4_ENCRYPT);
}

int SM4_set_decrypt_key(const uint8_t *key, SM4_KEY *ks)
{
    return SetSM4Key(key, ks, SM4_DECRYPT);
}

static void SM4EncryptDecrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks, int direction)
{
    int outLen = SM4_BLOCK_SIZES;
    int rc = 0;

    if (direction == SM4_ENCRYPT) {
        rc = EVP_EncryptUpdate(*ks, out, &outLen, in, SM4_BLOCK_SIZES);
    } else {
        rc = EVP_DecryptUpdate(*ks, out, &outLen, in, SM4_BLOCK_SIZES);
    }
    pAssert(rc != 1 || outLen != SM4_BLOCK_SIZES);
}

void SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)
{
    SM4EncryptDecrypt(in, out, ks, SM4_ENCRYPT);
}

void SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)
{
    SM4EncryptDecrypt(in, out, ks, SM4_DECRYPT);
}

void SM4_final(const SM4_KEY *ks)
{
    if (*ks != NULL) {
        EVP_CIPHER_CTX_cleanup(*ks);
    }
}
#endif

#if USE_OPENSSL_FUNCTIONS_SSKDF

UINT16 OSSLCryptKDFe(TPM_ALG_ID   hashAlg,  // IN: hash algorithm used in HMAC
		     TPM2B*       Z,        // IN: Z
		     const TPM2B* label,    // IN: a label value for the KDF
		     TPM2B*       partyUInfo,  // IN: PartyUInfo
		     TPM2B*       partyVInfo,  // IN: PartyVInfo
		     UINT32       sizeInBits,  // IN: size of generated key in bits
		     BYTE*        keyStream    // OUT: key buffer
		    )
{
    char        digestname[16];
    OSSL_PARAM  params[4];
    OSSL_PARAM  *p = params;
    size_t      buffer_size = 0;
    UINT16      generated = 0;
    size_t      offset = 0;
    EVP_KDF_CTX *ctx;
    EVP_KDF     *kdf;
    char        *buffer;
    INT16       bytes;  // number of bytes to generate
    const char  *name;

    pAssert(keyStream != NULL && Z != NULL && ((sizeInBits + 7) / 8) < INT16_MAX);
    //
    bytes = (INT16)((sizeInBits + 7) / 8);
    if(hashAlg == TPM_ALG_NULL || bytes == 0)
	return 0;

    name = GetDigestNameByHashAlg(hashAlg);
    if (!name)
	return 0;
    if (strlen(name) >= sizeof(digestname))
	FAIL(FATAL_ERROR_INTERNAL);
    strcpy(digestname, name);

    if (label)
	buffer_size += label->size;
    if (partyUInfo)
	buffer_size += partyUInfo->size;
    if (partyVInfo)
	buffer_size += partyVInfo->size;

    buffer = malloc(buffer_size);
    if (!buffer)
	return 0;

    kdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_SSKDF, NULL);
    if (!kdf)
	goto out;

    ctx = EVP_KDF_CTX_new(kdf);
    if (!ctx)
	goto out;

    if (label) {
	memcpy(&buffer[offset], label->buffer, label->size);
	offset += label->size;
    }
    if (partyUInfo) {
	memcpy(&buffer[offset], partyUInfo->buffer, partyUInfo->size);
	offset += partyUInfo->size;
    }
    if (partyVInfo)
	memcpy(&buffer[offset], partyVInfo->buffer, partyVInfo->size);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
					    digestname, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
					     Z->buffer, Z->size);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
					     buffer, buffer_size);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(ctx, keyStream, bytes, params) <= 0)
	goto out;

    // Mask off bits if the required bits is not a multiple of byte size
    if((sizeInBits % 8) != 0)
	keyStream[0] &= ((1 << (sizeInBits % 8)) - 1);

    generated = bytes;

out:
    EVP_KDF_free(kdf);
    free(buffer);

    return generated;
}

#endif // USE_OPENSSL_FUNCTIONS_SSKDF
