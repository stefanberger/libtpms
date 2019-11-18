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
#include "Helpers_fp.h"
#include "TpmToOsslMath_fp.h"

#include "config.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#if USE_OPENSSL_FUNCTIONS_SYMMETRIC

TPM_RC
OpenSSLCryptGenerateKeyDes(
                           TPMT_SENSITIVE *sensitive    // OUT: sensitive area
                          )
{
    DES_cblock *key;
    size_t      offset;
    size_t      limit;

    limit = MIN(sizeof(sensitive->sensitive.sym.t.buffer),
                sensitive->sensitive.sym.t.size);
    limit = TPM2_ROUNDUP(limit, sizeof(*key));
    pAssert(limit < sizeof(sensitive->sensitive.sym.t.buffer));

    for (offset = 0; offset < limit; offset += sizeof(*key)) {
        key = (DES_cblock *)&sensitive->sensitive.sym.t.buffer[offset];
        if (DES_random_key(key) != 1)
            return TPM_RC_NO_RESULT;
    }
    return TPM_RC_SUCCESS;
}

evpfunc GetEVPCipher(TPM_ALG_ID    algorithm,       // IN
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

    // key size to array index: 128 -> 0, 192 -> 1, 256 -> 2
    i = (keySizeInBits >> 6) - 2;
    if (i < 0 || i > 2)
        return NULL;

    pAssert(*keyToUseLen >= keySizeInBytes)
    memcpy(keyToUse, key, keySizeInBytes);

    switch (algorithm) {
#if ALG_AES
    case TPM_ALG_AES:
        *keyToUseLen = keySizeInBytes;
        switch (mode) {
#if ALG_CTR
        case ALG_CTR_VALUE:
            evpfn = (evpfunc []){EVP_aes_128_ctr, EVP_aes_192_ctr,
                                 EVP_aes_256_ctr}[i];
            break;
#endif
#if ALG_OFB
        case ALG_OFB_VALUE:
            evpfn = (evpfunc[]){EVP_aes_128_ofb, EVP_aes_192_ofb,
                                EVP_aes_256_ofb}[i];
            break;
#endif
#if ALG_CBC
        case ALG_CBC_VALUE:
            evpfn = (evpfunc[]){EVP_aes_128_cbc, EVP_aes_192_cbc,
                                EVP_aes_256_cbc}[i];
            break;
#endif
#if ALG_CFB
        case ALG_CFB_VALUE:
            evpfn = (evpfunc[]){EVP_aes_128_cfb, EVP_aes_192_cfb,
                                EVP_aes_256_cfb}[i];
            break;
#endif
#if ALG_ECB
        case ALG_ECB_VALUE:
            evpfn = (evpfunc[]){EVP_aes_128_ecb, EVP_aes_192_ecb,
                                EVP_aes_256_ecb}[i];
            break;
#endif
        }
        break;
#endif
#if ALG_TDES
    case TPM_ALG_TDES:
        if (keySizeInBits == 128) {
            pAssert(*keyToUseLen >= BITS_TO_BYTES(192))
            // stretch the key
            memcpy(&keyToUse[16], &keyToUse[0], 8);
            *keyToUseLen = BITS_TO_BYTES(192);
        }

        switch (mode) {
#if ALG_CTR
        case ALG_CTR_VALUE:
            evpfn = (evpfunc[]){EVP_des_ede3, EVP_des_ede3, NULL}[i];
            break;
#endif
#if ALG_OFB
        case ALG_OFB_VALUE:
            evpfn = (evpfunc[]){EVP_des_ede3_ofb, EVP_des_ede3_ofb, NULL}[i];
            break;
#endif
#if ALG_CBC
        case ALG_CBC_VALUE:
            evpfn = (evpfunc[]){EVP_des_ede3_cbc, EVP_des_ede3_cbc, NULL}[i];
            break;
#endif
#if ALG_CFB
        case ALG_CFB_VALUE:
            evpfn = (evpfunc[]){EVP_des_ede3_cfb64, EVP_des_ede3_cfb64, NULL}[i];
            break;
#endif
#if ALG_ECB
        case ALG_ECB_VALUE:
            evpfn = (evpfunc[]){EVP_des_ede3_ecb, EVP_des_ede3_ecb, NULL}[i];
            break;
#endif
        }
        break;
#endif

#if ALG_SM4
#error Missing implementation of EVP for SM4
    case TPM_ALG_SM4:
        break;
#endif

#if ALG_CAMELLIA
    case TPM_ALG_CAMELLIA:
        *keyToUseLen = keySizeInBytes;
        switch (mode) {
#if ALG_CTR
        case ALG_CTR_VALUE:
            evpfn = (evpfunc []){EVP_camellia_128_ctr, EVP_camellia_192_ctr,
                                 EVP_camellia_256_ctr}[i];
            break;
#endif
#if ALG_OFB
        case ALG_OFB_VALUE:
            evpfn = (evpfunc[]){EVP_camellia_128_ofb, EVP_camellia_192_ofb,
                                EVP_camellia_256_ofb}[i];
            break;
#endif
#if ALG_CBC
        case ALG_CBC_VALUE:
            evpfn = (evpfunc[]){EVP_camellia_128_cbc, EVP_camellia_192_cbc,
                                EVP_camellia_256_cbc}[i];
            break;
#endif
#if ALG_CFB
        case ALG_CFB_VALUE:
            evpfn = (evpfunc[]){EVP_camellia_128_cfb, EVP_camellia_192_cfb,
                                EVP_camellia_256_cfb}[i];
            break;
#endif
#if ALG_ECB
        case ALG_ECB_VALUE:
            evpfn = (evpfunc[]){EVP_camellia_128_ecb, EVP_camellia_192_ecb,
                                EVP_camellia_256_ecb}[i];
            break;
#endif
        }
        break;
#endif
    }

    if (evpfn == NULL)
        MemorySet(keyToUse, 0, *keyToUseLen);

    return evpfn;
}

#endif // USE_OPENSSL_FUNCTIONS_SYMMETRIC

#if USE_OPENSSL_FUNCTIONS_EC
BOOL
OpenSSLEccGetPrivate(
                     bigNum             dOut,  // OUT: the qualified random value
                     const EC_GROUP    *G      // IN:  the EC_GROUP to use
                    )
{
    BOOL           OK = FALSE;
    const BIGNUM  *D;
    EC_KEY        *eckey = EC_KEY_new();

    pAssert(G != NULL);

    if (!eckey)
        return FALSE;

    if (EC_KEY_set_group(eckey, G) != 1)
        goto Exit;

    if (EC_KEY_generate_key(eckey) == 1) {
        OK = TRUE;
        D = EC_KEY_get0_private_key(eckey);
        OsslToTpmBn(dOut, D);
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
ComputePrivateExponentD(
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
        pOK = pOK && (*D = BN_mod_inverse(NULL, E, phi, ctx)) != NULL;
    }
    BN_CTX_free(ctx);
    BN_clear_free(phi);

    return pOK;
}

LIB_EXPORT TPM_RC
InitOpenSSLRSAPublicKey(OBJECT      *key,     // IN
                        EVP_PKEY   **pkey     // OUT
                       )
{
    TPM_RC      retVal;
    RSA        *rsakey = RSA_new();
    BIGNUM     *N = NULL;
    BIGNUM     *E = BN_new();
    BN_ULONG    eval;

    *pkey = EVP_PKEY_new();

    if (rsakey == NULL || *pkey == NULL || E == NULL)
        ERROR_RETURN(TPM_RC_FAILURE);

    if(key->publicArea.parameters.rsaDetail.exponent != 0)
        eval = key->publicArea.parameters.rsaDetail.exponent;
    else
        eval = RSA_DEFAULT_PUBLIC_EXPONENT;

    if (BN_set_word(E, eval) != 1)
        ERROR_RETURN(TPM_RC_FAILURE);

    N = BN_bin2bn(key->publicArea.unique.rsa.b.buffer,
                  key->publicArea.unique.rsa.b.size, NULL);
    if (N == NULL ||
        RSA_set0_key(rsakey, N, E, NULL) != 1 ||
        EVP_PKEY_assign_RSA(*pkey, rsakey) == 0)
        ERROR_RETURN(TPM_RC_FAILURE)

    RSA_set_flags(rsakey, RSA_FLAG_NO_BLINDING);

    retVal = TPM_RC_SUCCESS;

 Exit:
    if (retVal != TPM_RC_SUCCESS) {
        RSA_free(rsakey);
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return retVal;
}

LIB_EXPORT TPM_RC
InitOpenSSLRSAPrivateKey(OBJECT     *rsaKey,   // IN
                         EVP_PKEY  **pkey      // OUT
                        )
{
    const BIGNUM *N = NULL;
    const BIGNUM *E = NULL;
    BIGNUM       *P = NULL;
    BIGNUM       *Q = NULL;
    BIGNUM       *Qr = NULL;
    BIGNUM       *D = NULL;
#if CRT_FORMAT_RSA == YES
    BIGNUM       *dP = BN_new();
    BIGNUM       *dQ = BN_new();
    BIGNUM       *qInv = BN_new();
#endif
    RSA          *key;
    BN_CTX       *ctx = NULL;
    TPM_RC        retVal = InitOpenSSLRSAPublicKey(rsaKey, pkey);

    if (retVal != TPM_RC_SUCCESS)
        return retVal;

    if(!rsaKey->attributes.privateExp)
        CryptRsaLoadPrivateExponent(rsaKey);

    ctx = BN_CTX_new();
    Q = BN_new();
    Qr = BN_new();
    P = BN_bin2bn(rsaKey->sensitive.sensitive.rsa.t.buffer,
                  rsaKey->sensitive.sensitive.rsa.t.size, NULL);
    if (ctx == NULL || Q == NULL || Qr == NULL || P == NULL)
        ERROR_RETURN(TPM_RC_FAILURE)

    key = EVP_PKEY_get0_RSA(*pkey);
    if (key == NULL)
        ERROR_RETURN(TPM_RC_FAILURE);
    RSA_get0_key(key, &N, &E, NULL);

    /* Q = N/P; no remainder */
    BN_div(Q, Qr, N, P, ctx);
    if(!BN_is_zero(Qr))
        ERROR_RETURN(TPM_RC_BINDING);

    // TODO(stefanb): consider caching D in the OBJECT
    if (ComputePrivateExponentD(P, Q, E, N, &D) == FALSE ||
        RSA_set0_key(key, NULL, NULL, D) != 1)
        ERROR_RETURN(TPM_RC_FAILURE);
    D = NULL;

#if CRT_FORMAT_RSA == YES
    /* CRT parameters are not absolutely needed but may speed up ops */
    dP = BigInitialized(dP, (bigConst)&rsaKey->privateExponent.dP);
    dQ = BigInitialized(dQ, (bigConst)&rsaKey->privateExponent.dQ);
    qInv = BigInitialized(qInv, (bigConst)&rsaKey->privateExponent.qInv);
    if (dP == NULL || dQ == NULL || qInv == NULL ||
        RSA_set0_crt_params(key, dP, dQ, qInv) != 1)
        ERROR_RETURN(TPM_RC_FAILURE);
#endif

    retVal = TPM_RC_SUCCESS;

 Exit:
    BN_CTX_free(ctx);
    BN_clear_free(P);
    BN_clear_free(Q);
    BN_free(Qr);

    if (retVal != TPM_RC_SUCCESS) {
        BN_clear_free(D);
#if CRT_FORMAT_RSA == YES
        BN_clear_free(dP);
        BN_clear_free(dQ);
        BN_clear_free(qInv);
#endif
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return retVal;
}

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
    BN_RSA(tmp);

    if (bnE == NULL || BN_set_word(bnE, e) != 1)
        ERROR_RETURN(TPM_RC_FAILURE);

    // Need to initialize the privateExponent structure
    RsaInitializeExponent(&rsaKey->privateExponent);

    rsa = RSA_new();
    if (rsa == NULL)
        ERROR_RETURN(TPM_RC_FAILURE);

    rc = RSA_generate_key_ex(rsa, keySizeInBits, bnE, NULL);
    if (rc == 0)
        ERROR_RETURN(TPM_RC_NO_RESULT);

    RSA_get0_key(rsa, &bnN, NULL, NULL);
    RSA_get0_factors(rsa, &bnP, NULL);

    OsslToTpmBn(tmp, bnN);
    BnTo2B((bigNum)tmp, &publicArea->unique.rsa.b, 0);

    OsslToTpmBn(tmp, bnP);
    BnTo2B((bigNum)tmp, &sensitive->sensitive.rsa.b, 0);

    // CryptRsaGenerateKey calls ComputePrivateExponent; we have to call
    // it via CryptRsaLoadPrivateExponent
    retVal = CryptRsaLoadPrivateExponent(rsaKey);

 Exit:
    BN_free(bnE);
    RSA_free(rsa);

    return retVal;
}

#endif // USE_OPENSSL_FUNCTIONS_RSA
