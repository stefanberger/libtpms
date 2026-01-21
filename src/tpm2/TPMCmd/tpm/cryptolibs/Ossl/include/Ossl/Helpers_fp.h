// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation, 2019-2025

#ifndef HELPERS_FP_H
#define HELPERS_FP_H

#include "tpm_public/TpmTypes.h"

#include <openssl/evp.h>

#if USE_OPENSSL_FUNCTIONS_SYMMETRIC
TPM_RC
OpenSSLCryptGenerateKeyDes(
                           TPMT_SENSITIVE *sensitive    // OUT: sensitive area
                          );

const EVP_CIPHER *GetEVPCipher(TPM_ALG_ID    algorithm,       // IN
			       UINT16        keySizeInBits,   // IN
			       TPM_ALG_ID    mode,            // IN
			       const BYTE   *key,             // IN
			       BYTE         *keyToUse,        // OUT same as key or stretched key
			       UINT16       *keyToUseLen      // IN/OUT
			      );

TPM_RC DoEVPGetUpdatedIV(EVP_CIPHER_CTX    *ctx,    // IN: required context
                         unsigned char     *iv,     // IN: pointer to buffer for IV
                         size_t             iv_len  // IN: size of the buffer
                         );

#endif

#if USE_OPENSSL_FUNCTIONS_EC
BOOL OpenSSLEccGetPrivate(
                          bigNum             dOut,   // OUT: the qualified random value
                          const EC_GROUP    *G,      // IN:  the EC_GROUP to use
                          const UINT32       requestedBits // IN: if not 0, then dOut must have that many bits
                         );
#endif

#if USE_OPENSSL_FUNCTIONS_RSA

const char *GetDigestNameByHashAlg(const TPM_ALG_ID hashAlg);

LIB_EXPORT TPM_RC
OpenSSLCryptRsaGenerateKey(
		    OBJECT              *rsaKey,            // IN/OUT: The object structure in which
		    //          the key is created.
		    UINT32               e,
		    int                  keySizeInBits
		    );

LIB_EXPORT TPM_RC
InitOpenSSLRSAPublicKey(OBJECT    *key,   // IN
                        EVP_PKEY **pkey   //OUT
                       );

LIB_EXPORT TPM_RC
InitOpenSSLRSAPrivateKey(OBJECT     *rsaKey,   // IN
                         EVP_PKEY  **pkey      // OUT
                        );

#endif // USE_OPENSSL_FUNCTIONS_RSA

#if USE_OPENSSL_FUNCTIONS_SSKDF
LIB_EXPORT UINT16
OSSLCryptKDFe(TPM_ALG_ID   hashAlg,  // IN: hash algorithm used in HMAC
	      TPM2B*       Z,        // IN: Z
	      const TPM2B* label,    // IN: a label value for the KDF
	      TPM2B*       partyUInfo,  // IN: PartyUInfo
	      TPM2B*       partyVInfo,  // IN: PartyVInfo
	      UINT32       sizeInBits,  // IN: size of generated key in bits
	      BYTE*        keyStream    // OUT: key buffer
	     );
#endif // USE_OPENSSL_FUNCTIONS_SSKDF

#endif  /* HELPERS_FP_H */
