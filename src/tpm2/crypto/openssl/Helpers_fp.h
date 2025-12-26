/********************************************************************************/
/*										*/
/*			       OpenSSL helper functions				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  (c) Copyright IBM Corporation, 2019-2025					*/
/*										*/
/* All rights reserved.								*/
/*										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/*										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/*										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/*										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/*										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/*										*/
/********************************************************************************/


#ifndef HELPERS_FP_H
#define HELPERS_FP_H

#include "TpmTypes.h"

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
