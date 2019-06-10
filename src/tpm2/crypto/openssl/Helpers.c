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

#include <openssl/evp.h>

#if USE_OPENSSL_FUNCTIONS_SYMMETRIC

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
#endif
#if ALG_SM4
#error Missing implementation of EVP for SM4
    case TPM_ALG_SM4:
        break;
#endif
#if ALG_CAMELLIA
#error Missing implementation of EVP for Camellia
    case TPM_ALG_CAMELLIA:
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
                     const EC_GROUP    *G,     // IN:  the EC_GROUP to use
                     RAND_STATE        *rand   // IN: state for DRBG
                    )
{
    BOOL           OK = FALSE;
    const BIGNUM  *D;
    EC_KEY        *eckey = EC_KEY_new();

    pAssert(G != NULL);

    if (rand != NULL)
        pAssert(FALSE);  // FIXME: Use rand's KDF for key generation

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
