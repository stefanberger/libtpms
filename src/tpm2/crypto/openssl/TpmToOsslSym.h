/********************************************************************************/
/*										*/
/*		Splice the OpenSSL() library into the TPM code.    		*/
/*			     Written by Ken Goldman				*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2023				*/
/*										*/
/********************************************************************************/

//** Introduction
//
// This header file is used to 'splice' the OpenSSL library into the TPM code.
//
// The support required of a library are a hash module, a block cipher module and
// portions of a big number library.

// All of the library-dependent headers should have the same guard to that only the
// first one gets defined.
#ifndef SYM_LIB_DEFINED
#define SYM_LIB_DEFINED

#define SYM_LIB_OSSL

#include <openssl/aes.h>
#if ALG_TDES
#include <openssl/des.h>
#endif

#if ALG_SM4
#  if defined(OPENSSL_NO_SM4) || OPENSSL_VERSION_NUMBER < 0x10101010L
#    error "Current version of OpenSSL doesn't support SM4"
#   //elif OPENSSL_VERSION_NUMBER >= 0x10200000L		// libtpms deactivated
#   //    include <openssl/sm4.h>				// libtpms deactivated
#   else
#       include <openssl/evp.h>					// libtpms changed begin
        typedef EVP_CIPHER_CTX* SM4_KEY;
#       define SM4_ENCRYPT 1
#       define SM4_DECRYPT 0

int SM4_set_encrypt_key(const uint8_t *key, SM4_KEY *ks);
int SM4_set_decrypt_key(const uint8_t *key, SM4_KEY *ks);	// libtpms changed end
void SM4_encrypt(const uint8_t* in, uint8_t* out, const SM4_KEY* ks);
void SM4_decrypt(const uint8_t* in, uint8_t* out, const SM4_KEY* ks);
void SM4_final(const SM4_KEY *ks);				// libtpms added
#  endif  // OpenSSL < 1.2
#endif    // ALG_SM4

#if ALG_CAMELLIA
#  include <openssl/camellia.h>
#endif

#include <openssl/bn.h>
#include <openssl/ossl_typ.h>

//***************************************************************
//** Links to the OpenSSL symmetric algorithms.
//***************************************************************

// The Crypt functions that call the block encryption function use the parameters
// in the order:
//  1) keySchedule
//  2) in buffer
//  3) out buffer
// Since open SSL uses the order in encryptoCall_t above, need to swizzle the
// values to the order required by the library.
#define SWIZZLE(keySchedule, in, out)				\
    (const BYTE*)(in), (BYTE*)(out), (void*)(keySchedule)

// Define the order of parameters to the library functions that do block encryption
// and decryption.
typedef void (*TpmCryptSetSymKeyCall_t)(const BYTE* in, BYTE* out, void* keySchedule);

typedef void(*TpmCryptSymFinal_t)(void *keySchedule); /* libtpms added */
#define SYM_ALIGNMENT   4 /* libtpms: keep old value */

//***************************************************************
//** Links to the OpenSSL AES code
//***************************************************************
// Macros to set up the encryption/decryption key schedules
//
// AES:
#define TpmCryptSetEncryptKeyAES(key, keySizeInBits, schedule)		\
    AES_set_encrypt_key((key), (keySizeInBits), (tpmKeyScheduleAES*)(schedule))
#define TpmCryptSetDecryptKeyAES(key, keySizeInBits, schedule)		\
    AES_set_decrypt_key((key), (keySizeInBits), (tpmKeyScheduleAES*)(schedule))

// Macros to alias encryption calls to specific algorithms. This should be used
// sparingly. Currently, only used by CryptSym.c and CryptRand.c
//
// When using these calls, to call the AES block encryption code, the caller
// should use:
//      TpmCryptEncryptAES(SWIZZLE(keySchedule, in, out));
#define TpmCryptEncryptAES AES_encrypt
#define TpmCryptDecryptAES AES_decrypt
#define tpmKeyScheduleAES  AES_KEY
#define TpmCryptFinalAES   NULL  // libtpms added

#define TpmCryptSetEncryptKeyTDES(key, keySizeInBits, schedule)		\
    TDES_set_encrypt_key((key), (keySizeInBits), (tpmKeyScheduleTDES *)(schedule))
#define TpmCryptSetDecryptKeyTDES(key, keySizeInBits, schedule)		\
    TDES_set_encrypt_key((key), (keySizeInBits), (tpmKeyScheduleTDES *)(schedule))

#define TpmCryptEncryptTDES         TDES_encrypt
#define TpmCryptDecryptTDES         TDES_decrypt
#define tpmKeyScheduleTDES          DES_key_schedule
#define TpmCryptFinalTDES           NULL  // libtpms added

#if ALG_TDES  // libtpms added begin
#include "TpmToOsslDesSupport_fp.h"
#endif        // libtpms added end

//***************************************************************
//** Links to the OpenSSL SM4 code
//***************************************************************
// Macros to set up the encryption/decryption key schedules
#define TpmCryptSetEncryptKeySM4(key, keySizeInBits, schedule)	\
    SM4_set_encrypt_key((key), (tpmKeyScheduleSM4 *)(schedule)) /* libtpms changed */
#define TpmCryptSetDecryptKeySM4(key, keySizeInBits, schedule)	\
    SM4_set_decrypt_key((key), (tpmKeyScheduleSM4 *)(schedule)) /* libtpms changed */

// Macros to alias encryption calls to specific algorithms. This should be used
// sparingly.
#define TpmCryptEncryptSM4 SM4_encrypt
#define TpmCryptDecryptSM4 SM4_decrypt
#define tpmKeyScheduleSM4  SM4_KEY
#define TpmCryptFinalSM4   SM4_final // libtpms added

//***************************************************************
//** Links to the OpenSSL CAMELLIA code
//***************************************************************
// Macros to set up the encryption/decryption key schedules
#define TpmCryptSetEncryptKeyCAMELLIA(key, keySizeInBits, schedule)	\
    Camellia_set_key((key), (keySizeInBits), (tpmKeyScheduleCAMELLIA*)(schedule))
#define TpmCryptSetDecryptKeyCAMELLIA(key, keySizeInBits, schedule)	\
    Camellia_set_key((key), (keySizeInBits), (tpmKeyScheduleCAMELLIA*)(schedule))

// Macros to alias encryption calls to specific algorithms. This should be used
// sparingly.
#define TpmCryptEncryptCAMELLIA Camellia_encrypt
#define TpmCryptDecryptCAMELLIA Camellia_decrypt
#define tpmKeyScheduleCAMELLIA  CAMELLIA_KEY
#define TpmCryptFinalCAMELLIA            NULL // libtpms added

// Forward reference

// kgold typedef union tpmCryptKeySchedule_t tpmCryptKeySchedule_t;

// This definition would change if there were something to report
#define SymLibSimulationEnd()

#endif  // SYM_LIB_DEFINED

