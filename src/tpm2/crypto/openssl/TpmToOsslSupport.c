/********************************************************************************/
/*										*/
/*		Initialization of the Interface to the OpenSSL Library.	   	*/
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
// The functions in this file are used for initialization of the interface to the
// OpenSSL library.

//** Defines and Includes

#include "BnOssl.h"
#include "CryptoInterface.h"
#include "TpmToOsslSym.h"
#include "TpmToOsslHash.h"
#include <openssl/opensslv.h>
#include <stdio.h>

#if CRYPTO_LIB_REPORTING

//*** OsslGetVersion()
// Report the version of OpenSSL.
void OsslGetVersion(_CRYPTO_IMPL_DESCRIPTION* result)
{
    snprintf(result->name, sizeof(result->name), "OpenSSL");
#  if defined(OPENSSL_VERSION_STR)
    snprintf(result->version, sizeof(result->version), "%s", OPENSSL_VERSION_STR);
#  else
    // decode the hex version string according to the rules described in opensslv.h
    snprintf(result->version,
             sizeof(result->version),
             "%d.%d.%d%c",
             (unsigned char)((OPENSSL_VERSION_NUMBER >> 28) & 0x0f),
             (unsigned char)((OPENSSL_VERSION_NUMBER >> 20) & 0xff),
             (unsigned char)((OPENSSL_VERSION_NUMBER >> 12) & 0xff),
             (char)((OPENSSL_VERSION_NUMBER >> 4) & 0xff) - 1 + 'a');
#  endif  //OPENSSL_VERSION_STR
}

#endif  //CRYPTO_LIB_REPORTING

#if defined(HASH_LIB_OSSL) || defined(MATH_LIB_OSSL) || defined(SYM_LIB_OSSL)
// Used to pass the pointers to the correct sub-keys
typedef const BYTE* desKeyPointers[3];

//*** BnSupportLibInit()
// This does any initialization required by the support library.
LIB_EXPORT int BnSupportLibInit(void)
{
    return TRUE;
}

//*** OsslContextEnter()
// This function is used to initialize an OpenSSL context at the start of a function
// that will call to an OpenSSL math function.
BN_CTX* OsslContextEnter(void)
{
    BN_CTX* CTX = BN_CTX_new();
    //
    return OsslPushContext(CTX);
}

//*** OsslContextLeave()
// This is the companion function to OsslContextEnter().
void OsslContextLeave(BN_CTX* CTX)
{
    OsslPopContext(CTX);
    BN_CTX_free(CTX);
}

//*** OsslPushContext()
// This function is used to create a frame in a context. All values allocated within
// this context after the frame is started will be automatically freed when the
// context (OsslPopContext()
BN_CTX* OsslPushContext(BN_CTX* CTX)
{
    if(CTX == NULL)
        FAIL(FATAL_ERROR_ALLOCATION);
    BN_CTX_start(CTX);
    return CTX;
}

//*** OsslPopContext()
// This is the companion function to OsslPushContext().
void OsslPopContext(BN_CTX* CTX)
{
    // BN_CTX_end can't be called with NULL. It will blow up.
    if(CTX != NULL)
        BN_CTX_end(CTX);
}

#  if CRYPTO_LIB_REPORTING

#    if defined(SYM_LIB_OSSL) && SIMULATION && CRYPTO_LIB_REPORTING
//*** _crypto_GetSymImpl()
// Report the version of OpenSSL being used for symmetric crypto.
void _crypto_GetSymImpl(_CRYPTO_IMPL_DESCRIPTION* result)
{
    OsslGetVersion(result);
}
#    else
#      error huh?
#    endif  // defined(SYM_LIB_OSSL) && SIMULATION

#    if defined(HASH_LIB_OSSL) && SIMULATION && CRYPTO_LIB_REPORTING
//*** _crypto_GetHashImpl()
// Report the version of OpenSSL being used for hashing.
void _crypto_GetHashImpl(_CRYPTO_IMPL_DESCRIPTION* result)
{
    OsslGetVersion(result);
}
#    endif  // defined(HASH_LIB_OSSL) && SIMULATION

#  endif  // CRYPTO_LIB_REPORTING

#endif  // HASH_LIB_OSSL || MATH_LIB_OSSL || SYM_LIB_OSSL
