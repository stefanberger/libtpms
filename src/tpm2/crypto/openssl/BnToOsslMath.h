/********************************************************************************/
/*										*/
/*						*/
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
/*  (c) Copyright IBM Corp. and others, 2023				  	*/
/*										*/
/********************************************************************************/

//** Introduction
// This file contains OpenSSL specific functions called by TpmBigNum library to provide
// the TpmBigNum + OpenSSL math support.

#ifndef _BN_TO_OSSL_MATH_H_
#define _BN_TO_OSSL_MATH_H_

#define MATH_LIB_OSSL

// Require TPM Big Num types
#if !defined(MATH_LIB_TPMBIGNUM) && !defined(_BNOSSL_H_)
#  error this OpenSSL Interface expects to be used from TpmBigNum
#endif

#include "BnValues.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#if 0 // libtpms added
#if OPENSSL_VERSION_NUMBER >= 0x30100ff0L
// Check the bignum_st definition against the one below and either update the
// version check or provide the new definition for this version.
#  error Untested OpenSSL version
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
// from crypto/bn/bn_lcl.h (OpenSSL 1.x) or crypto/bn/bn_local.h (OpenSSL 3.0)
struct bignum_st
{
    BN_ULONG* d;   /* Pointer to an array of 'BN_BITS2' bit
		    * chunks. */
    int       top; /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;      /* Size of the d array. */
    int neg;       /* one if the number is negative */
    int flags;
};
#else
#  define EC_POINT_get_affine_coordinates EC_POINT_get_affine_coordinates_GFp
#  define EC_POINT_set_affine_coordinates EC_POINT_set_affine_coordinates_GFp
#endif // OPENSSL_VERSION_NUMBER
#endif // libtpms added

#if USE_OPENSSL_FUNCTIONS_ECDSA				// libtpms added begin
# include <openssl/ecdsa.h>				// LibreSSL needs it
#endif

#if USE_EC_POINT_GET_AFFINE_COORDINATES_API
#  define EC_POINT_get_affine_coordinates_GFp EC_POINT_get_affine_coordinates
#  define EC_POINT_set_affine_coordinates_GFp EC_POINT_set_affine_coordinates
#endif							// libtpms added end

	//** Macros and Defines

	// Make sure that the library is using the correct size for a crypt word
#if defined THIRTY_TWO_BIT && (RADIX_BITS != 32)			\
    || ((defined SIXTY_FOUR_BIT_LONG || defined SIXTY_FOUR_BIT)		\
	&& (RADIX_BITS != 64))
#  error Ossl library is using different radix
#endif

// Allocate a local BIGNUM value. For the allocation, a bigNum structure is created
// as is a local BIGNUM. The bigNum is initialized and then the BIGNUM is
// set to reference the local value.
#define BIG_VAR(name, bits)		 \
    BN_VAR(name##Bn, (bits));		 \
    BIGNUM* _##name = BN_new();			/* libtpms */	\
    BIGNUM* name = BigInitialized(_##name	/* libtpms */	\
									, BnInit(name##Bn, BYTES_TO_CRYPT_WORDS(sizeof(_##name##Bn.d))))

// Allocate a BIGNUM and initialize with the values in a bigNum initializer
#define BIG_INITIALIZED(name, initializer)				\
    BIGNUM* _##name = BN_new();				/* libtpms */	\
    BIGNUM* name = BigInitialized(_##name, initializer) /* libtpms */

typedef struct
{
    const TPMBN_ECC_CURVE_CONSTANTS* C;  // the TPM curve values
    EC_GROUP*                        G;  // group parameters
    BN_CTX* CTX;  // the context for the math (this might not be
    // the context in which the curve was created>;
} OSSL_CURVE_DATA;

// Define the curve data type expected by the TpmBigNum library:
typedef OSSL_CURVE_DATA                     bigCurveData;

TPM_INLINE const TPMBN_ECC_CURVE_CONSTANTS* AccessCurveConstants(
								 const bigCurveData* E)
{
    return E->C;
}

#include "TpmToOsslSupport_fp.h"

// Start and end a context within which the OpenSSL memory management works
#define OSSL_ENTER() BN_CTX* CTX = OsslContextEnter()
#define OSSL_LEAVE() OsslContextLeave(CTX)

#if 0	/* kgold not used */
// Start and end a local stack frame within the context of the curve frame
#define ECC_ENTER() BN_CTX* CTX = OsslPushContext(E->CTX)
#define ECC_LEAVE() OsslPopContext(CTX)
#endif

#define BN_NEW() BnNewVariable(CTX)

// This definition would change if there were something to report
#define MathLibSimulationEnd()

#endif  // _BN_TO_OSSL_MATH_H_
