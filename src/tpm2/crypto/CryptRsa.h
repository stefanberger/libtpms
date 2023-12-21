/********************************************************************************/
/*										*/
/*			     RSA-related structures and defines			*/
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

// This file contains the RSA-related structures and defines.

#ifndef _CRYPT_RSA_H
#define _CRYPT_RSA_H

// These values are used in the Crypt_Int* representation of various RSA values.
// define ci_rsa_t as buffer containing a CRYPT_INT object with space for
// (MAX_RSA_KEY_BITS) of actual data.
CRYPT_INT_TYPE(rsa, MAX_RSA_KEY_BITS);
#define CRYPT_RSA_VAR(name) CRYPT_INT_VAR(name, MAX_RSA_KEY_BITS)
#define CRYPT_RSA_INITIALIZED(name, initializer)			\
    CRYPT_INT_INITIALIZED(name, MAX_RSA_KEY_BITS, initializer)

#define CRYPT_PRIME_VAR(name) CRYPT_INT_VAR(name, (MAX_RSA_KEY_BITS / 2))
// define ci_prime_t as buffer containing a CRYPT_INT object with space for
// (MAX_RSA_KEY_BITS/2) of actual data.
CRYPT_INT_TYPE(prime, (MAX_RSA_KEY_BITS / 2));
#define CRYPT_PRIME_INITIALIZED(name, initializer)			\
    CRYPT_INT_INITIALIZED(name, MAX_RSA_KEY_BITS / 2, initializer)

#if !CRT_FORMAT_RSA
#  error This verson only works with CRT formatted data
#endif  // !CRT_FORMAT_RSA

typedef struct privateExponent
{
    Crypt_Int* P;
    Crypt_Int* Q;
    Crypt_Int* dP;
    Crypt_Int* dQ;
    Crypt_Int* qInv;
    ci_prime_t entries[5];
} privateExponent;

#define NEW_PRIVATE_EXPONENT(X)		\
    privateExponent  _##X;					\
    privateExponent* X = RsaInitializeExponent(&(_##X))

					// libtpms added begin: keep old privateExponent
/* The privateExponentOld is part of the OBJECT and we keep it there even though
 * upstream got rid of it and stores Q, dP, dQ, and qInv by appending them to
 * P stored in TPMT_SENSITIVE.TPMU_SENSITIVE_COMPOSITE.TPM2B_PRIVATE_KEY_RSA
 */
typedef struct privateExponentOld
{
    ci_prime_t          Q;
    ci_prime_t          dP;
    ci_prime_t          dQ;
    ci_prime_t          qInv;
} privateExponent_t;

#include "BnMemory_fp.h"

static inline void RsaInitializeExponentOld(privateExponent_t* pExp)
{
    BN_INIT(pExp->Q);
    BN_INIT(pExp->dP);
    BN_INIT(pExp->dQ);
    BN_INIT(pExp->qInv);
}

static inline void RsaSetExponentOld(privateExponent_t* pExp,  // OUT
				     privateExponent*   Z      // IN
				     )
{
    // pExp->Q must be set elsewhere
    ExtMath_Copy((Crypt_Int*)&pExp->dP, Z->dP);
    ExtMath_Copy((Crypt_Int*)&pExp->dQ, Z->dQ);
    ExtMath_Copy((Crypt_Int*)&pExp->qInv, Z->qInv);
}

static inline void RsaSetExponentFromOld(privateExponent*   Z,     // OUT
					 privateExponent_t* pExp   // IN
					 )
{
    ExtMath_Copy(Z->Q, (Crypt_Int*)&pExp->Q);
    ExtMath_Copy(Z->dP, (Crypt_Int*)&pExp->dP);
    ExtMath_Copy(Z->dQ, (Crypt_Int*)&pExp->dQ);
    ExtMath_Copy(Z->qInv, (Crypt_Int*)&pExp->qInv);
}
					// libtpms added end
#endif  // _CRYPT_RSA_H
