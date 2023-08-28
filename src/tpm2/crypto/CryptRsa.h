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

// 10.1.5	CryptRsa.h
// This file contains the RSA-related structures and defines.
#ifndef _CRYPT_RSA_H
#define _CRYPT_RSA_H

// These values are used in the bigNum representation of various RSA values.

BN_TYPE(rsa, MAX_RSA_KEY_BITS);
#define BN_RSA(name)       BN_VAR(name, MAX_RSA_KEY_BITS)
#define BN_RSA_INITIALIZED(name, initializer)			\
    BN_INITIALIZED(name, MAX_RSA_KEY_BITS, initializer)

#define BN_PRIME(name)     BN_VAR(name, (MAX_RSA_KEY_BITS / 2))
BN_TYPE(prime, (MAX_RSA_KEY_BITS / 2));
#define BN_PRIME_INITIALIZED(name, initializer)				\
    BN_INITIALIZED(name, MAX_RSA_KEY_BITS / 2, initializer)

#if !CRT_FORMAT_RSA
#   error   This verson only works with CRT formatted data
#endif // !CRT_FORMAT_RSA

typedef struct privateExponent
{
    bigNum              P;
    bigNum              Q;
    bigNum              dP_unused;
    bigNum              dQ_unused;
    bigNum              qInv_unused;
    bn_prime_t          entries[5];
} privateExponent;

#define     NEW_PRIVATE_EXPONENT(X)					\
    privateExponent         _##X;					\
    privateExponent         *X = RsaInitializeExponent(&(_##X))

					// libtpms added begin: keep old privateExponent
/* The privateExponentOld is part of the OBJECT and we keep it there even though
 * upstream got rid of it and stores Q, dP, dQ, and qInv by appending them to
 * P stored in TPMT_SENSITIVE.TPMU_SENSITIVE_COMPOSITE.TPM2B_PRIVATE_KEY_RSA
 */
typedef struct privateExponentOld
{
    bn_prime_t          Q;
    bn_prime_t          dP;
    bn_prime_t          dQ;
    bn_prime_t          qInv;
} privateExponent_t;

#include "BnMemory_fp.h"

static inline void
RsaInitializeExponentOld(
			 privateExponent_t      *pExp
			)
{
    BN_INIT(pExp->Q);
    BN_INIT(pExp->dP);
    BN_INIT(pExp->dQ);
    BN_INIT(pExp->qInv);
}					// libtpms added end

#endif      // _CRYPT_RSA_H

