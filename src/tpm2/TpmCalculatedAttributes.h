/********************************************************************************/
/*										*/
/*			     				*/
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
/*  (c) Copyright IBM Corp. and others, 2023					*/
/*										*/
/********************************************************************************/

#ifndef _TPM_CALCULATED_ATTRIBUTES_H_
#define _TPM_CALCULATED_ATTRIBUTES_H_

#include "TpmAlgorithmDefines.h"
#include "GpMacros.h"

#define JOIN(x, y)       x##y
#define JOIN3(x, y, z)   x##y##z
#define CONCAT(x, y)     JOIN(x, y)
#define CONCAT3(x, y, z) JOIN3(x, y, z)

//** Derived from Vendor-specific values
// Values derived from vendor specific settings in TpmProfile.h
#define PCR_SELECT_MIN    ((PLATFORM_PCR + 7) / 8)
#define PCR_SELECT_MAX    ((IMPLEMENTATION_PCR + 7) / 8)
#define MAX_ORDERLY_COUNT ((1 << ORDERLY_BITS) - 1)
#define RSA_MAX_PRIME     (MAX_RSA_KEY_BYTES / 2)
#define RSA_PRIVATE_SIZE  (RSA_MAX_PRIME * 5)

// If CONTEXT_INTEGRITY_HASH_ALG is defined, then the vendor is using the old style
// table. Otherwise, pick the "strongest" implemented hash algorithm as the context
// hash.
#ifndef CONTEXT_HASH_ALGORITHM
#  if defined ALG_SHA3_512 && ALG_SHA3_512 == YES
#    define CONTEXT_HASH_ALGORITHM SHA3_512
#  elif defined ALG_SHA512 && ALG_SHA512 == YES
#    define CONTEXT_HASH_ALGORITHM SHA512
#  elif defined ALG_SHA3_384 && ALG_SHA3_384 == YES
#    define CONTEXT_HASH_ALGORITHM SHA3_384
#  elif defined ALG_SHA384 && ALG_SHA384 == YES
#    define CONTEXT_HASH_ALGORITHM SHA384
#  elif defined ALG_SHA3_256 && ALG_SHA3_256 == YES
#    define CONTEXT_HASH_ALGORITHM SHA3_256
#  elif defined ALG_SHA256 && ALG_SHA256 == YES
#    define CONTEXT_HASH_ALGORITHM SHA256
#  elif defined ALG_SM3_256 && ALG_SM3_256 == YES
#    define CONTEXT_HASH_ALGORITHM SM3_256
#  elif defined ALG_SHA1 && ALG_SHA1 == YES
#    define CONTEXT_HASH_ALGORITHM SHA1
#  endif
#  define CONTEXT_INTEGRITY_HASH_ALG CONCAT(TPM_ALG_, CONTEXT_HASH_ALGORITHM)
#endif

#ifndef CONTEXT_INTEGRITY_HASH_SIZE
#  define CONTEXT_INTEGRITY_HASH_SIZE CONCAT(CONTEXT_HASH_ALGORITHM, _DIGEST_SIZE)
#endif
#if ALG_RSA
#  define RSA_SECURITY_STRENGTH				     \
    (MAX_RSA_KEY_BITS >= 15360						\
     ? 256								\
     : (MAX_RSA_KEY_BITS >= 7680					\
	? 192								\
	: (MAX_RSA_KEY_BITS >= 3072					\
	   ? 128							\
	   : (MAX_RSA_KEY_BITS >= 2048					\
	      ? 112							\
	      : (MAX_RSA_KEY_BITS >= 1024 ? 80 : 0)))))
#else
#  define RSA_SECURITY_STRENGTH 0
#endif  // ALG_RSA

#if ALG_ECC
#  define ECC_SECURITY_STRENGTH		\
    (MAX_ECC_KEY_BITS >= 521				\
     ? 256								\
     : (MAX_ECC_KEY_BITS >= 384 ? 192 : (MAX_ECC_KEY_BITS >= 256 ? 128 : 0)))
#else
#  define ECC_SECURITY_STRENGTH 0
#endif  // ALG_ECC

#define MAX_ASYM_SECURITY_STRENGTH MAX(RSA_SECURITY_STRENGTH, ECC_SECURITY_STRENGTH)

#define MAX_HASH_SECURITY_STRENGTH ((CONTEXT_INTEGRITY_HASH_SIZE * 8) / 2)

// Unless some algorithm is broken...
#define MAX_SYM_SECURITY_STRENGTH MAX_SYM_KEY_BITS

#define MAX_SECURITY_STRENGTH_BITS	    \
    MAX(MAX_ASYM_SECURITY_STRENGTH,					\
	MAX(MAX_SYM_SECURITY_STRENGTH, MAX_HASH_SECURITY_STRENGTH))

// This is the size that was used before the 1.38 errata requiring that P1.14.4 be
// followed
#define PROOF_SIZE CONTEXT_INTEGRITY_HASH_SIZE

// As required by P1.14.4
#define COMPLIANT_PROOF_SIZE						\
    (MAX(CONTEXT_INTEGRITY_HASH_SIZE, (2 * MAX_SYM_KEY_BYTES)))

// As required by P1.14.3.1
#define COMPLIANT_PRIMARY_SEED_SIZE BITS_TO_BYTES(MAX_SECURITY_STRENGTH_BITS * 2)

// This is the pre-errata version
#ifndef PRIMARY_SEED_SIZE
#  define PRIMARY_SEED_SIZE PROOF_SIZE
#endif

#if USE_SPEC_COMPLIANT_PROOFS
#  undef PROOF_SIZE
#  define PROOF_SIZE COMPLIANT_PROOF_SIZE
#  undef PRIMARY_SEED_SIZE
#  define PRIMARY_SEED_SIZE COMPLIANT_PRIMARY_SEED_SIZE
#endif  // USE_SPEC_COMPLIANT_PROOFS

#if !SKIP_PROOF_ERRORS
#  if PROOF_SIZE < COMPLIANT_PROOF_SIZE
#    error "PROOF_SIZE is not compliant with TPM specification"
#  endif
#  if PRIMARY_SEED_SIZE < COMPLIANT_PRIMARY_SEED_SIZE
#    error Non-compliant PRIMARY_SEED_SIZE
#  endif
#endif  // !SKIP_PROOF_ERRORS

// If CONTEXT_ENCRYPT_ALG is defined, then the vendor is using the old style table
#if defined CONTEXT_ENCRYPT_ALG
#  undef CONTEXT_ENCRYPT_ALGORITHM
#  if CONTEXT_ENCRYPT_ALG == ALG_AES_VALUE
#    define CONTEXT_ENCRYPT_ALGORITHM AES
#  elif CONTEXT_ENCRYPT_ALG == ALG_SM4_VALUE
#    define CONTEXT_ENCRYPT_ALGORITHM SM4
#  elif CONTEXT_ENCRYPT_ALG == ALG_CAMELLIA_VALUE
#    define CONTEXT_ENCRYPT_ALGORITHM CAMELLIA
#  else
#    error Unknown value for CONTEXT_ENCRYPT_ALG
#  endif  // CONTEXT_ENCRYPT_ALG == ALG_AES_VALUE
#else
#  define CONTEXT_ENCRYPT_ALG CONCAT3(ALG_, CONTEXT_ENCRYPT_ALGORITHM, _VALUE)
#endif  // CONTEXT_ENCRYPT_ALG
#define CONTEXT_ENCRYPT_KEY_BITS  CONCAT(CONTEXT_ENCRYPT_ALGORITHM, _MAX_KEY_SIZE_BITS)
#define CONTEXT_ENCRYPT_KEY_BYTES ((CONTEXT_ENCRYPT_KEY_BITS + 7) / 8)

// This is updated to follow the requirement of P2 that the label not be larger
// than 32 bytes.
#ifndef LABEL_MAX_BUFFER
#  define LABEL_MAX_BUFFER MIN(32, MAX(MAX_ECC_KEY_BYTES, MAX_DIGEST_SIZE))
#endif

// This bit is used to indicate that an authorization ticket expires on TPM Reset
// and TPM Restart. It is added to the timeout value returned by TPM2_PoliySigned()
// and TPM2_PolicySecret() and used by TPM2_PolicyTicket(). The timeout value is
// relative to Time (g_time). Time is reset whenever the TPM loses power and cannot
// be moved forward by the user (as can Clock). 'g_time' is a 64-bit value expressing
// time in ms. Stealing the MSb for a flag means that the TPM needs to be reset
// at least once every 292,471,208 years rather than once every 584,942,417 years.
#define EXPIRATION_BIT ((UINT64)1 << 63)

// This definition is moved from TpmProfile.h because it is not actually vendor-
// specific. It has to be the same size as the 'sequence' parameter of a TPMS_CONTEXT
// and that is a UINT64. So, this is an invariant value
#define CONTEXT_COUNTER UINT64
#endif  // _TPM_CALCULATED_ATTRIBUTES_H_
