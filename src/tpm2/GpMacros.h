/********************************************************************************/
/*										*/
/*		This file is a collection of miscellaneous macros.     		*/
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
// This file is a collection of miscellaneous macros.

#ifndef GP_MACROS_H
#define GP_MACROS_H

#ifndef NULL
#  define NULL 0
#endif

#include "endian_swap.h"
#include "VendorInfo.h"

//** For Self-test
// These macros are used in CryptUtil to invoke the incremental self test.
#if SELF_TEST
#  define TEST(alg)				     \
    do						     \
	{						     \
	    if(TEST_BIT(alg, g_toTest))			     \
		CryptTestAlgorithm(alg, NULL);		     \
	} while(0)
#else
#  define TEST(alg)
#endif  // SELF_TEST

	//** For Failures
#if defined _POSIX_
#  define FUNCTION_NAME __func__     /* libtpms changed */
#else
#  define FUNCTION_NAME __FUNCTION__
#endif

#if defined(FAIL_TRACE) && FAIL_TRACE != 0
#  define CODELOCATOR() FUNCTION_NAME, __LINE__
#else  // !FAIL_TRACE
// if provided, use the definition of CODELOCATOR from TpmConfiguration so
// implementor can customize this.
#  ifndef CODELOCATOR
#    define CODELOCATOR() 0
#  endif
#endif  // FAIL_TRACE

	// SETFAILED calls TpmFail.  It may or may not return based on the NO_LONGJMP flag.
	// CODELOCATOR is a macro that expands to either one 64-bit value that encodes the
	// location, or two parameters: Function Name and Line Number.
#define SETFAILED(errorCode) (TpmFail(CODELOCATOR(), errorCode))

// If implementation is using longjmp, then calls to TpmFail() will never
// return.  However, without longjmp facility, TpmFail will return while most of
// the code currently expects FAIL() calls to immediately abort the current
// command. If they don't, some commands return success instead of failure.  The
// family of macros below are provided to allow the code to be modified to
// correctly propagate errors correctly, based on the context.
//
// * Some functions, particularly the ECC crypto have state cleanup at the end
//   of the function and need to use the goto Exit pattern.
// * Other functions return TPM_RC values, which should return TPM_RC_FAILURE
// * Still other functions return an isOK boolean and need to return FALSE.
//
// if longjmp is available, all these macros just call SETFAILED and immediately
// abort.  Note any of these approaches could leak memory if the crypto adapter
// libraries are using dynamic memory.
//
// FAIL vs. FAIL_NORET
// ===================
// Be cautious with these macros.  FAIL_NORET is intended as an affirmation
// that the upstream code calling the function using this macro has been
// investigated to confirm that upstream functions correctly handle this
// function putting the TPM into failure mode without returning an error.
//
// The TPM library was originally written with a lot of error checking omitted,
// which means code occurring after a FAIL macro may not expect to be called
// when the TPM is in failure mode.  When NO_LONGJMP is false (the system has a
// longjmp API), then none of that code is executed because the sample platform
// sets up longjmp before calling ExecuteCommand.  However, in the NO_LONGJMP
// case, code following a FAIL or FAIL_NORET macro will get run.  The
// conservative assumption is that code is untested and may be unsafe in such a
// situation.  FAIL_NORET can replace FAIL when the code has been reviewed to
// ensure the post-FAIL code is safe.  Of course, this is a point-in-time
// assertion that is only true when the FAIL_NORET macro is first inserted;
// hence it is better to use one of the early-exit macros to immediately return.
// However, the necessary return-code plumbing may be large and FAIL/FAIL_NORET
// are provided to support gradual improvement over time.
#if !FAIL_TRACE
#   define FAIL(errorCode) (TpmFail(errorCode))
#   define LOG_FAILURE(errorCode) (TpmLogFailure(errorCode))
#else
#   define FAIL(errorCode)        TpmFail(FUNCTION_NAME, __LINE__, errorCode)
#   define LOG_FAILURE(errorCode) TpmLogFailure(FUNCTION_NAME, __LINE__, errorCode)
#endif
#  define FAIL_RC(failCode)                SETFAILED(failCode)
/* If implementation is using longjmp, then the call to TpmFail() does not return and the compiler
   will complain about unreachable code that comes after. To allow for not having longjmp, TpmFail()
   will return and the subsequent code will be executed. This macro accounts for the difference. */

#ifndef NO_LONGJMP
// has longjmp
// necesary to reference Exit, even though the code is no-return
#  define FAIL_RETURN(returnCode)
#  define TPM_FAIL_RETURN NORETURN void

#  define FAIL_BOOL(failCode)              SETFAILED(failCode)

#else  // NO_LONGJMP
// no longjmp service is available
#  define FAIL_RETURN(returnCode) return(returnCode)
#  define TPM_FAIL_RETURN      void

// fail and return FALSE
#  define FAIL_BOOL(failCode) FAIL_IMMEDIATE(failCode, FALSE)

#endif

#if(defined EMPTY_ASSERT) && (EMPTY_ASSERT != NO)
#  define pAssert(a) ((void)0)
#else
#  define pAssert(a)					   \
    do							   \
	{							   \
	    if(!(a))						   \
		FAIL(FATAL_ERROR_PARAMETER);			   \
	} while(0)

#  define pAssert_RC(a)				   \
    do						   \
	{						   \
	    if(!(a))					   \
		FAIL_RC(FATAL_ERROR_ASSERT);		   \
	} while(0);

#  define pAssert_BOOL(a)			     \
    do						     \
	{						     \
	    if(!(a))					     \
		FAIL_BOOL(FATAL_ERROR_ASSERT);		     \
	} while(0);

#endif

/* 5.10.4	Derived from Vendor-specific values */
/* Values derived from vendor specific settings in TpmProfile.h */
#define PCR_SELECT_MIN          ((PLATFORM_PCR+7)/8)
#define PCR_SELECT_MAX          ((IMPLEMENTATION_PCR+7)/8)
#define MAX_ORDERLY_COUNT       ((1 << ORDERLY_BITS) - 1)
#define RSA_MAX_PRIME           (MAX_RSA_KEY_BYTES / 2)
#define RSA_PRIVATE_SIZE        (RSA_MAX_PRIME * 5)

/* This is used commonly in the Crypt code as a way to keep listings from getting too long. This is
   not to save paper but to allow one to see more useful stuff on the screen at any given time. */
#define     ERROR_RETURN(returnCode)		\
    {						\
	retVal = returnCode;			\
	goto Exit;				\
    }

// braces are necessary for this usage:
// if (y)
//     GOTO_ERROR_UNLESS(x)
// else ...
// without braces the else would attach to the GOTO macro instead of the
// outer if statement; given the amount of TPM code that doesn't use braces on
// if statements, this is a live risk.
#define GOTO_ERROR_UNLESS(_X)		      \
    do					      \
	{				      \
	    if(!(_X))				      \
		goto Error;			      \
	} while(0)

#include "MinMax.h"

#ifndef IsOdd
#  define IsOdd(a) (((a)&1) != 0)
#endif

#ifndef BITS_TO_BYTES
#  define BITS_TO_BYTES(bits) (((bits) + 7) >> 3)
#endif

// These are defined for use when the size of the vector being checked is known
// at compile time.
#define TEST_BIT(bit, vector)  TestBit((bit), (BYTE*)&(vector), sizeof(vector))
#define SET_BIT(bit, vector)   SetBit((bit), (BYTE*)&(vector), sizeof(vector))
#define CLEAR_BIT(bit, vector) ClearBit((bit), (BYTE*)&(vector), sizeof(vector))

// The following definitions are used if they have not already been defined. The
// defaults for these settings are compatible with ISO/IEC 9899:2011 (E)
#ifndef LIB_EXPORT
#  define LIB_EXPORT
#  define LIB_IMPORT
#endif
#ifndef NORETURN
#  define NORETURN _Noreturn
#endif
#ifndef NOT_REFERENCED
#  define NOT_REFERENCED(x = x) ((void)(x))
#endif

#define STD_RESPONSE_HEADER (sizeof(TPM_ST) + sizeof(UINT32) + sizeof(TPM_RC))
#define JOIN(x,y) x##y
#define JOIN3(x, y, z) x##y##z
#define CONCAT(x,y) JOIN(x, y)
#define CONCAT3(x, y, z) JOIN3(x,y,z)

/*     If CONTEXT_INTEGRITY_HASH_ALG is defined, then the vendor is using the old style
       table. Otherwise, pick the strongest implemented hash algorithm as the context hash. */

#ifndef CONTEXT_HASH_ALGORITHM
#   if defined ALG_SHA3_512 && ALG_SHA3_512 == YES
#       define CONTEXT_HASH_ALGORITHM   SHA3_512
#   elif defined ALG_SHA512 && ALG_SHA512 == YES
#       define CONTEXT_HASH_ALGORITHM    SHA512
#   elif defined ALG_SHA3_384 && ALG_SHA3_384 == YES
#       define CONTEXT_HASH_ALGORITHM    SHA3_384
#   elif defined ALG_SHA384 && ALG_SHA384 == YES
#       define CONTEXT_HASH_ALGORITHM    SHA384
#   elif defined ALG_SHA3_256 && ALG_SHA3_256 == YES
#       define CONTEXT_HASH_ALGORITHM    SHA3_256
#   elif defined ALG_SHA256 && ALG_SHA256 == YES
#       define CONTEXT_HASH_ALGORITHM    SHA256
#   elif defined ALG_SM3_256 && ALG_SM3_256 == YES
#       define CONTEXT_HASH_ALGORITHM    SM3_256
#   elif defined ALG_SHA1 && ALG_SHA1 == YES
#       define CONTEXT_HASH_ALGORITHM  SHA1
#   endif
#   define CONTEXT_INTEGRITY_HASH_ALG  CONCAT(TPM_ALG_, CONTEXT_HASH_ALGORITHM)
#if CONTEXT_HASH_ALGORITHM != SHA512	// libtpms added begin
#error CONTEXT_HASH_ALGORITHM must remain SHA512
#endif					// libtpms added end
#endif

#ifndef CONTEXT_INTEGRITY_HASH_SIZE
#define CONTEXT_INTEGRITY_HASH_SIZE CONCAT(CONTEXT_HASH_ALGORITHM, _DIGEST_SIZE)
#endif
#if ALG_RSA
#define     RSA_SECURITY_STRENGTH (MAX_RSA_KEY_BITS >= 15360 ? 256 :	\
				  (MAX_RSA_KEY_BITS >=  7680 ? 192 :	\
				  (MAX_RSA_KEY_BITS >=  3072 ? 128 :	\
				  (MAX_RSA_KEY_BITS >=  2048 ? 112 :    \
				  (MAX_RSA_KEY_BITS >=  1024 ?  80 :  0)))))
#else
#define     RSA_SECURITY_STRENGTH   0
#endif // ALG_RSA
#if ALG_ECC
#define     ECC_SECURITY_STRENGTH (MAX_ECC_KEY_BITS >= 521 ? 256 :	\
				  (MAX_ECC_KEY_BITS >= 384 ? 192 :	\
				  (MAX_ECC_KEY_BITS >= 256 ? 128 : 0)))
#else
#define     ECC_SECURITY_STRENGTH   0
#endif // ALG_ECC
#define     MAX_ASYM_SECURITY_STRENGTH					\
    MAX(RSA_SECURITY_STRENGTH, ECC_SECURITY_STRENGTH)
#define     MAX_HASH_SECURITY_STRENGTH  ((CONTEXT_INTEGRITY_HASH_SIZE * 8) / 2)

/*     Unless some algorithm is broken... */

#define     MAX_SYM_SECURITY_STRENGTH   MAX_SYM_KEY_BITS
#define MAX_SECURITY_STRENGTH_BITS					\
    MAX(MAX_ASYM_SECURITY_STRENGTH,					\
	MAX(MAX_SYM_SECURITY_STRENGTH,					\
	    MAX_HASH_SECURITY_STRENGTH))
/*     This is the size that was used before the 1.38 errata requiring that P1.14.4 be followed */
#define PROOF_SIZE      CONTEXT_INTEGRITY_HASH_SIZE
/*     As required by P1.14.4 */
#define COMPLIANT_PROOF_SIZE						\
    (MAX(CONTEXT_INTEGRITY_HASH_SIZE, (2 * MAX_SYM_KEY_BYTES)))
/*     As required by P1.14.3.1 */
#define COMPLIANT_PRIMARY_SEED_SIZE				\
    BITS_TO_BYTES(MAX_SECURITY_STRENGTH_BITS * 2)
/*     This is the pre-errata version */
#ifndef PRIMARY_SEED_SIZE
#   define PRIMARY_SEED_SIZE    PROOF_SIZE
#endif
#if USE_SPEC_COMPLIANT_PROOFS
#   undef PROOF_SIZE
#   define PROOF_SIZE           COMPLIANT_PROOF_SIZE
#   undef PRIMARY_SEED_SIZE
#   define PRIMARY_SEED_SIZE    COMPLIANT_PRIMARY_SEED_SIZE
#endif  // USE_SPEC_COMPLIANT_PROOFS
#if !SKIP_PROOF_ERRORS
#   if PROOF_SIZE < COMPLIANT_PROOF_SIZE
#       error "PROOF_SIZE is not compliant with TPM specification"
#   endif
#   if PRIMARY_SEED_SIZE < COMPLIANT_PRIMARY_SEED_SIZE
#       error  "Non-compliant PRIMARY_SEED_SIZE"
#   endif
#endif	// !SKIP_PROOF_ERRORS

/* If CONTEXT_ENCRYPT_ALG is defined, then the vendor is using the old style table */
#if defined CONTEXT_ENCRYPT_ALG
#   undef CONTEXT_ENCRYPT_ALGORITHM
#   if CONTEXT_ENCRYPT_ALG == ALG_AES_VALUE
#       define CONTEXT_ENCRYPT_ALGORITHM  AES
#   elif CONTEXT_ENCRYPT_ALG == ALG_SM4_VALUE
#       define CONTEXT_ENCRYPT_ALGORITHM  SM4
#   elif CONTEXT_ENCRYPT_ALG == ALG_CAMELLIA_VALUE
#       define CONTEXT_ENCRYPT_ALGORITHM  CAMELLIA
#   elif CONTEXT_ENCRYPT_ALG == ALG_TDES_VALUE
#   error Are you kidding?
#   else
#       error Unknown value for CONTEXT_ENCRYPT_ALG
#   endif // CONTEXT_ENCRYPT_ALG == ALG_AES_VALUE
#else
#   define CONTEXT_ENCRYPT_ALG						\
    CONCAT3(ALG_, CONTEXT_ENCRYPT_ALGORITHM, _VALUE)
#endif  // CONTEXT_ENCRYPT_ALG
#define CONTEXT_ENCRYPT_KEY_BITS					\
    CONCAT(CONTEXT_ENCRYPT_ALGORITHM, _MAX_KEY_SIZE_BITS)
#define CONTEXT_ENCRYPT_KEY_BYTES       ((CONTEXT_ENCRYPT_KEY_BITS+7)/8)

/* This is updated to follow the requirement of P2 that the label not be larger than 32 bytes. */
#ifndef LABEL_MAX_BUFFER
#define LABEL_MAX_BUFFER MIN(32, MAX(MAX_ECC_KEY_BYTES, MAX_DIGEST_SIZE))
#endif
// This bit is used to indicate that an authorization ticket expires on TPM Reset
// and TPM Restart. It is added to the timeout value returned by TPM2_PoliySigned()
// and TPM2_PolicySecret() and used by TPM2_PolicyTicket(). The timeout value is
// relative to Time (g_time). Time is reset whenever the TPM loses power and cannot
// be moved forward by the user (as can Clock). 'g_time' is a 64-bit value expressing
// time in ms. Stealing the MSb for a flag means that the TPM needs to be reset
// at least once every 292,471,208 years rather than once every 584,942,417 years.
#define EXPIRATION_BIT ((UINT64)1 << 63)

// Check for consistency of the bit ordering of bit fields
#if BIG_ENDIAN_TPM && MOST_SIGNIFICANT_BIT_0 && USE_BIT_FIELD_STRUCTURES
#  error "Settings not consistent"
#endif

// These macros are used to handle the variation in handling of bit fields. If
#if USE_BIT_FIELD_STRUCTURES  // The default, old version, with bit fields
#  define IS_ATTRIBUTE(a, type, b)    ((a.b) != 0)
#  define SET_ATTRIBUTE(a, type, b)   (a.b = SET)
#  define CLEAR_ATTRIBUTE(a, type, b) (a.b = CLEAR)
#  define GET_ATTRIBUTE(a, type, b)   (a.b)
#  define TPMA_ZERO_INITIALIZER()		  \
    {							  \
	0						  \
    }
#else
#  define IS_ATTRIBUTE(a, type, b)    ((a & type##_##b) != 0)
#  define SET_ATTRIBUTE(a, type, b)   (a |= type##_##b)
#  define CLEAR_ATTRIBUTE(a, type, b) (a &= ~type##_##b)
#  define GET_ATTRIBUTE(a, type, b)   (type)((a & type##_##b) >> type##_##b##_SHIFT)
#  define TPMA_ZERO_INITIALIZER()     (0)
#endif

// These macros determine if the values in this file are referenced or instanced.
// Global.c defines GLOBAL_C so all the values in this file will be instanced in
// Global.obj. For all other files that include this file, the values will simply
// be external references. For constants, there can be an initializer.
#ifndef EXTERN
#  ifdef GLOBAL_C
#    define EXTERN
#  else
#    define EXTERN extern
#  endif
#endif  // EXTERN

#ifdef GLOBAL_C
#  define INITIALIZER(_value_) = _value_
#else
#  define INITIALIZER(_value_)
#endif

// This macro will create an OID. All OIDs are in DER form with a first octet of
// 0x06 indicating an OID fallowed by an octet indicating the number of octets in the
// rest of the OID. This allows a user of this OID to know how much/little to copy.
#define MAKE_OID(NAME) EXTERN const BYTE OID##NAME[] INITIALIZER({OID##NAME##_VALUE})

// This definition is moved from TpmProfile.h because it is not actually vendor-
// specific. It has to be the same size as the 'sequence' parameter of a TPMS_CONTEXT
// and that is a UINT64. So, this is an invariant value
#define CONTEXT_COUNTER UINT64

#endif  // GP_MACROS_H
