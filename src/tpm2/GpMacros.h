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
/*  (c) Copyright IBM Corp. and others, 2016 - 2024				*/
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
#if ENABLE_SELF_TESTS
#  define TPM_DO_SELF_TEST(alg)              \
      do                                     \
      {                                      \
          if(TEST_BIT(alg, g_toTest))        \
              CryptTestAlgorithm(alg, NULL); \
      } while(0)
#else
#  define TPM_DO_SELF_TEST(alg)
#endif  // ENABLE_SELF_TESTS

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

#ifndef NO_LONGJMP
// has longjmp
// necesary to reference Exit, even though the code is no-return
#  define TPM_FAIL_RETURN NORETURN void

// see discussion above about FAIL/FAIL_NORET
#  define FAIL(failCode)                   SETFAILED(failCode)
#  define FAIL_NORET(failCode)             SETFAILED(failCode)
#  define FAIL_IMMEDIATE(failCode, retval) SETFAILED(failCode)
#  define FAIL_BOOL(failCode)              SETFAILED(failCode)
#  define FAIL_RC(failCode)                SETFAILED(failCode)
#  define FAIL_VOID(failCode)              SETFAILED(failCode)
#  define FAIL_NULL(failCode)              SETFAILED(failCode)
#  define FAIL_EXIT(failCode, returnVar, returnCode)	     \
    do								     \
	{							     \
	    SETFAILED(failCode);				     \
	    goto Exit;						     \
	} while(0)

#else  // NO_LONGJMP
// no longjmp service is available
#  define TPM_FAIL_RETURN      void

// This macro is provided for existing code and should not be used in new code.
// see discussion above.
#  define FAIL(failCode)       FAIL_NORET(failCode)

// Be cautious with this macro, see discussion above.
#  define FAIL_NORET(failCode) SETFAILED(failCode)

// fail and immediately return void
#  define FAIL_VOID(failCode)		       \
    do						       \
	{					       \
	    SETFAILED(failCode);		       \
	    return;				       \
	} while(0)

// fail and immediately return a value
#  define FAIL_IMMEDIATE(failCode, retval)			   \
    do								   \
	{								\
	    SETFAILED(failCode);					\
	    return retval;						\
	} while(0)

// fail and return FALSE
#  define FAIL_BOOL(failCode) FAIL_IMMEDIATE(failCode, FALSE)

// fail and return TPM_RC_FAILURE
#  define FAIL_RC(failCode)   FAIL_IMMEDIATE(failCode, TPM_RC_FAILURE)

// fail and return NULL
#  define FAIL_NULL(failCode) FAIL_IMMEDIATE(failCode, NULL)

// fail and return using the goto exit pattern
#  define FAIL_EXIT(failCode, returnVar, returnCode)			\
    do									\
	{								\
	    SETFAILED(failCode);					\
	    returnVar = returnCode;					\
	    goto Exit;							\
	} while(0)

#endif

// This macro tests that a condition is TRUE and puts the TPM into failure mode
// if it is not. If longjmp is being used, then the macro makes a call from
// which there is no return. Otherwise, the function will return the given
// return code.
#define VERIFY(condition, failCode, returnCode)				\
    do									\
	{								\
	    if(!(condition))						\
		{							\
		    FAIL_IMMEDIATE(failCode, returnCode);		\
		}							\
	} while(0)

// this function also verifies a condition and enters failure mode, but sets a
// return value and jumps to Exit on failure - allowing for cleanup.
#define VERIFY_OR_EXIT(condition, failCode, returnVar, returnCode)	\
    do									\
	{								\
	    if(!(condition))						\
		{							\
		    FAIL_EXIT(failCode, returnVar, returnCode);		\
		}							\
	} while(0)

// verify the given TPM_RC is success and we are not in
// failure mode.  Otherwise, return immediately with TPM_RC_FAILURE.
// note that failure mode is checked first so that an existing FATAL_* error code
// is not overwritten with the default from this macro.
#define VERIFY_RC(rc)							\
    do									\
	{								\
	    if(g_inFailureMode)						\
		{							\
		    return TPM_RC_FAILURE;				\
		}							\
	    if(rc != TPM_RC_SUCCESS)					\
		{							\
		    FAIL_IMMEDIATE(FATAL_ERROR_ASSERT, TPM_RC_FAILURE); \
		}							\
	} while(0)

// verify the TPM is not in failure mode or return failure
#define VERIFY_NOT_FAILED()						\
    do									\
	{								\
	    if(g_inFailureMode)						\
		{							\
		    return TPM_RC_FAILURE;				\
		}							\
	} while(0)

// Enter failure mode if the given TPM_RC is not success, return void.
#define VERIFY_RC_VOID(rc)						\
    do									\
	{								\
	    if(g_inFailureMode)						\
		{							\
		    return;						\
		}							\
	    if(rc != TPM_RC_SUCCESS)					\
		{							\
		    FAIL_VOID(FATAL_ERROR_ASSERT);			\
		}							\
	} while(0)

// These VERIFY_CRYPTO macros all set failure mode to FATAL_ERROR_CRYPTO
// and immediately return.  The general way to parse the names is:
// VERIFY_CRYPTO_[conditionType]_[OR_EXIT]_[retValType]
// if conditionType is omitted, it is taken as BOOL.
// Without OR_EXIT, implies an immediate return. Thus VERIFY_CRYPTO_BOOL:
// 1. check fn against TRUE
// 2. if false,  set failure mode to FATAL_ERROR_CRYPTO
// 3. immediately return FALSE.
// and, VERIFY_CRYPTO_OR_EXIT_RC translates to:
// 1. Check a BOOL
// 2. If false, set failure mode with FATAL_ERROR_CRYPTO,
// 3. assume retVal is type TPM_RC, set it to TPM_RC_FAILURE
// 4. Goto Exit
// while VERIFY_CRYPTO_RC_OR_EXIT translates to:
// 1. Check fn result against TPM_RC_SUCCESS
// 2. if not equal, set failure mode to FATAL_ERROR_CRYPTO
// 3. assume retVal is type TPM_RC, set it to TPM_RC_FAILURE
// 4. Goto Exit.
#define VERIFY_CRYPTO(fn) VERIFY((fn), FATAL_ERROR_CRYPTO, TPM_RC_FAILURE)

#define VERIFY_CRYPTO_BOOL(fn) VERIFY((fn), FATAL_ERROR_CRYPTO, FALSE)

#define VERIFY_CRYPTO_OR_NULL(fn) VERIFY((fn), FATAL_ERROR_CRYPTO, NULL)

// these VERIFY_CRYPTO macros all set a result value and goto Exit
#define VERIFY_CRYPTO_OR_EXIT(fn, returnVar, returnCode)		\
    VERIFY_OR_EXIT(fn, FATAL_ERROR_CRYPTO, returnVar, returnCode);

// these VERIFY_CRYPTO_OR_EXIT functions assume the return value variable is
// named retVal
#define VERIFY_CRYPTO_OR_EXIT_RC(fn)					\
    VERIFY_CRYPTO_OR_EXIT_GENERIC(fn, retVal, TPM_RC_FAILURE)

#define VERIFY_CRYPTO_OR_EXIT_FALSE(fn)				\
    VERIFY_CRYPTO_OR_EXIT_GENERIC(fn, retVal, FALSE)

#define VERIFY_CRYPTO_RC_OR_EXIT(fn)			       \
    do							       \
	{							       \
	    TPM_RC rc = fn;					       \
	    if(rc != TPM_RC_SUCCESS)				       \
		{							\
		    FAIL_EXIT(FATAL_ERROR_CRYPTO, retVal, rc);		\
		}							\
	} while(0)

#if(defined EMPTY_ASSERT) && (EMPTY_ASSERT != NO)
#  define pAssert(a) ((void)0)
#else
#  define pAssert(a)					   \
    do							   \
	{							   \
	    if(!(a))						   \
		FAIL(FATAL_ERROR_PARAMETER);			   \
	} while(0)

#  define pAssert_ZERO(a)						\
    do									\
	{								\
	    if(!(a))							\
		FAIL_IMMEDIATE(FATAL_ERROR_ASSERT, 0);			\
	} while(0);

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

#  define pAssert_NULL(a)			     \
    do						     \
	{						     \
	    if(!(a))					     \
		FAIL_NULL(FATAL_ERROR_ASSERT);		     \
	} while(0);

// using FAIL_NORET isn't optimium but is available in limited cases that
// result in wrong calculated values, and can be checked later
// but should have no vulnerability implications.
#  define pAssert_NORET(a)			      \
    {						      \
	if(!(a))					      \
	    FAIL_NORET(FATAL_ERROR_ASSERT);		      \
    }

// this macro is used where a calling code has been verified to function correctly
// when the failing assert immediately returns without an error code.
// this can be because either the caller checks the fatal error flag, or
// the state is safe and a higher-level check will catch it.
#  define pAssert_VOID_OK(a)			     \
    {						     \
	if(!(a))					     \
	    FAIL_VOID(FATAL_ERROR_ASSERT);		     \
    }

#endif

// These macros are commonly used in the "Crypt" code as a way to keep listings from
// getting too long. This is not to save paper but to allow one to see more
// useful stuff on the screen at any given time.  Neither macro sets failure mode.
#define ERROR_EXIT(returnCode)	       \
    do				       \
	{				       \
	    retVal = returnCode;	       \
	    goto Exit;			       \
	} while(0)

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

#include "TpmCalculatedAttributes.h"

#endif  // GP_MACROS_H
