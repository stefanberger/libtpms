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

//
// This verifies that information expected from the consumer's TpmConfiguration is
// set properly and consistently.
//
#ifndef _VERIFY_CONFIGURATION_H
#define _VERIFY_CONFIGURATION_H

// verify these defines are either YES or NO.
#define MUST_BE_0_OR_1(x) MUST_BE(((x) == 0) || ((x) == 1))

// Debug Options
MUST_BE_0_OR_1(DEBUG);
MUST_BE_0_OR_1(SIMULATION);
MUST_BE_0_OR_1(DRBG_DEBUG_PRINT);
MUST_BE_0_OR_1(CERTIFYX509_DEBUG);
MUST_BE_0_OR_1(USE_DEBUG_RNG);

// RSA Debug Options
MUST_BE_0_OR_1(RSA_INSTRUMENT);
MUST_BE_0_OR_1(USE_RSA_KEY_CACHE);
MUST_BE_0_OR_1(USE_KEY_CACHE_FILE);

// Test Options
MUST_BE_0_OR_1(ALLOW_FORCE_FAILURE_MODE);

// Internal checks
MUST_BE_0_OR_1(LIBRARY_COMPATIBILITY_CHECK);
MUST_BE_0_OR_1(COMPILER_CHECKS);
MUST_BE_0_OR_1(RUNTIME_SIZE_CHECKS);

// Compliance options
MUST_BE_0_OR_1(FIPS_COMPLIANT);
MUST_BE_0_OR_1(USE_SPEC_COMPLIANT_PROOFS);
MUST_BE_0_OR_1(SKIP_PROOF_ERRORS);

// Implementation alternatives - should not change external behavior
MUST_BE_0_OR_1(TABLE_DRIVEN_DISPATCH);
MUST_BE_0_OR_1(TABLE_DRIVEN_MARSHAL);
MUST_BE_0_OR_1(USE_MARSHALING_DEFINES);
MUST_BE_0_OR_1(COMPRESSED_LISTS);
MUST_BE_0_OR_1(USE_BIT_FIELD_STRUCTURES);
MUST_BE_0_OR_1(RSA_KEY_SIEVE);

// Implementation alternatives - changes external behavior
MUST_BE_0_OR_1(_DRBG_STATE_SAVE);
MUST_BE_0_OR_1(USE_DA_USED);
MUST_BE_0_OR_1(ENABLE_SELF_TESTS);
MUST_BE_0_OR_1(CLOCK_STOPS);
MUST_BE_0_OR_1(ACCUMULATE_SELF_HEAL_TIMER);
MUST_BE_0_OR_1(FAIL_TRACE);

// Vendor alternatives
// Check VENDOR_PERMANENT_AUTH_ENABLED & VENDOR_PERMANENT_AUTH_HANDLE are consistent
MUST_BE_0_OR_1(VENDOR_PERMANENT_AUTH_ENABLED);

#if VENDOR_PERMANENT_AUTH_ENABLED == YES
#  if !defined(VENDOR_PERMANENT_AUTH_HANDLE)		       \
    || VENDOR_PERMANENT_AUTH_HANDLE < TPM_RH_AUTH_00			\
    || VENDOR_PERMANENT_AUTH_HANDLE > TPM_RH_AUTH_FF
#    error VENDOR_PERMANENT_AUTH_ENABLED requires a valid definition for VENDOR_PERMANENT_AUTH_HANDLE, see Part2
#  endif
#else
#  if defined(VENDOR_PERMANENT_AUTH_HANDLE)
#    error VENDOR_PERMANENT_AUTH_HANDLE requires VENDOR_PERMANENT_AUTH_ENABLED to be YES
#  endif
#endif

// now check for inconsistent combinations of options
#if USE_KEY_CACHE_FILE && !USE_RSA_KEY_CACHE
#  error cannot use USE_KEY_CACHE_FILE if not using USE_RSA_KEY_CACHE
#endif

#if !DEBUG
#  if USE_KEY_CACHE_FILE || USE_RSA_KEY_CACHE || DRBG_DEBUG_PRINT	\
    || CERTIFYX509_DEBUG || USE_DEBUG_RNG
#    error using insecure options not in DEBUG mode.
#  endif
#endif

#if !SIMULATION
#  if USE_KEY_CACHE_FILE
#    error USE_KEY_CACHE_FILE requires SIMULATION
#  endif
#  if RSA_INSTRUMENT
#    error RSA_INSTRUMENT requires SIMULATION
#  endif
#  if USE_DEBUG_RNG
#    error USE_DEBUG_RNG requires SIMULATION
#  endif
#endif

#endif  // _VERIFY_CONFIGURATION_H
