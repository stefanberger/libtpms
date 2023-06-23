/********************************************************************************/
/*										*/
/*			    Build Switches	 				*/
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

// This file contains the build switches. This contains switches for multiple
// versions of the crypto-library so some may not apply to your environment.
// Each switch has an accompanying description below.
//
// clang-format off
#ifndef _TPM_BUILD_SWITCHES_H_
#define _TPM_BUILD_SWITCHES_H_

#if defined(YES) || defined(NO)
#  error YES and NO should be defined in TpmBuildSwitches.h
#endif
#if defined(SET) || defined(CLEAR)
#  error SET and CLEAR should be defined in TpmBuildSwitches.h
#endif

#define YES   1
#define SET   1
#define NO    0
#define CLEAR 0

// TRUE/FALSE may be coming from system headers, but if not, provide them.
#ifndef TRUE
#  define TRUE 1
#endif
#ifndef FALSE
#  define FALSE 0
#endif

// Need an unambiguous definition for DEBUG. Do not change this
#ifndef DEBUG
#  ifdef NDEBUG
#    define DEBUG NO
#  else
#    define DEBUG YES
#  endif
#elif(DEBUG != NO) && (DEBUG != YES)
#  error DEBUG should be 0 or 1
#endif

////////////////////////////////////////////////////////////////
// DEBUG OPTIONS
////////////////////////////////////////////////////////////////

// The SIMULATION switch allows certain other macros to be enabled. The things that
// can be enabled in a simulation include key caching, reproducible "random"
// sequences, instrumentation of the RSA key generation process, and certain other
// debug code. SIMULATION Needs to be defined as either YES or NO. This grouping of
// macros will make sure that it is set correctly. A simulated TPM would include a
// Virtual TPM. The interfaces for a Virtual TPM should be modified from the standard
// ones in the Simulator project.
#define SIMULATION                 NO			// libtpms: changed to NO

// If doing debug, can set the DRBG to print out the intermediate test values.
// Before enabling this, make sure that the dbgDumpMemBlock() function
// has been added someplace (preferably, somewhere in CryptRand.c)
#define DRBG_DEBUG_PRINT            (NO  * DEBUG)

// This define is used to control the debug for the CertifyX509 command.
#define CERTIFYX509_DEBUG           (NO * DEBUG)	// libtpms: NO

// This provides fixed seeding of the RNG when doing debug on a simulator. This
// should allow consistent results on test runs as long as the input parameters
// to the functions remains the same.
#define USE_DEBUG_RNG               (NO  * DEBUG)

////////////////////////////////////////////////////////////////
// RSA DEBUG OPTIONS
////////////////////////////////////////////////////////////////

// Enable the instrumentation of the sieve process. This is used to tune the sieve
// variables.
#define RSA_INSTRUMENT              (NO  * DEBUG)

// Enables use of the key cache. Default is YES
#define USE_RSA_KEY_CACHE           (NO  * DEBUG)

// Enables use of a file to store the key cache values so that the TPM will start
// faster during debug. Default for this is YES
#define USE_KEY_CACHE_FILE          (NO  * DEBUG)

////////////////////////////////////////////////////////////////
// TEST OPTIONS
////////////////////////////////////////////////////////////////
// The SIMULATION flag can enable test crypto behaviors and caching that
// significantly change the behavior of the code.  This flag controls only the
// g_forceFailureMode flag in the TPM library while leaving the rest of the TPM
// behavior alone.  Useful for testing when the full set of options controlled by
// SIMULATION may not be desired.
#define ALLOW_FORCE_FAILURE_MODE    NO		// libtpms: NO

////////////////////////////////////////////////////////////////
// Internal checks
////////////////////////////////////////////////////////////////

// Define this to run the function that checks the compatibility between the
// chosen big number math library and the TPM code. Not all ports use this.
#define LIBRARY_COMPATIBILITY_CHECK YES		// libtpms: YES

// In some cases, the relationship between two values may be dependent on things that
// change based on various selections like the chosen cryptographic libraries. It is
// possible that these selections will result in incompatible settings. These are often
// detectable by the compiler but it is not always possible to do the check in the
// preprocessor code. For example, when the check requires use of 'sizeof'() then the
// preprocessor can't do the comparison. For these cases, we include a special macro
// that, depending on the compiler will generate a warning to indicate if the check
// always passes or always fails because it involves fixed constants.
//
// In modern compilers this is now commonly known as a static_assert, but the precise
// implementation varies by compiler. CompilerDependencies.h defines MUST_BE as a macro
// that abstracts out the differences, and COMPILER_CHECKS can remove the checks where
// the current compiler doesn't support it.  COMPILER_CHECKS should be enabled if the
// compiler supports some form of static_assert.
// See the CompilerDependencies_*.h files for specific implementations per compiler.
#define COMPILER_CHECKS             YES

// Some of the values (such as sizes) are the result of different options set in
// TpmProfile.h. The combination might not be consistent. A function is defined
// (TpmSizeChecks()) that is used to verify the sizes at run time. To enable the
// function, define this parameter.
#define RUNTIME_SIZE_CHECKS        NO		// libtpms: NO

////////////////////////////////////////////////////////////////
// Compliance options
////////////////////////////////////////////////////////////////

// Enable extra behaviors to meet FIPS compliance requirements
#define FIPS_COMPLIANT              NO		// libtpms: NO

// Indicates if the implementation is to compute the sizes of the proof and primary
// seed size values based on the implemented algorithms.
#define USE_SPEC_COMPLIANT_PROOFS   YES

// Set this to allow compile to continue even though the chosen proof values
// do not match the compliant values. This is written so that someone would
// have to proactively ignore errors.
#define SKIP_PROOF_ERRORS           NO

////////////////////////////////////////////////////////////////
// Implementation alternatives - don't  change external behavior
////////////////////////////////////////////////////////////////

// Define TABLE_DRIVEN_DISPATCH to use tables rather than case statements
// for command dispatch and handle unmarshaling
#define TABLE_DRIVEN_DISPATCH       YES

// This define is used to enable the new table-driven marshaling code.
#define TABLE_DRIVEN_MARSHAL        NO

// This switch allows use of #defines in place of pass-through marshaling or
// unmarshaling code. A pass-through function just calls another function to do
// the required function and does no parameter checking of its own. The
// table-driven dispatcher calls directly to the lowest level
// marshaling/unmarshaling code and by-passes any pass-through functions.
#define USE_MARSHALING_DEFINES      YES

// Switch added to support packed lists that leave out space associated with
// unimplemented commands. Comment this out to use linear lists.
// Note: if vendor specific commands are present, the associated list is always
// in compressed form.
#define COMPRESSED_LISTS            NO /* libtpms: change in v0.10 */

// This define is used to eliminate the use of bit-fields. It can be enabled for big-
// or little-endian machines. For big-endian architectures that numbers bits in
// registers from left to right (MSb0) this must be enabled. Little-endian machines
// number from right to left with the least significant bit having assigned a bit
// number of 0. These are LSb0 machines (they are also little-endian so they are also
// least-significant byte 0 (LSB0) machines. Big-endian (MSB0) machines may number in
// either direction (MSb0 or LSb0). For an MSB0+MSb0 machine this value is required to
// be 'NO'
#define USE_BIT_FIELD_STRUCTURES    NO

// Enable the generation of RSA primes using a sieve.
#define RSA_KEY_SIEVE               YES

////////////////////////////////////////////////////////////////
// Implementation alternatives - changes external behavior
////////////////////////////////////////////////////////////////

// This switch enables the RNG state save and restore
#define _DRBG_STATE_SAVE            YES

// Definition to allow alternate behavior for non-orderly startup. If there is a
// chance that the TPM could not update 'failedTries'
#define USE_DA_USED                 YES		// libtpms: YES

// This switch is used to enable the self-test capability in AlgorithmTests.c
#define ENABLE_SELF_TESTS                   YES

// This switch indicates where clock epoch value should be stored. If this value
// defined, then it is assumed that the timer will change at any time so the
// nonce should be a random number kept in RAM. When it is not defined, then the
// timer only stops during power outages.
#define CLOCK_STOPS                 NO

// Indicate if the implementation is going to give lockout time credit for time up to
// the last orderly shutdown.
#define ACCUMULATE_SELF_HEAL_TIMER  YES

// If an assertion event is not going to produce any trace information (function and
// line number) then make FAIL_TRACE == NO
#define FAIL_TRACE                  YES

// TODO_RENAME_INC_FOLDER: public refers to the TPM_CoreLib public headers
#include "CompilerDependencies.h"

#endif  // _TPM_BUILD_SWITCHES_H_
