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

// This file contains the build switches. This contains switches for multiple
// versions of the crypto-library so some may not apply to your environment.
//

#ifndef _COMPILER_DEPENDENCIES_H_
#define _COMPILER_DEPENDENCIES_H_

#if defined(__GNUC__)
#  include "CompilerDependencies_gcc.h"
#elif defined(_MSC_VER)
#  include "CompilerDependencies_msvc.h"
#else
#  error unexpected
#endif

#include <stdint.h>

// Things that are not defined should be defined as NULL

#ifndef NORETURN
#  define NORETURN
#endif
#ifndef LIB_EXPORT
#  define LIB_EXPORT
#endif
#ifndef LIB_IMPORT
#  define LIB_IMPORT
#endif
#ifndef _REDUCE_WARNING_LEVEL_
#  define _REDUCE_WARNING_LEVEL_(n)
#endif
#ifndef _NORMAL_WARNING_LEVEL_
#  define _NORMAL_WARNING_LEVEL_
#endif
#ifndef NOT_REFERENCED
#  define NOT_REFERENCED(x) (x = x)
#endif

#ifdef _POSIX_
typedef int SOCKET;
#endif

#if !defined(TPM_STATIC_ASSERT) || !defined(COMPILER_CHECKS)
#  error Expect definitions of COMPILER_CHECKS and TPM_STATIC_ASSERT
#elif COMPILER_CHECKS
// pre static_assert static_assert
#  define MUST_BE(e) TPM_STATIC_ASSERT(e)

#else
// intentionally disabled, fine.
#  define MUST_BE(e)
#endif

#endif  // _COMPILER_DEPENDENCIES_H_
