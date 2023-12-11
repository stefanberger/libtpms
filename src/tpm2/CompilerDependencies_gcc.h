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

// This file contains compiler specific switches.
// These definitions are for the GCC compiler
//

#ifndef _COMPILER_DEPENDENCIES_GCC_H_
#define _COMPILER_DEPENDENCIES_GCC_H_

#if !defined(__GNUC__)
#  error CompilerDependencies_gcc.h included for wrong compiler
#endif

// don't warn on unused local typedefs, they are used as a
// cross-compiler static_assert
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-local-typedefs"
#pragma GCC diagnostic pop

#undef _MSC_VER
#undef WIN32

#ifndef WINAPI
#  define WINAPI
#endif
#ifndef __pragma
#  define __pragma(x)
#endif
    /* libtpms added begin */
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 2)
#  define REVERSE_ENDIAN_16(_Number) __builtin_bswap16(_Number)
#  define REVERSE_ENDIAN_32(_Number) __builtin_bswap32(_Number)
#  define REVERSE_ENDIAN_64(_Number) __builtin_bswap64(_Number)
#else
#  if defined __linux__ || defined __CYGWIN__
#    include <byteswap.h>
#    define REVERSE_ENDIAN_16(_Number) bswap_16(_Number)
#    define REVERSE_ENDIAN_32(_Number) bswap_32(_Number)
#    define REVERSE_ENDIAN_64(_Number) bswap_64(_Number)
#  elif defined __OpenBSD__
#    include <endian.h>
#    define REVERSE_ENDIAN_16(_Number) swap16(_Number)
#    define REVERSE_ENDIAN_32(_Number) swap32(_Number)
#    define REVERSE_ENDIAN_64(_Number) swap64(_Number)
#  elif defined __APPLE__
#    include <libkern/OSByteOrder.h>
#    define REVERSE_ENDIAN_16(_Number) _OSSwapInt16(_Number)
#    define REVERSE_ENDIAN_32(_Number) _OSSwapInt32(_Number)
#    define REVERSE_ENDIAN_64(_Number) _OSSwapInt64(_Number)
#  elif defined __FreeBSD__
#    include <sys/endian.h>
#    define REVERSE_ENDIAN_16(_Number) bswap16(_Number)
#    define REVERSE_ENDIAN_32(_Number) bswap32(_Number)
#    define REVERSE_ENDIAN_64(_Number) bswap64(_Number)
#  else
#    error Unsupported OS
#  endif
#endif
    /* libtpms added end */

#define NORETURN __attribute__((noreturn))

#define TPM_INLINE           inline __attribute__((always_inline))
#define TPM_STATIC_ASSERT(e) _Static_assert(e, "static assert")
#endif  // _COMPILER_DEPENDENCIES_H_
