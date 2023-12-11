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
// These definitions are for the Microsoft compiler
//

#ifndef _COMPILER_DEPENDENCIES_MSVC_H_
#define _COMPILER_DEPENDENCIES_MSVC_H_

#if !defined(_MSC_VER)
#  error CompilerDependencies_msvc.h included for wrong compiler
#endif

// Endian conversion for aligned structures
#define REVERSE_ENDIAN_16(_Number) _byteswap_ushort(_Number)
#define REVERSE_ENDIAN_32(_Number) _byteswap_ulong(_Number)
#define REVERSE_ENDIAN_64(_Number) _byteswap_uint64(_Number)

// Avoid compiler warning for in line of stdio (or not)
//#define _NO_CRT_STDIO_INLINE

// This macro is used to handle LIB_EXPORT of function and variable names in lieu
// of a .def file. Visual Studio requires that functions be explicitly exported and
// imported.
#ifdef TPM_AS_DLL
#  define LIB_EXPORT __declspec(dllexport)  // VS compatible version
#  define LIB_IMPORT __declspec(dllimport)
#else
// building static libraries
#  define LIB_EXPORT
#  define LIB_IMPORT
#endif

#define TPM_INLINE inline

// This is defined to indicate a function that does not return. Microsoft compilers
// do not support the _Noretrun function parameter.
#define NORETURN __declspec(noreturn)
#if _MSC_VER >= 1400  // SAL processing when needed
#  include <sal.h>
#endif

// #  ifdef _WIN64
// #    define _INTPTR 2
// #  else
// #    define _INTPTR 1
// #  endif

#define NOT_REFERENCED(x) (x)

// Lower the compiler error warning for system include
// files. They tend not to be that clean and there is no
// reason to sort through all the spurious errors that they
// generate when the normal error level is set to /Wall
#define _REDUCE_WARNING_LEVEL_(n) __pragma(warning(push, n))
// Restore the compiler warning level
#define _NORMAL_WARNING_LEVEL_ __pragma(warning(pop))
#include <stdint.h>

#ifdef TPM_STATIC_ASSERT
#  error TPM_STATIC_ASSERT already defined
#endif

// MSVC: failure results in error C2118: negative subscript error
#define TPM_STATIC_ASSERT(e) typedef char __C_ASSERT__[(e) ? 1 : -1]

#endif  // _COMPILER_DEPENDENCIES_MSVC_H_
