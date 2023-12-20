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

//** Introduction
// This file contains OpenSSL specific functions called by TpmBigNum library to provide
// the TpmBigNum + OpenSSL math support.

#ifndef _TPM_TO_TPMBIGNUM_MATH_H_
#define _TPM_TO_TPMBIGNUM_MATH_H_

#ifdef MATH_LIB_DEFINED
#  error only one primary math library allowed
#endif
#define MATH_LIB_DEFINED

// indicate the TPMBIGNUM library is active
#define MATH_LIB_TPMBIGNUM

// TODO_RENAME_INC_FOLDER: private refers to the TPM_CoreLib private headers
#include "GpMacros.h"  // required for TpmFail_fp.h
#include "Capabilities.h"
#include "TpmTypes.h"  // requires capabilities & GpMacros
#include "BnValues.h"

#ifndef LIB_INCLUDE
#  error include ordering error, LIB_INCLUDE not defined
#endif
#ifndef BN_MATH_LIB
#  error BN_MATH_LIB not defined, required to provide BN library functions.
#endif

#if defined(CRYPT_CURVE_INITIALIZED) || defined(CRYPT_CURVE_FREE)
#error include ordering error, expected CRYPT_CURVE_INITIALIZED & CRYPT_CURVE_FREE to be undefined.
#endif

// Add support library dependent definitions.
// For TpmBigNum, we expect bigCurveData to be a defined type.
#include LIB_INCLUDE(BnTo, BN_MATH_LIB, Math)

#include "BnConvert_fp.h"
#include "BnMath_fp.h"
#include "BnMemory_fp.h"
#include "BnSupport_Interface.h"

// Define macros and types necessary for the math library abstraction layer
// Create a data object backing a Crypt_Int big enough for the given number of
// data bits
#define CRYPT_INT_BUF(buftypename, bits) BN_STRUCT(buftypename, bits)

// Create a data object backing a Crypt_Point big enough for the given number of
// data bits, per coordinate
#define CRYPT_POINT_BUF(buftypename, bits) BN_POINT_BUF(buftypename, bits)

// Create an instance of a data object underlying Crypt_EccCurve on the stack
// sufficient for given bit size.  In our case, all are the same size.
#define CRYPT_CURVE_BUF(buftypename, max_size_in_bits) bigCurveData

// now include the math library functional interface and instantiate the
// Crypt_Int & related types
// TODO_RENAME_INC_FOLDER: This should have a Tpm_Cryptolib_Common component prefix.
#include "MathLibraryInterface.h"

#endif  // _TPM_TO_TPMBIGNUM_MATH_H_
