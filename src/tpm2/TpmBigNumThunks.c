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
// This file contains BN Thunks between the MathInterfaceLibrary types and the
// bignum_t types.

#include "TpmBigNum.h"

// Note - these were moved out of TPM_INLINE to build correctly on GCC.  On MSVC
// link time code generation correctly handles the inline versions, but
// it isn't portable to GCC.

// ***************************************************************************
// Library Level Functions
// ***************************************************************************

// Called when system is initializing to allow math libraries to perform
// startup actions.
LIB_EXPORT int ExtMath_LibInit(void)
{
    return BnSupportLibInit();
}

// ***************************************************************************
// Integer/Number Functions (non-ECC)
// ***************************************************************************
// #################
// type initializers
// #################
LIB_EXPORT Crypt_Int* ExtMath_Initialize_Int(Crypt_Int* var, NUMBYTES bitCount)
{
    return (Crypt_Int*)BnInit((bigNum)var, BN_STRUCT_ALLOCATION(bitCount));
}

// #################
// Buffer Converters
// #################
LIB_EXPORT Crypt_Int* ExtMath_IntFromBytes(
					   Crypt_Int* buffer, const BYTE* input, NUMBYTES byteCount)
{
    return (Crypt_Int*)BnFromBytes((bigNum)buffer, input, byteCount);
}

LIB_EXPORT BOOL ExtMath_IntToBytes(
				   const Crypt_Int* value, BYTE* output, NUMBYTES* pByteCount)
{
    return BnToBytes((bigConst)value, output, pByteCount);
}

// ###############################
// Ordinary Arithmetic, writ large
// ###############################

//** ExtMath_Divide()
// This function divides two Crypt_Int* values. The function returns FALSE if there is
// an error in the operation. Quotient may be null, in which case this function returns
// only the remainder.
LIB_EXPORT BOOL ExtMath_Divide(Crypt_Int*       quotient,
			       Crypt_Int*       remainder,
			       const Crypt_Int* dividend,
			       const Crypt_Int* divisor)
{
    return BnDiv(
		 (bigNum)quotient, (bigNum)remainder, (bigConst)dividend, (bigConst)divisor);
}

// ###############################
// Modular Arithmetic, writ large
// ###############################
// define Mod in terms of Divide

#if ALG_RSA
//** ExtMath_ModExp()
// Do modular exponentiation using Crypt_Int* values. This function is only needed
// when the TPM implements RSA.
LIB_EXPORT BOOL ExtMath_ModExp(Crypt_Int*       result,
			       const Crypt_Int* number,
			       const Crypt_Int* exponent,
			       const Crypt_Int* modulus)
{
    return BnModExp(
		    (bigNum)result, (bigConst)number, (bigConst)exponent, (bigConst)modulus);
}
#endif  // ALG_RSA

// ###############################
// Queries
// ###############################

//*** ExtMath_UnsignedCmp()
// This function performs a comparison of op1 to op2. The compare is approximately
// constant time if the size of the values used in the compare is consistent
// across calls (from the same line in the calling code).
//  Return Type: int
//      < 0             op1 is less than op2
//      0               op1 is equal to op2
//      > 0             op1 is greater than op2
LIB_EXPORT int ExtMath_UnsignedCmp(const Crypt_Int* op1, const Crypt_Int* op2)
{
    return BnUnsignedCmp((bigConst)op1, (bigConst)op2);
}


