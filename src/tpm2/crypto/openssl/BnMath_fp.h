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
/*  (c) Copyright IBM Corp. and others, 2016 - 2023				*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Aug 30, 2019  Time: 02:11:54PM
 */

#ifndef _BN_MATH_FP_H_
#define _BN_MATH_FP_H_

//*** BnAdd()
// This function adds two bigNum values. This function always returns TRUE.
LIB_EXPORT BOOL BnAdd(bigNum result, bigConst op1, bigConst op2);

//*** BnAddWord()
// This function adds a word value to a bigNum. This function always returns TRUE.
LIB_EXPORT BOOL BnAddWord(bigNum result, bigConst op, crypt_uword_t word);

//*** BnSub()
// This function does subtraction of two bigNum values and returns result = op1 - op2
// when op1 is greater than op2. If op2 is greater than op1, then a fault is
// generated. This function always returns TRUE.
LIB_EXPORT BOOL BnSub(bigNum result, bigConst op1, bigConst op2);

//*** BnSubWord()
// This function subtracts a word value from a bigNum. This function always
// returns TRUE.
LIB_EXPORT BOOL BnSubWord(bigNum result, bigConst op, crypt_uword_t word);

//*** BnUnsignedCmp()
// This function performs a comparison of op1 to op2. The compare is approximately
// constant time if the size of the values used in the compare is consistent
// across calls (from the same line in the calling code).
//  Return Type: int
//      < 0             op1 is less than op2
//      0               op1 is equal to op2
//      > 0             op1 is greater than op2
LIB_EXPORT int BnUnsignedCmp(bigConst op1, bigConst op2);

//*** BnUnsignedCmpWord()
// Compare a bigNum to a crypt_uword_t.
//  Return Type: int
//      -1              op1 is less that word
//      0               op1 is equal to word
//      1               op1 is greater than word
LIB_EXPORT int BnUnsignedCmpWord(bigConst op1, crypt_uword_t word);

//*** BnModWord()
// This function does modular division of a big number when the modulus is a
// word value.
LIB_EXPORT crypt_word_t BnModWord(bigConst numerator, crypt_word_t modulus);

//*** BnMsb()
// This function returns the number of the MSb of a bigNum value.
//  Return Type: int
//      -1              the word was zero or 'bn' was NULL
//      n               the bit number of the most significant bit in the word
LIB_EXPORT int BnMsb(bigConst bn);

//*** BnSizeInBits()
// This function returns the number of bits required to hold a number. It is one
// greater than the Msb.
//
LIB_EXPORT unsigned BnSizeInBits(bigConst n);

//*** BnSetWord()
// Change the value of a bignum_t to a word value.
LIB_EXPORT bigNum BnSetWord(bigNum n, crypt_uword_t w);

//*** BnSetBit()
// This function will SET a bit in a bigNum. Bit 0 is the least-significant bit in
// the 0th digit_t. The function always return TRUE
LIB_EXPORT BOOL BnSetBit(bigNum       bn,     // IN/OUT: big number to modify
			 unsigned int bitNum  // IN: Bit number to SET
			 );

//*** BnTestBit()
// This function is used to check to see if a bit is SET in a bignum_t. The 0th bit
// is the LSb of d[0].
//  Return Type: BOOL
//      TRUE(1)         the bit is set
//      FALSE(0)        the bit is not set or the number is out of range
LIB_EXPORT BOOL BnTestBit(bigNum       bn,     // IN: number to check
			  unsigned int bitNum  // IN: bit to test
			  );

//***BnMaskBits()
// This function is used to mask off high order bits of a big number.
// The returned value will have no more than 'maskBit' bits
// set.
// Note: There is a requirement that unused words of a bignum_t are set to zero.
//  Return Type: BOOL
//      TRUE(1)         result masked
//      FALSE(0)        the input was not as large as the mask
LIB_EXPORT BOOL BnMaskBits(bigNum        bn,      // IN/OUT: number to mask
			   crypt_uword_t maskBit  // IN: the bit number for the mask.
			   );

//*** BnShiftRight()
// This function will shift a bigNum to the right by the shiftAmount.
// This function always returns TRUE.
LIB_EXPORT BOOL BnShiftRight(bigNum result, bigConst toShift, uint32_t shiftAmount);

//*** BnGetCurveData()
// This function returns the pointer for the parameter data
// associated with a curve.
const TPMBN_ECC_CURVE_CONSTANTS* BnGetCurveData(TPM_ECC_CURVE curveId);

//*** BnIsPointOnCurve()
// This function checks if a point is on the curve.
BOOL BnIsPointOnCurve(pointConst Q, const TPMBN_ECC_CURVE_CONSTANTS* C);

#endif  // _BN_MATH_FP_H_
