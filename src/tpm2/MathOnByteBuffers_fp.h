/********************************************************************************/
/*										*/
/*	Math functions performed with canonical integers in byte buffers	*/
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
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _MATH_ON_BYTE_BUFFERS_FP_H_
#define _MATH_ON_BYTE_BUFFERS_FP_H_

//*** UnsignedCmpB
// This function compare two unsigned values. The values are byte-aligned,
// big-endian numbers (e.g, a hash).
//  Return Type: int
//      1          if (a > b)
//      0          if (a = b)
//      -1         if (a < b)
LIB_EXPORT int UnsignedCompareB(UINT32      aSize,  // IN: size of a
                                const BYTE* a,      // IN: a
                                UINT32      bSize,  // IN: size of b
                                const BYTE* b       // IN: b
);

//***SignedCompareB()
// Compare two signed integers:
//  Return Type: int
//      1         if a > b
//      0         if a = b
//      -1        if a < b
int SignedCompareB(const UINT32 aSize,  // IN: size of a
                   const BYTE*  a,      // IN: a buffer
                   const UINT32 bSize,  // IN: size of b
                   const BYTE*  b       // IN: b buffer
);

//*** ModExpB
// This function is used to do modular exponentiation in support of RSA.
// The most typical uses are: 'c' = 'm'^'e' mod 'n' (RSA encrypt) and
// 'm' = 'c'^'d' mod 'n' (RSA decrypt).  When doing decryption, the 'e' parameter
// of the function will contain the private exponent 'd' instead of the public
// exponent 'e'.
//
// If the results will not fit in the provided buffer,
// an error is returned (CRYPT_ERROR_UNDERFLOW). If the results is smaller
// than the buffer, the results is de-normalized.
//
// This version is intended for use with RSA and requires that 'm' be
// less than 'n'.
//
//  Return Type: TPM_RC
//      TPM_RC_SIZE         number to exponentiate is larger than the modulus
//      TPM_RC_NO_RESULT    result will not fit into the provided buffer
//
TPM_RC
ModExpB(UINT32 cSize,  // IN: the size of the output buffer. It will
                       //     need to be the same size as the modulus
        BYTE* c,       // OUT: the buffer to receive the results
                       //     (c->size must be set to the maximum size
                       //     for the returned value)
        const UINT32 mSize,
        const BYTE*  m,  // IN: number to exponentiate
        const UINT32 eSize,
        const BYTE*  e,  // IN: power
        const UINT32 nSize,
        const BYTE*  n  // IN: modulus
);

//*** DivideB()
// Divide an integer ('n') by an integer ('d') producing a quotient ('q') and
// a remainder ('r'). If 'q' or 'r' is not needed, then the pointer to them
// may be set to NULL.
//
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT         'q' or 'r' is too small to receive the result
//
LIB_EXPORT TPM_RC DivideB(const TPM2B* n,  // IN: numerator
                          const TPM2B* d,  // IN: denominator
                          TPM2B*       q,  // OUT: quotient
                          TPM2B*       r   // OUT: remainder
);

//*** AdjustNumberB()
// Remove/add leading zeros from a number in a TPM2B. Will try to make the number
// by adding or removing leading zeros. If the number is larger than the requested
// size, it will make the number as small as possible. Setting 'requestedSize' to
// zero is equivalent to requesting that the number be normalized.
UINT16
AdjustNumberB(TPM2B* num, UINT16 requestedSize);

//*** ShiftLeft()
// This function shifts a byte buffer (a TPM2B) one byte to the left. That is,
// the most significant bit of the most significant byte is lost.
TPM2B* ShiftLeft(TPM2B* value  // IN/OUT: value to shift and shifted value out
);

#endif  // _MATH_ON_BYTE_BUFFERS_FP_H_
