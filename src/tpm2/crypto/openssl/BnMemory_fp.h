/********************************************************************************/
/*										*/
/*			     							*/
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
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _BN_MEMORY_FP_H_
#define _BN_MEMORY_FP_H_

//*** BnSetTop()
// This function is used when the size of a bignum_t is changed. It
// makes sure that the unused words are set to zero and that any significant
// words of zeros are eliminated from the used size indicator.
LIB_EXPORT bigNum BnSetTop(bigNum        bn,  // IN/OUT: number to clean
                           crypt_uword_t top  // IN: the new top
);

#if 0  /* libtpms added */
//*** BnClearTop()
// This function will make sure that all unused words are zero.
LIB_EXPORT bigNum BnClearTop(bigNum bn);
#endif /* libtpms added */

//*** BnInitializeWord()
// This function is used to initialize an allocated bigNum with a word value. The
// bigNum does not have to be allocated with a single word.
LIB_EXPORT bigNum BnInitializeWord(bigNum        bn,         // IN:
                                   crypt_uword_t allocated,  // IN:
                                   crypt_uword_t word        // IN:
);

//*** BnInit()
// This function initializes a stack allocated bignum_t. It initializes
// 'allocated' and 'size' and zeros the words of 'd'.
LIB_EXPORT bigNum BnInit(bigNum bn, crypt_uword_t allocated);

//*** BnCopy()
// Function to copy a bignum_t. If the output is NULL, then
// nothing happens. If the input is NULL, the output is set
// to zero.
LIB_EXPORT BOOL BnCopy(bigNum out, bigConst in);
#if ALG_ECC

#if 0   /* libtpms added */
//*** BnPointCopy()
// Function to copy a bn point.
LIB_EXPORT BOOL BnPointCopy(bigPoint pOut, pointConst pIn);
#endif  /* libtpms added */

//*** BnInitializePoint()
// This function is used to initialize a point structure with the addresses
// of the coordinates.
LIB_EXPORT bn_point_t* BnInitializePoint(
    bigPoint p,  // OUT: structure to receive pointers
    bigNum   x,  // IN: x coordinate
    bigNum   y,  // IN: y coordinate
    bigNum   z   // IN: x coordinate
);
#endif  // ALG_ECC

#endif  // _BN_MEMORY_FP_H_
