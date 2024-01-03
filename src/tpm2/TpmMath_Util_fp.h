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

#ifndef _TPM_MATH_FP_H_
#define _TPM_MATH_FP_H_

//*** TpmMath_IntFrom2B()
// Convert an TPM2B to a Crypt_Int.
// If the input value does not exist, or the output does not exist, or the input
// will not fit into the output the function returns NULL
LIB_EXPORT Crypt_Int* TpmMath_IntFrom2B(Crypt_Int*   value,  // OUT:
					const TPM2B* a2B     // IN: number to convert
					);

//*** TpmMath_IntTo2B()
//
// Function to convert a Crypt_Int to TPM2B. The TPM2B bytes are
// always in big-endian ordering (most significant byte first). If 'size' is
// non-zero and less than required by `value` then an error is returned. If
// `size` is non-zero and larger than `value`, the result buffer is padded
// with zeros. If `size` is zero, then the TPM2B is assumed to be large enough
// for the data and a2b->size will be adjusted accordingly.
LIB_EXPORT BOOL TpmMath_IntTo2B(
				const Crypt_Int* value,  // IN: value to convert
				TPM2B*           a2B,    // OUT: buffer for output
				NUMBYTES         size    // IN: Size of output buffer - see comments.
				);

//*** TpmMath_GetRandomBits()
// This function gets random bits for use in various places.
//
// One consequence of the generation scheme is that, if the number of bits requested
// is not a multiple of 8, then the high-order bits are set to zero. This would come
// into play when generating a 521-bit ECC key. A 66-byte (528-bit) value is
// generated and the high order 7 bits are masked off (CLEAR).
// In this situation, the highest order byte is the first byte (big-endian/TPM2B format)
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure
LIB_EXPORT BOOL TpmMath_GetRandomBits(
				      BYTE*       pBuffer,  // OUT: buffer to set
				      size_t      bits,     // IN: number of bits to generate (see remarks)
				      RAND_STATE* rand      // IN: random engine
				      );

//*** TpmMath_GetRandomInteger
// This function generates a random integer with the requested number of bits.
// Except for size, no range checking is performed.
// The maximum size that can be created is LARGEST_NUMBER + 64 bits.
// if either more bits, or the Crypt_Int* is too small to contain the requested bits
// the TPM enters failure mode and this function returns FALSE.
LIB_EXPORT BOOL TpmMath_GetRandomInteger(Crypt_Int* bn,  // OUT: integer buffer to set
					 size_t     bits,  // IN: size of output,
					 RAND_STATE* rand  // IN: random engine
					 );

//*** TpmMath_GetRandomInRange()
// This function is used to generate a random number r in the range 1 <= r < limit.
// The function gets a random number of bits that is the size of limit. There is some
// some probability that the returned number is going to be greater than or equal
// to the limit. If it is, try again. There is no more than 50% chance that the
// next number is also greater, so try again. We keep trying until we get a
// value that meets the criteria. Since limit is very often a number with a LOT of
// high order ones, this rarely would need a second try.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure ('limit' is too small)
LIB_EXPORT BOOL TpmMath_GetRandomInRange(
					 Crypt_Int*       dest,   // OUT: integer buffer to set
					 const Crypt_Int* limit,  // IN: limit (see remarks)
					 RAND_STATE*      rand    // IN: random engine
					 );

// BnMath.c					// libtpms added begin
BOOL BnGenerateRandomInRangeAllBytes(bigNum      dest,
				     bigConst    limit,
				     RAND_STATE* rand
				     );
						// libtpms added end
#endif  //_TPM_MATH_FP_H_
