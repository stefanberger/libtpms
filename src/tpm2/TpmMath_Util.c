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
/*  (c) Copyright IBM Corp. and others, 2023					*/
/*										*/
/********************************************************************************/

//** Introduction
// This file contains utility functions to help using the external Math library
#include "Tpm.h"
#include "TpmMath_Util_fp.h"

//*** TpmMath_IntFrom2B()
// Convert an TPM2B to a Crypt_Int.
// If the input value does not exist, or the output does not exist, or the input
// will not fit into the output the function returns NULL
LIB_EXPORT Crypt_Int* TpmMath_IntFrom2B(Crypt_Int*   value,  // OUT:
					const TPM2B* a2B     // IN: number to convert
					)
{
    if(value != NULL && a2B != NULL)
	return ExtMath_IntFromBytes(value, a2B->buffer, a2B->size);
    return NULL;
}

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
				)
{
    // Set the output size
    if(value && a2B)
	{
	    a2B->size = size;
	    return ExtMath_IntToBytes(value, a2B->buffer, &a2B->size);
	}
    return FALSE;
}

/* 10.2.3.3.20	BnGetRandomBits() */
/* Return Value	Meaning */
/* TRUE(1)	success */
/* FALSE(0)	failure */
LIB_EXPORT BOOL
BnGetRandomBits(
		bigNum           n,
		size_t           bits,
		RAND_STATE      *rand
		)
{
    // Since this could be used for ECC key generation using the extra bits method,
    // make sure that the value is large enough
    TPM2B_TYPE(LARGEST, LARGEST_NUMBER + 8);
    TPM2B_LARGEST    large;
    //
    large.b.size = (UINT16)BITS_TO_BYTES(bits);
    if(DRBG_Generate(rand, large.t.buffer, large.t.size) == large.t.size)
	{
	    if(BnFrom2B(n, &large.b) != NULL)
		{
		    if(BnMaskBits(n, (crypt_uword_t)bits))
			return TRUE;
		}
	}
    return FALSE;
}
/* 10.2.3.3.21 BnGenerateRandomInRange() */
/* Function to generate a random number r in the range 1 <= r < limit. The function gets a random
   number of bits that is the size of limit. There is some some probability that the returned number
   is going to be greater than or equal to the limit. If it is, try again. There is no more than 50%
   chance that the next number is also greater, so try again. We keep trying until we get a value
   that meets the criteria. Since limit is very often a number with a LOT of high order ones, this
   rarely would need a second try. */
/* Return Value	Meaning */
/* TRUE(1)	success */
/* FALSE(0)	failure */
LIB_EXPORT BOOL
BnGenerateRandomInRange(
			bigNum           dest,
			bigConst         limit,
			RAND_STATE      *rand
			)
{
    size_t   bits = BnSizeInBits(limit);
    //
    if(bits < 2)
	{
	    BnSetWord(dest, 0);
	    return FALSE;
	}
    else
	{
	    while(BnGetRandomBits(dest, bits, rand)
		  && (BnEqualZero(dest) || (BnUnsignedCmp(dest, limit) >= 0)));
	}
    return !g_inFailureMode;
}
