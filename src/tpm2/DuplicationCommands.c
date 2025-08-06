/********************************************************************************/
/*										*/
/*			    Duplication Commands 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: DuplicationCommands.c 1490 2019-07-26 21:13:22Z kgoldman $	*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2021				*/
/*										*/
/********************************************************************************/

#include "Tpm.h"
#include "Rewrap_fp.h"
#if CC_Rewrap  // Conditional expansion of this file
#include "Object_spt_fp.h"
TPM_RC
TPM2_Rewrap(
	    Rewrap_In       *in,            // IN: input parameter list
	    Rewrap_Out      *out            // OUT: output parameter list
	    )
{
    TPM_RC                  result = TPM_RC_SUCCESS;
    TPM2B_DATA              data;               // symmetric key
    UINT16                  hashSize = 0;
    TPM2B_PRIVATE           privateBlob;        // A temporary private blob
    // to transit between old
    // and new wrappers
    // Input Validation
    if((in->inSymSeed.t.size == 0 && in->oldParent != TPM_RH_NULL)
       || (in->inSymSeed.t.size != 0 && in->oldParent == TPM_RH_NULL))
	return TPM_RCS_HANDLE + RC_Rewrap_oldParent;
    if(in->oldParent != TPM_RH_NULL)
	{
	    OBJECT              *oldParent = HandleToObject(in->oldParent);
	    // old parent key must be a storage object
	    if(!ObjectIsStorage(in->oldParent))
		return TPM_RCS_TYPE + RC_Rewrap_oldParent;

	    pAssert_RC(oldParent != NULL);
	    // Decrypt input secret data via asymmetric decryption.  A
	    // TPM_RC_VALUE, TPM_RC_KEY or unmarshal errors may be returned at this
	    // point
	    result = CryptSecretDecrypt(oldParent, NULL, DUPLICATE_STRING,
					&in->inSymSeed, &data);
	    if(result != TPM_RC_SUCCESS)
		return TPM_RCS_VALUE + RC_Rewrap_inSymSeed;
	    // Unwrap Outer
	    result = UnwrapOuter(oldParent, &in->name.b,
				 oldParent->publicArea.nameAlg, &data.b,
				 FALSE,
				 in->inDuplicate.t.size, in->inDuplicate.t.buffer);
	    if(result != TPM_RC_SUCCESS)
		return RcSafeAddToResult(result, RC_Rewrap_inDuplicate);
	    // Copy unwrapped data to temporary variable, remove the integrity field
	    hashSize = sizeof(UINT16) +
		       CryptHashGetDigestSize(oldParent->publicArea.nameAlg);
	    privateBlob.t.size = in->inDuplicate.t.size - hashSize;
	    pAssert_RC(privateBlob.t.size <= sizeof(privateBlob.t.buffer));
	    MemoryCopy(privateBlob.t.buffer, in->inDuplicate.t.buffer + hashSize,
		       privateBlob.t.size);
	}
    else
	{
	    // No outer wrap from input blob.  Direct copy.
	    privateBlob = in->inDuplicate;
	}
    if(in->newParent != TPM_RH_NULL)
	{
	    OBJECT          *newParent;
	    newParent = HandleToObject(in->newParent);

	    // New parent must be a storage object
	    if(!ObjectIsStorage(in->newParent))
		return TPM_RCS_TYPE + RC_Rewrap_newParent;

	    pAssert_RC(newParent != NULL);

	    // Make new encrypt key and its associated secret structure.  A
	    // TPM_RC_VALUE error may be returned at this point if RSA algorithm is
	    // enabled in TPM
	    out->outSymSeed.t.size = sizeof(out->outSymSeed.t.secret);
	    result = CryptSecretEncrypt(newParent, DUPLICATE_STRING, &data,
					&out->outSymSeed);
	    if(result != TPM_RC_SUCCESS)
		return result;
	    // Copy temporary variable to output, reserve the space for integrity
	    hashSize = sizeof(UINT16) +
		       CryptHashGetDigestSize(newParent->publicArea.nameAlg);
	    // Make sure that everything fits into the output buffer
	    // Note: this is mostly only an issue if there was no outer wrapper on
	    // 'inDuplicate'. It could be as large as a TPM2B_PRIVATE buffer. If we add
	    // a digest for an outer wrapper, it won't fit anymore.
	    if((size_t)(privateBlob.t.size + hashSize) > sizeof(out->outDuplicate.t.buffer))
		return TPM_RCS_VALUE + RC_Rewrap_inDuplicate;
	    // Command output
	    out->outDuplicate.t.size = privateBlob.t.size;
	    pAssert(privateBlob.t.size
		    <= sizeof(out->outDuplicate.t.buffer) - hashSize);
	    MemoryCopy(out->outDuplicate.t.buffer + hashSize, privateBlob.t.buffer,
		       privateBlob.t.size);
	    // Produce outer wrapper for output
	    out->outDuplicate.t.size = ProduceOuterWrap(newParent, &in->name.b,
							newParent->publicArea.nameAlg,
							&data.b,
							FALSE,
							out->outDuplicate.t.size,
							out->outDuplicate.t.buffer);
	}
    else  // New parent is a null key so there is no seed
	{
	    out->outSymSeed.t.size = 0;
	    // Copy privateBlob directly
	    out->outDuplicate = privateBlob;
	}
    return TPM_RC_SUCCESS;
}
#endif // CC_Rewrap
