/********************************************************************************/
/*										*/
/*		Signing and Signature Verification	   			*/
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

#include "Tpm.h"
#include "VerifySignature_fp.h"

#include "Tpm.h"
#include "VerifySignature_fp.h"

#if CC_VerifySignature  // Conditional expansion of this file

/*(See part 3 specification)
// This command uses loaded key to validate an asymmetric signature on a message
// with the message digest passed to the TPM.
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES         'keyHandle' does not reference a signing key
//      TPM_RC_SIGNATURE          signature is not genuine
//      TPM_RC_SCHEME             CryptValidateSignature()
//      TPM_RC_HANDLE             the input handle is references an HMAC key but
//                                the private portion is not loaded
TPM_RC
TPM2_VerifySignature(VerifySignature_In*  in,  // IN: input parameter list
		     VerifySignature_Out* out  // OUT: output parameter list
		     )
{
    TPM_RC            result;
    OBJECT*           signObject = HandleToObject(in->keyHandle);
    TPMI_RH_HIERARCHY hierarchy;
    // Input Validation
    // The object to validate the signature must be a signing key.
    if(!IS_ATTRIBUTE(signObject->publicArea.objectAttributes, TPMA_OBJECT, sign))
	return TPM_RCS_ATTRIBUTES + RC_VerifySignature_keyHandle;

    // Validate Signature.  TPM_RC_SCHEME, TPM_RC_HANDLE or TPM_RC_SIGNATURE
    // error may be returned by CryptCVerifySignatrue()
    result = CryptValidateSignature(in->keyHandle, &in->digest, &in->signature);
    if(result != TPM_RC_SUCCESS)
	return RcSafeAddToResult(result, RC_VerifySignature_signature);

    // Command Output

    hierarchy = GetHierarchy(in->keyHandle);
    if(hierarchy == TPM_RH_NULL || signObject->publicArea.nameAlg == TPM_ALG_NULL)
	{
	    // produce empty ticket if hierarchy is TPM_RH_NULL or nameAlg is
	    // TPM_ALG_NULL
	    out->validation.tag           = TPM_ST_VERIFIED;
	    out->validation.hierarchy     = TPM_RH_NULL;
	    out->validation.digest.t.size = 0;
	}
    else
	{
	    // Compute ticket
	    result = TicketComputeVerified(
					   hierarchy, &in->digest, &signObject->name, &out->validation);
	    if(result != TPM_RC_SUCCESS)
		return result;
	}

    return TPM_RC_SUCCESS;
}

#endif  // CC_VerifySignature

#include "Tpm.h"
#include "Sign_fp.h"

#if CC_Sign  // Conditional expansion of this file

#  include "Attest_spt_fp.h"

/*(See part 3 specification)
// sign an externally provided hash using an asymmetric signing key
*/
//  Return Type: TPM_RC
//      TPM_RC_BINDING          The public and private portions of the key are not
//                              properly bound.
//      TPM_RC_KEY              'signHandle' does not reference a signing key;
//      TPM_RC_SCHEME           the scheme is not compatible with sign key type,
//                              or input scheme is not compatible with default
//                              scheme, or the chosen scheme is not a valid
//                              sign scheme
//      TPM_RC_TICKET           'validation' is not a valid ticket
//      TPM_RC_VALUE            the value to sign is larger than allowed for the
//                              type of 'keyHandle'

TPM_RC
TPM2_Sign(Sign_In*  in,  // IN: input parameter list
	  Sign_Out* out  // OUT: output parameter list
	  )
{
    TPM_RC            result;
    TPMT_TK_HASHCHECK ticket;
    OBJECT*           signObject = HandleToObject(in->keyHandle);
    //
    // Input Validation
    if(!IsSigningObject(signObject))
	return TPM_RCS_KEY + RC_Sign_keyHandle;

    // A key that will be used for x.509 signatures can't be used in TPM2_Sign().
    if(IS_ATTRIBUTE(signObject->publicArea.objectAttributes, TPMA_OBJECT, x509sign))
	return TPM_RCS_ATTRIBUTES + RC_Sign_keyHandle;

    // pick a scheme for sign.  If the input sign scheme is not compatible with
    // the default scheme, return an error.
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
	return TPM_RCS_SCHEME + RC_Sign_inScheme;

    // If validation is provided, or the key is restricted, check the ticket
    if(in->validation.digest.t.size != 0
       || IS_ATTRIBUTE(
		       signObject->publicArea.objectAttributes, TPMA_OBJECT, restricted))
	{
	    // Compute and compare ticket
	    result = TicketComputeHashCheck(in->validation.hierarchy,
					    in->inScheme.details.any.hashAlg,
					    &in->digest,
					    &ticket);
	    if(result != TPM_RC_SUCCESS)
		return result;

	    if(!MemoryEqual2B(&in->validation.digest.b, &ticket.digest.b))
		return TPM_RCS_TICKET + RC_Sign_validation;
	}
    else
	// If we don't have a ticket, at least verify that the provided 'digest'
	// is the size of the scheme hashAlg digest.
	// NOTE: this does not guarantee that the 'digest' is actually produced using
	// the indicated hash algorithm, but at least it might be.
	{
	    if(in->digest.t.size
	       != CryptHashGetDigestSize(in->inScheme.details.any.hashAlg))
		return TPM_RCS_SIZE + RC_Sign_digest;
	}

    // Command Output
    // Sign the hash. A TPM_RC_VALUE or TPM_RC_SCHEME
    // error may be returned at this point
    result = CryptSign(signObject, &in->inScheme, &in->digest, &out->signature);

    return result;
}

#endif  // CC_Sign
