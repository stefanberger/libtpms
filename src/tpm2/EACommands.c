/********************************************************************************/
/*										*/
/*			    Enhanced Authorization Commands			*/
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
#include "Policy_spt_fp.h"
#include "PolicySigned_fp.h"
#include "RuntimeProfile_fp.h"

#if CC_PolicySigned  // Conditional expansion of this file

/*(See part 3 specification)
// Include an asymmetrically signed authorization to the policy evaluation
*/
//  Return Type: TPM_RC
//      TPM_RC_CPHASH           cpHash was previously set to a different value
//      TPM_RC_EXPIRED          'expiration' indicates a time in the past or
//                              'expiration' is non-zero but no nonceTPM is present
//      TPM_RC_NONCE            'nonceTPM' is not the nonce associated with the
//                              'policySession'
//      TPM_RC_SCHEME           the signing scheme of 'auth' is not supported by the
//                              TPM
//      TPM_RC_SIGNATURE        the signature is not genuine
//      TPM_RC_SIZE             input cpHash has wrong size
TPM_RC
TPM2_PolicySigned(PolicySigned_In*  in,  // IN: input parameter list
		  PolicySigned_Out* out  // OUT: output parameter list
		  )
{
    TPM_RC       result = TPM_RC_SUCCESS;
    SESSION*     session;
    TPM2B_NAME   entityName;
    TPM2B_DIGEST authHash;
    HASH_STATE   hashState;
    UINT64       authTimeout = 0;
    // Input Validation
    // Set up local pointers
    session = SessionGet(in->policySession);  // the session structure

    // Only do input validation if this is not a trial policy session
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    authTimeout = ComputeAuthTimeout(session, in->expiration, &in->nonceTPM);

	    result      = PolicyParameterChecks(session,
						authTimeout,
						&in->cpHashA,
						&in->nonceTPM,
						RC_PolicySigned_nonceTPM,
						RC_PolicySigned_cpHashA,
						RC_PolicySigned_expiration);
	    if(result != TPM_RC_SUCCESS)
		return result;
	    // Re-compute the digest being signed
	    /*(See part 3 specification)
	    // The digest is computed as:
	    //     aHash := hash ( nonceTPM | expiration | cpHashA | policyRef)
	    //  where:
	    //      hash()      the hash associated with the signed authorization
	    //      nonceTPM    the nonceTPM value from the TPM2_StartAuthSession .
	    //                  response If the authorization is not limited to this
	    //                  session, the size of this value is zero.
	    //      expiration  time limit on authorization set by authorizing object.
	    //                  This 32-bit value is set to zero if the expiration
	    //                  time is not being set.
	    //      cpHashA     hash of the command parameters for the command being
	    //                  approved using the hash algorithm of the PSAP session.
	    //                  Set to NULLauth if the authorization is not limited
	    //                  to a specific command.
	    //      policyRef   hash of an opaque value determined by the authorizing
	    //                  object.  Set to the NULLdigest if no hash is present.
	    */
	    // Start hash
	    authHash.t.size = CryptHashStart(&hashState, CryptGetSignHashAlg(&in->auth));
	    // If there is no digest size, then we don't have a verification function
	    // for this algorithm (e.g. TPM_ALG_ECDAA) so indicate that it is a
	    // bad scheme.
	    if(authHash.t.size == 0)
		return TPM_RCS_SCHEME + RC_PolicySigned_auth;

	    //  nonceTPM
	    CryptDigestUpdate2B(&hashState, &in->nonceTPM.b);

	    //  expiration
	    CryptDigestUpdateInt(&hashState, sizeof(UINT32), in->expiration);

	    //  cpHashA
	    CryptDigestUpdate2B(&hashState, &in->cpHashA.b);

	    //  policyRef
	    CryptDigestUpdate2B(&hashState, &in->policyRef.b);

	    //  Complete digest
	    CryptHashEnd2B(&hashState, &authHash.b);

	    // Validate Signature.  A TPM_RC_SCHEME, TPM_RC_HANDLE or TPM_RC_SIGNATURE
	    // error may be returned at this point
	    result = CryptValidateSignature(in->authObject, &authHash, &in->auth);
	    if(result != TPM_RC_SUCCESS)
		return RcSafeAddToResult(result, RC_PolicySigned_auth);
	}
    // Internal Data Update
    // Update policy with input policyRef and name of authorization key
    // These values are updated even if the session is a trial session
    PolicyContextUpdate(TPM_CC_PolicySigned,
			EntityGetName(in->authObject, &entityName),
			&in->policyRef,
			&in->cpHashA,
			authTimeout,
			session);
    // Command Output
    // Create ticket and timeout buffer if in->expiration < 0 and this is not
    // a trial session.
    // NOTE: PolicyParameterChecks() makes sure that nonceTPM is present
    // when expiration is non-zero.
    if(in->expiration < 0 && session->attributes.isTrialPolicy == CLEAR)
	{
	    BOOL expiresOnReset = (in->nonceTPM.t.size == 0);
	    // Compute policy ticket
	    authTimeout &= ~EXPIRATION_BIT;

	    result = TicketComputeAuth(TPM_ST_AUTH_SIGNED,
				       EntityGetHierarchy(in->authObject),
				       authTimeout,
				       expiresOnReset,
				       &in->cpHashA,
				       &in->policyRef,
				       &entityName,
				       &out->policyTicket);
	    if(result != TPM_RC_SUCCESS)
		return result;

	    // Generate timeout buffer.  The format of output timeout buffer is
	    // TPM-specific.
	    // Note: In this implementation, the timeout buffer value is computed after
	    // the ticket is produced so, when the ticket is checked, the expiration
	    // flag needs to be extracted before the ticket is checked.
	    // In the Windows compatible version, the least-significant bit of the
	    // timeout value is used as a flag to indicate if the authorization expires
	    // on reset. The flag is the MSb.
	    out->timeout.t.size = sizeof(authTimeout);
	    if(expiresOnReset)
		authTimeout |= EXPIRATION_BIT;
	    UINT64_TO_BYTE_ARRAY(authTimeout, out->timeout.t.buffer);
	}
    else
	{
	    // Generate a null ticket.
	    // timeout buffer is null
	    out->timeout.t.size = 0;

	    // authorization ticket is null
	    out->policyTicket.tag           = TPM_ST_AUTH_SIGNED;
	    out->policyTicket.hierarchy     = TPM_RH_NULL;
	    out->policyTicket.digest.t.size = 0;
	}
    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicySigned


#include "Tpm.h"
#include "PolicySecret_fp.h"

#if CC_PolicySecret  // Conditional expansion of this file

#  include "Policy_spt_fp.h"
#  include "NV_spt_fp.h"

/*(See part 3 specification)
// Add a secret-based authorization to the policy evaluation
*/
//  Return Type: TPM_RC
//      TPM_RC_CPHASH           cpHash for policy was previously set to a
//                              value that is not the same as 'cpHashA'
//      TPM_RC_EXPIRED          'expiration' indicates a time in the past
//      TPM_RC_NONCE            'nonceTPM' does not match the nonce associated
//                              with 'policySession'
//      TPM_RC_SIZE             'cpHashA' is not the size of a digest for the
//                              hash associated with 'policySession'
TPM_RC
TPM2_PolicySecret(PolicySecret_In*  in,  // IN: input parameter list
		  PolicySecret_Out* out  // OUT: output parameter list
		  )
{
    TPM_RC     result;
    SESSION*   session;
    TPM2B_NAME entityName;
    UINT64     authTimeout = 0;
    // Input Validation
    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    //Only do input validation if this is not a trial policy session
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    authTimeout = ComputeAuthTimeout(session, in->expiration, &in->nonceTPM);

	    result      = PolicyParameterChecks(session,
						authTimeout,
						&in->cpHashA,
						&in->nonceTPM,
						RC_PolicySecret_nonceTPM,
						RC_PolicySecret_cpHashA,
						RC_PolicySecret_expiration);
	    if(result != TPM_RC_SUCCESS)
		return result;
	}
    // Internal Data Update
    // Update policy context with input policyRef and name of authorizing key
    // This value is computed even for trial sessions. Possibly update the cpHash
    PolicyContextUpdate(TPM_CC_PolicySecret,
			EntityGetName(in->authHandle, &entityName),
			&in->policyRef,
			&in->cpHashA,
			authTimeout,
			session);
    // Command Output
    // Create ticket and timeout buffer if in->expiration < 0 and this is not
    // a trial session.
    // NOTE: PolicyParameterChecks() makes sure that nonceTPM is present
    // when expiration is non-zero.
    if(in->expiration < 0 && session->attributes.isTrialPolicy == CLEAR
       && !NvIsPinPassIndex(in->authHandle))
	{
	    BOOL expiresOnReset = (in->nonceTPM.t.size == 0);
	    // Compute policy ticket
	    authTimeout &= ~EXPIRATION_BIT;
	    result = TicketComputeAuth(TPM_ST_AUTH_SECRET,
				       EntityGetHierarchy(in->authHandle),
				       authTimeout,
				       expiresOnReset,
				       &in->cpHashA,
				       &in->policyRef,
				       &entityName,
				       &out->policyTicket);
	    if(result != TPM_RC_SUCCESS)
		return result;

	    // Generate timeout buffer.  The format of output timeout buffer is
	    // TPM-specific.
	    // Note: In this implementation, the timeout buffer value is computed after
	    // the ticket is produced so, when the ticket is checked, the expiration
	    // flag needs to be extracted before the ticket is checked.
	    out->timeout.t.size = sizeof(authTimeout);
	    // In the Windows compatible version, the least-significant bit of the
	    // timeout value is used as a flag to indicate if the authorization expires
	    // on reset. The flag is the MSb.
	    if(expiresOnReset)
		authTimeout |= EXPIRATION_BIT;
	    UINT64_TO_BYTE_ARRAY(authTimeout, out->timeout.t.buffer);
	}
    else
	{
	    // timeout buffer is null
	    out->timeout.t.size = 0;

	    // authorization ticket is null
	    out->policyTicket.tag           = TPM_ST_AUTH_SECRET;
	    out->policyTicket.hierarchy     = TPM_RH_NULL;
	    out->policyTicket.digest.t.size = 0;
	}
    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicySecret

#include "Tpm.h"
#include "PolicyTicket_fp.h"

#if CC_PolicyTicket  // Conditional expansion of this file

#  include "Policy_spt_fp.h"

/*(See part 3 specification)
// Include ticket to the policy evaluation
*/
//  Return Type: TPM_RC
//      TPM_RC_CPHASH           policy's cpHash was previously set to a different
//                              value
//      TPM_RC_EXPIRED          'timeout' value in the ticket is in the past and the
//                              ticket has expired
//      TPM_RC_SIZE             'timeout' or 'cpHash' has invalid size for the
//      TPM_RC_TICKET           'ticket' is not valid
TPM_RC
TPM2_PolicyTicket(PolicyTicket_In* in  // IN: input parameter list
		  )
{
    TPM_RC       result;
    SESSION*     session;
    UINT64       authTimeout;
    TPMT_TK_AUTH ticketToCompare;
    TPM_CC       commandCode = TPM_CC_PolicySecret;
    BOOL         expiresOnReset;
    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // NOTE: A trial policy session is not allowed to use this command.
    // A ticket is used in place of a previously given authorization. Since
    // a trial policy doesn't actually authenticate, the validated
    // ticket is not necessary and, in place of using a ticket, one
    // should use the intended authorization for which the ticket
    // would be a substitute.
    if(session->attributes.isTrialPolicy)
	return TPM_RCS_ATTRIBUTES + RC_PolicyTicket_policySession;
    // Restore timeout data.  The format of timeout buffer is TPM-specific.
    // In this implementation, the most significant bit of the timeout value is
    // used as the flag to indicate that the ticket expires on TPM Reset or
    // TPM Restart. The flag has to be removed before the parameters and ticket
    // are checked.
    if(in->timeout.t.size != sizeof(UINT64))
	return TPM_RCS_SIZE + RC_PolicyTicket_timeout;
    authTimeout = BYTE_ARRAY_TO_UINT64(in->timeout.t.buffer);

    // extract the flag
    expiresOnReset = (authTimeout & EXPIRATION_BIT) != 0;
    authTimeout &= ~EXPIRATION_BIT;

    // Do the normal checks on the cpHashA and timeout values
    result = PolicyParameterChecks(session,
				   authTimeout,
				   &in->cpHashA,
				   NULL,  // no nonce
				   0,     // no bad nonce return
				   RC_PolicyTicket_cpHashA,
				   RC_PolicyTicket_timeout);
    if(result != TPM_RC_SUCCESS)
	return result;
    // Validate Ticket
    // Re-generate policy ticket by input parameters
    result = TicketComputeAuth(in->ticket.tag,
			       in->ticket.hierarchy,
			       authTimeout,
			       expiresOnReset,
			       &in->cpHashA,
			       &in->policyRef,
			       &in->authName,
			       &ticketToCompare);
    if(result != TPM_RC_SUCCESS)
	return result;

    // Compare generated digest with input ticket digest
    if(!MemoryEqual2B(&in->ticket.digest.b, &ticketToCompare.digest.b))
	return TPM_RCS_TICKET + RC_PolicyTicket_ticket;

    // Internal Data Update

    // Is this ticket to take the place of a TPM2_PolicySigned() or
    // a TPM2_PolicySecret()?
    if(in->ticket.tag == TPM_ST_AUTH_SIGNED)
	commandCode = TPM_CC_PolicySigned;
    else if(in->ticket.tag == TPM_ST_AUTH_SECRET)
	commandCode = TPM_CC_PolicySecret;
    else
	// There could only be two possible tag values.  Any other value should
	// be caught by the ticket validation process.
	FAIL(FATAL_ERROR_INTERNAL);

    // Update policy context
    PolicyContextUpdate(commandCode,
			&in->authName,
			&in->policyRef,
			&in->cpHashA,
			authTimeout,
			session);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyTicket

#include "Tpm.h"
#include "PolicyOR_fp.h"

#if CC_PolicyOR  // Conditional expansion of this file

#  include "Policy_spt_fp.h"

/*(See part 3 specification)
// PolicyOR command
*/
//  Return Type: TPM_RC
//      TPM_RC_VALUE            no digest in 'pHashList' matched the current
//                              value of policyDigest for 'policySession'
TPM_RC
TPM2_PolicyOR(PolicyOR_In* in  // IN: input parameter list
	      )
{
    SESSION* session;
    UINT32   i;
    // Input Validation and Update

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Compare and Update Internal Session policy if match
    for(i = 0; i < in->pHashList.count; i++)
	{
	    if(session->attributes.isTrialPolicy == SET
	       || (MemoryEqual2B(&session->u2.policyDigest.b,
				 &in->pHashList.digests[i].b)))
		{
		    // Found a match
		    HASH_STATE hashState;
		    TPM_CC     commandCode = TPM_CC_PolicyOR;

		    // Start hash
		    session->u2.policyDigest.t.size =
			CryptHashStart(&hashState, session->authHashAlg);
		    // Set policyDigest to 0 string and add it to hash
		    MemorySet(session->u2.policyDigest.t.buffer,
			      0,
			      session->u2.policyDigest.t.size);
		    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

		    // add command code
		    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

		    // Add each of the hashes in the list
		    for(i = 0; i < in->pHashList.count; i++)
			{
			    // Extend policyDigest
			    CryptDigestUpdate2B(&hashState, &in->pHashList.digests[i].b);
			}
		    // Complete digest
		    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

		    return TPM_RC_SUCCESS;
		}
	}
    // None of the values in the list matched the current policyDigest
    return TPM_RCS_VALUE + RC_PolicyOR_pHashList;
}

#endif  // CC_PolicyOR

#include "Tpm.h"

#if CC_PolicyPCR  // Conditional expansion of this file

#  include "PolicyPCR_fp.h"
#  include "Marshal.h"

/*(See part 3 specification)
// Add a PCR gate for a policy session
*/
//  Return Type: TPM_RC
//      TPM_RC_VALUE          if provided, 'pcrDigest' does not match the
//                            current PCR settings
//      TPM_RC_PCR_CHANGED    a previous TPM2_PolicyPCR() set
//                            pcrCounter and it has changed
TPM_RC
TPM2_PolicyPCR(PolicyPCR_In* in  // IN: input parameter list
	       )
{
    SESSION*     session;
    TPM2B_DIGEST pcrDigest;
    BYTE         pcrs[sizeof(TPML_PCR_SELECTION)];
    UINT32       pcrSize;
    BYTE*        buffer;
    TPM_CC       commandCode = TPM_CC_PolicyPCR;
    HASH_STATE   hashState;
    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Compute current PCR digest
    PCRComputeCurrentDigest(session->authHashAlg, &in->pcrs, &pcrDigest);

    // Do validation for non trial session
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    // Make sure that this is not going to invalidate a previous PCR check
	    if(session->pcrCounter != 0 && session->pcrCounter != gr.pcrCounter)
		return TPM_RC_PCR_CHANGED;

	    // If the caller specified the PCR digest and it does not
	    // match the current PCR settings, return an error..
	    if(in->pcrDigest.t.size != 0)
		{
		    if(!MemoryEqual2B(&in->pcrDigest.b, &pcrDigest.b))
			return TPM_RCS_VALUE + RC_PolicyPCR_pcrDigest;
		}
	}
    else
	{
	    // For trial session, just use the input PCR digest if one provided
	    // Note: It can't be too big because it is a TPM2B_DIGEST and the size
	    // would have been checked during unmarshaling
	    if(in->pcrDigest.t.size != 0)
		pcrDigest = in->pcrDigest;
	}
    // Internal Data Update
    // Update policy hash
    // policyDigestnew = hash(   policyDigestold || TPM_CC_PolicyPCR
    //                      || PCRS || pcrDigest)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add PCRS
    buffer  = pcrs;
    pcrSize = TPML_PCR_SELECTION_Marshal(&in->pcrs, &buffer, NULL);
    CryptDigestUpdate(&hashState, pcrSize, pcrs);

    //  add PCR digest
    CryptDigestUpdate2B(&hashState, &pcrDigest.b);

    //  complete the hash and get the results
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    //  update pcrCounter in session context for non trial session
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    session->pcrCounter = gr.pcrCounter;
	}

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyPCR

#include "Tpm.h"
#include "PolicyPhysicalPresence_fp.h"

#if CC_PolicyPhysicalPresence  // Conditional expansion of this file

/*(See part 3 specification)
// indicate that physical presence will need to be asserted at the time the
// authorization is performed
*/
TPM_RC
TPM2_PolicyPhysicalPresence(PolicyPhysicalPresence_In* in  // IN: input parameter list
			    )
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyPhysicalPresence;
    HASH_STATE hashState;

    // Internal Data Update

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyPhysicalPresence)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update session attribute
    session->attributes.isPPRequired = SET;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyPhysicalPresence


#include "Tpm.h"
#include "PolicyLocality_fp.h"
#include "Marshal.h"

#if CC_PolicyLocality  // Conditional expansion of this file

//  Return Type: TPM_RC
//      TPM_RC_RANGE          all the locality values selected by
//                            'locality' have been disabled
//                            by previous TPM2_PolicyLocality() calls.
TPM_RC
TPM2_PolicyLocality(PolicyLocality_In* in  // IN: input parameter list
		    )
{
    SESSION*   session;
    BYTE       marshalBuffer[sizeof(TPMA_LOCALITY)];
    BYTE       prevSetting[sizeof(TPMA_LOCALITY)];
    UINT32     marshalSize;
    BYTE*      buffer;
    TPM_CC     commandCode = TPM_CC_PolicyLocality;
    HASH_STATE hashState;
    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Get new locality setting in canonical form
    marshalBuffer[0] = 0;  // Code analysis says that this is not initialized
    buffer           = marshalBuffer;
    marshalSize      = TPMA_LOCALITY_Marshal(&in->locality, &buffer, NULL);

    // Its an error if the locality parameter is zero
    if(marshalBuffer[0] == 0)
	return TPM_RCS_RANGE + RC_PolicyLocality_locality;

    // Get existing locality setting in canonical form
    prevSetting[0] = 0;  // Code analysis says that this is not initialized
    buffer         = prevSetting;
    TPMA_LOCALITY_Marshal(&session->commandLocality, &buffer, NULL);

    // If the locality has previously been set
    if(prevSetting[0] != 0
       // then the current locality setting and the requested have to be the same
       // type (that is, either both normal or both extended
       && ((prevSetting[0] < 32) != (marshalBuffer[0] < 32)))
	return TPM_RCS_RANGE + RC_PolicyLocality_locality;

    // See if the input is a regular or extended locality
    if(marshalBuffer[0] < 32)
	{
	    // if there was no previous setting, start with all normal localities
	    // enabled
	    if(prevSetting[0] == 0)
		prevSetting[0] = 0x1F;

	    // AND the new setting with the previous setting and store it in prevSetting
	    prevSetting[0] &= marshalBuffer[0];

	    // The result setting can not be 0
	    if(prevSetting[0] == 0)
		return TPM_RCS_RANGE + RC_PolicyLocality_locality;
	}
    else
	{
	    // for extended locality
	    // if the locality has already been set, then it must match the
	    if(prevSetting[0] != 0 && prevSetting[0] != marshalBuffer[0])
		return TPM_RCS_RANGE + RC_PolicyLocality_locality;

	    // Setting is OK
	    prevSetting[0] = marshalBuffer[0];
	}

    // Internal Data Update

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyLocality || locality)
    // Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    // add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    // add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    // add input locality
    CryptDigestUpdate(&hashState, marshalSize, marshalBuffer);

    // complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update session locality by unmarshal function.  The function must succeed
    // because both input and existing locality setting have been validated.
    buffer = prevSetting;
    TPMA_LOCALITY_Unmarshal(&session->commandLocality, &buffer, (INT32*)&marshalSize);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyLocality



#include "Tpm.h"
#include "PolicyNV_fp.h"

#if CC_PolicyNV  // Conditional expansion of this file

#  include "Policy_spt_fp.h"

/*(See part 3 specification)
// Do comparison to NV location
*/
//  Return Type: TPM_RC
//      TPM_RC_AUTH_TYPE            NV index authorization type is not correct
//      TPM_RC_NV_LOCKED            NV index read locked
//      TPM_RC_NV_UNINITIALIZED     the NV index has not been initialized
//      TPM_RC_POLICY               the comparison to the NV contents failed
//      TPM_RC_SIZE                 the size of 'nvIndex' data starting at 'offset'
//                                  is less than the size of 'operandB'
//      TPM_RC_VALUE                'offset' is too large
TPM_RC
TPM2_PolicyNV(PolicyNV_In* in  // IN: input parameter list
	      )
{
    TPM_RC       result;
    SESSION*     session;
    NV_REF       locator;
    NV_INDEX*    nvIndex;
    BYTE         nvBuffer[sizeof(in->operandB.t.buffer)];
    TPM2B_NAME   nvName;
    TPM_CC       commandCode = TPM_CC_PolicyNV;
    HASH_STATE   hashState;
    TPM2B_DIGEST argHash;
    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    //If this is a trial policy, skip all validations and the operation
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    // No need to access the actual NV index information for a trial policy.
	    nvIndex = NvGetIndexInfo(in->nvIndex, &locator);

	    // Common read access checks. NvReadAccessChecks() may return
	    // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
	    result = NvReadAccessChecks(
					in->authHandle, in->nvIndex, nvIndex->publicArea.attributes);
	    if(result != TPM_RC_SUCCESS)
		return result;

	    // Make sure that offset is within range
	    if(in->offset > nvIndex->publicArea.dataSize)
		return TPM_RCS_VALUE + RC_PolicyNV_offset;

	    // Valid NV data size should not be smaller than input operandB size
	    if((nvIndex->publicArea.dataSize - in->offset) < in->operandB.t.size)
		return TPM_RCS_SIZE + RC_PolicyNV_operandB;

	    // Get NV data.  The size of NV data equals the input operand B size
	    NvGetIndexData(nvIndex, locator, in->offset, in->operandB.t.size, nvBuffer);

	    // Check to see if the condition is valid
	    if(!PolicySptCheckCondition(in->operation, nvBuffer,
					in->operandB.t.buffer, in->operandB.t.size))
		return TPM_RC_POLICY;
	}
    // Internal Data Update

    // Start argument hash
    argHash.t.size = CryptHashStart(&hashState, session->authHashAlg);

    //  add operandB
    CryptDigestUpdate2B(&hashState, &in->operandB.b);

    //  add offset
    CryptDigestUpdateInt(&hashState, sizeof(UINT16), in->offset);

    //  add operation
    CryptDigestUpdateInt(&hashState, sizeof(TPM_EO), in->operation);

    //  complete argument digest
    CryptHashEnd2B(&hashState, &argHash.b);

    // Update policyDigest
    //  Start digest
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add argument digest
    CryptDigestUpdate2B(&hashState, &argHash.b);

    // Adding nvName
    CryptDigestUpdate2B(&hashState, &EntityGetName(in->nvIndex, &nvName)->b);

    // complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyNV


#include "Tpm.h"
#include "PolicyCounterTimer_fp.h"

#if CC_PolicyCounterTimer  // Conditional expansion of this file

#  include "Policy_spt_fp.h"

/*(See part 3 specification)
// Add a conditional gating of a policy based on the contents of the
// TPMS_TIME_INFO structure.
*/
//  Return Type: TPM_RC
//      TPM_RC_POLICY           the comparison of the selected portion of the
//                              TPMS_TIME_INFO with 'operandB' failed
//      TPM_RC_RANGE            'offset' + 'size' exceed size of TPMS_TIME_INFO
//                              structure
TPM_RC
TPM2_PolicyCounterTimer(PolicyCounterTimer_In* in  // IN: input parameter list
			)
{
    SESSION*     session;
    TIME_INFO    infoData;  // data buffer of  TPMS_TIME_INFO
    BYTE*        pInfoData = (BYTE*)&infoData;
    UINT16       infoDataSize;
    TPM_CC       commandCode = TPM_CC_PolicyCounterTimer;
    HASH_STATE   hashState;
    TPM2B_DIGEST argHash;
    // Input Validation
    // Get a marshaled time structure
    infoDataSize = TimeGetMarshaled(&infoData);
    pAssert(infoDataSize <= sizeof(infoData));  // libtpms added; 25 < 32 ==> unfounded coverity complaint
    // Make sure that the referenced stays within the bounds of the structure.
    // NOTE: the offset checks are made even for a trial policy because the policy
    // will not make any sense if the references are out of bounds of the timer
    // structure.
    if(in->offset > infoDataSize)
	return TPM_RCS_VALUE + RC_PolicyCounterTimer_offset;
    if((UINT32)in->offset + (UINT32)in->operandB.t.size > infoDataSize)
	return TPM_RCS_RANGE;
    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    //If this is a trial policy, skip the check to see if the condition is met.
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    // If the command is going to use any part of the counter or timer, need
	    // to verify that time is advancing.
	    // The time and clock vales are the first two 64-bit values in the clock
	    if(in->offset < sizeof(UINT64) + sizeof(UINT64))
		{
		    // Using Clock or Time so see if clock is running. Clock doesn't
		    // run while NV is unavailable.
		    // TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned here.
		    RETURN_IF_NV_IS_NOT_AVAILABLE;
		}
	    // offset to the starting position
	    pInfoData = (BYTE*)infoData;
	    // Check to see if the condition is valid
	    if(!PolicySptCheckCondition(in->operation,
					pInfoData + in->offset,
					in->operandB.t.buffer,
					in->operandB.t.size))
		return TPM_RC_POLICY;
	}
    // Internal Data Update
    // Start argument list hash
    argHash.t.size = CryptHashStart(&hashState, session->authHashAlg);
    //  add operandB
    CryptDigestUpdate2B(&hashState, &in->operandB.b);
    //  add offset
    CryptDigestUpdateInt(&hashState, sizeof(UINT16), in->offset);
    //  add operation
    CryptDigestUpdateInt(&hashState, sizeof(TPM_EO), in->operation);
    //  complete argument hash
    CryptHashEnd2B(&hashState, &argHash.b);

    // update policyDigest
    //  start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add argument digest
    CryptDigestUpdate2B(&hashState, &argHash.b);

    // complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyCounterTimer



#include "Tpm.h"
#include "PolicyCommandCode_fp.h"

#if CC_PolicyCommandCode  // Conditional expansion of this file

/*(See part 3 specification)
// Add a Command Code restriction to the policyDigest
*/
//  Return Type: TPM_RC
//      TPM_RC_VALUE        'commandCode' of 'policySession' previously set to
//                          a different value

TPM_RC
TPM2_PolicyCommandCode(PolicyCommandCode_In* in  // IN: input parameter list
		       )
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyCommandCode;
    HASH_STATE hashState;
    // Input validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    if(session->commandCode != 0 && session->commandCode != in->code)
	return TPM_RCS_VALUE + RC_PolicyCommandCode_code;
    if(CommandCodeToCommandIndex(in->code) == UNIMPLEMENTED_COMMAND_INDEX)
	return TPM_RCS_POLICY_CC + RC_PolicyCommandCode_code;

    // Internal Data Update
    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyCommandCode || code)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add input commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), in->code);

    //  complete the hash and get the results
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update commandCode value in session context
    session->commandCode = in->code;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyCommandCode


#include "Tpm.h"
#include "PolicyCpHash_fp.h"

#if CC_PolicyCpHash  // Conditional expansion of this file

/*(See part 3 specification)
// Add a cpHash restriction to the policyDigest
*/
//  Return Type: TPM_RC
//      TPM_RC_CPHASH           cpHash of 'policySession' has previously been set
//                              to a different value
//      TPM_RC_SIZE             'cpHashA' is not the size of a digest produced
//                              by the hash algorithm associated with
//                              'policySession'
TPM_RC
TPM2_PolicyCpHash(PolicyCpHash_In* in  // IN: input parameter list
		  )
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyCpHash;
    HASH_STATE hashState;
    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // A valid cpHash must have the same size as session hash digest
    // NOTE: the size of the digest can't be zero because TPM_ALG_NULL
    // can't be used for the authHashAlg.
    if(in->cpHashA.t.size != CryptHashGetDigestSize(session->authHashAlg))
	return TPM_RCS_SIZE + RC_PolicyCpHash_cpHashA;

    // error if the cpHash in session context is not empty and is not the same
    // as the input or is not a cpHash
    if((IsCpHashUnionOccupied(session->attributes))
       && (!session->attributes.isCpHashDefined
	   || !MemoryEqual2B(&in->cpHashA.b, &session->u1.cpHash.b)))
	return TPM_RC_CPHASH;

    // Internal Data Update

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyCpHash || cpHashA)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add cpHashA
    CryptDigestUpdate2B(&hashState, &in->cpHashA.b);

    //  complete the digest and get the results
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update cpHash in session context
    session->u1.cpHash                  = in->cpHashA;
    session->attributes.isCpHashDefined = SET;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyCpHash


#include "Tpm.h"
#include "PolicyNameHash_fp.h"

#if CC_PolicyNameHash  // Conditional expansion of this file

/*(See part 3 specification)
// Add a nameHash restriction to the policyDigest
*/
//  Return Type: TPM_RC
//      TPM_RC_CPHASH     'nameHash' has been previously set to a different value
//      TPM_RC_SIZE       'nameHash' is not the size of the digest produced by the
//                        hash algorithm associated with 'policySession'
TPM_RC
TPM2_PolicyNameHash(PolicyNameHash_In* in  // IN: input parameter list
		    )
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyNameHash;
    HASH_STATE hashState;
    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // A valid nameHash must have the same size as session hash digest
    // Since the authHashAlg for a session cannot be TPM_ALG_NULL, the digest size
    // is always non-zero.
    if(in->nameHash.t.size != CryptHashGetDigestSize(session->authHashAlg))
	return TPM_RCS_SIZE + RC_PolicyNameHash_nameHash;

    // error if the nameHash in session context is not empty
    if(IsCpHashUnionOccupied(session->attributes))
	return TPM_RC_CPHASH;

    // Internal Data Update

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyNameHash || nameHash)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add nameHash
    CryptDigestUpdate2B(&hashState, &in->nameHash.b);

    //  complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update nameHash in session context
    session->u1.nameHash                  = in->nameHash;
    if (g_RuntimeProfile.stateFormatLevel >= 4)		// libtpms added: isNameHashDefined was added
	session->attributes.isNameHashDefined = SET;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyNameHash


#include "Tpm.h"
#include "PolicyDuplicationSelect_fp.h"

#if CC_PolicyDuplicationSelect  // Conditional expansion of this file

/*(See part 3 specification)
// allows qualification of duplication so that it a specific new parent may be
// selected or a new parent selected for a specific object.
*/
//  Return Type: TPM_RC
//      TPM_RC_COMMAND_CODE   'commandCode' of 'policySession' is not empty
//      TPM_RC_CPHASH         'nameHash' of 'policySession' is not empty
TPM_RC
TPM2_PolicyDuplicationSelect(
			     PolicyDuplicationSelect_In* in  // IN: input parameter list
			     )
{
    SESSION*   session;
    HASH_STATE hashState;
    TPM_CC     commandCode = TPM_CC_PolicyDuplicationSelect;
    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // nameHash in session context must be empty
    if(session->u1.nameHash.t.size != 0)
	return TPM_RC_CPHASH;

    // commandCode in session context must be empty
    if(session->commandCode != 0)
	return TPM_RC_COMMAND_CODE;

    // Internal Data Update

    // Update name hash
    session->u1.nameHash.t.size = CryptHashStart(&hashState, session->authHashAlg);

    //  add objectName
    CryptDigestUpdate2B(&hashState, &in->objectName.b);

    //  add new parent name
    CryptDigestUpdate2B(&hashState, &in->newParentName.b);

    //  complete hash
    CryptHashEnd2B(&hashState, &session->u1.nameHash.b);
    if (g_RuntimeProfile.stateFormatLevel >= 4)		// libtpms added: isNameHashDefined was added
	session->attributes.isNameHashDefined = SET;

    // update policy hash
    // Old policyDigest size should be the same as the new policyDigest size since
    // they are using the same hash algorithm
    session->u2.policyDigest.t.size =
	CryptHashStart(&hashState, session->authHashAlg);
    //  add old policy
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add command code
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add objectName
    if(in->includeObject == YES)
	CryptDigestUpdate2B(&hashState, &in->objectName.b);

    //  add new parent name
    CryptDigestUpdate2B(&hashState, &in->newParentName.b);

    //  add includeObject
    CryptDigestUpdateInt(&hashState, sizeof(TPMI_YES_NO), in->includeObject);

    //  complete digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // set commandCode in session context
    session->commandCode = TPM_CC_Duplicate;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyDuplicationSelect


#include "Tpm.h"
#include "PolicyAuthorize_fp.h"

#if CC_PolicyAuthorize  // Conditional expansion of this file

#  include "Policy_spt_fp.h"

/*(See part 3 specification)
// Change policy by a signature from authority
*/
//  Return Type: TPM_RC
//      TPM_RC_HASH         hash algorithm in 'keyName' is not supported
//      TPM_RC_SIZE         'keyName' is not the correct size for its hash algorithm
//      TPM_RC_VALUE        the current policyDigest of 'policySession' does not
//                          match 'approvedPolicy'; or 'checkTicket' doesn't match
//                          the provided values
TPM_RC
TPM2_PolicyAuthorize(PolicyAuthorize_In* in  // IN: input parameter list
		     )
{
    TPM_RC           result = TPM_RC_SUCCESS;
    SESSION*         session;
    TPM2B_DIGEST     authHash;
    HASH_STATE       hashState;
    TPMT_TK_VERIFIED ticket;
    TPM_ALG_ID       hashAlg;
    UINT16           digestSize;
    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    if(in->keySign.t.size < 2)
	{
	    return TPM_RCS_SIZE + RC_PolicyAuthorize_keySign;
	}

    // Extract from the Name of the key, the algorithm used to compute its Name
    hashAlg = BYTE_ARRAY_TO_UINT16(in->keySign.t.name);

    // 'keySign' parameter needs to use a supported hash algorithm, otherwise
    // can't tell how large the digest should be
    if(!CryptHashIsValidAlg(hashAlg, FALSE))
	return TPM_RCS_HASH + RC_PolicyAuthorize_keySign;

    digestSize = CryptHashGetDigestSize(hashAlg);
    if(digestSize != (in->keySign.t.size - 2))
	return TPM_RCS_SIZE + RC_PolicyAuthorize_keySign;

    //If this is a trial policy, skip all validations
    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    // Check that "approvedPolicy" matches the current value of the
	    // policyDigest in policy session
	    if(!MemoryEqual2B(&session->u2.policyDigest.b, &in->approvedPolicy.b))
		return TPM_RCS_VALUE + RC_PolicyAuthorize_approvedPolicy;

	    // Validate ticket TPMT_TK_VERIFIED
	    // Compute aHash.  The authorizing object sign a digest
	    //  aHash := hash(approvedPolicy || policyRef).
	    // Start hash
	    authHash.t.size = CryptHashStart(&hashState, hashAlg);

	    // add approvedPolicy
	    CryptDigestUpdate2B(&hashState, &in->approvedPolicy.b);

	    // add policyRef
	    CryptDigestUpdate2B(&hashState, &in->policyRef.b);

	    // complete hash
	    CryptHashEnd2B(&hashState, &authHash.b);

	    // re-compute TPMT_TK_VERIFIED
	    result = TicketComputeVerified(in->checkTicket.hierarchy, &authHash,
					   &in->keySign, &ticket);
	    if(result != TPM_RC_SUCCESS)
		return result;

	    // Compare ticket digest.  If not match, return error
	    if(!MemoryEqual2B(&in->checkTicket.digest.b, &ticket.digest.b))
		return TPM_RCS_VALUE + RC_PolicyAuthorize_checkTicket;
	}

    // Internal Data Update

    // Set policyDigest to zero digest
    PolicyDigestClear(session);

    // Update policyDigest
    PolicyContextUpdate(
			TPM_CC_PolicyAuthorize, &in->keySign, &in->policyRef, NULL, 0, session);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyAuthorize


#include "Tpm.h"
#include "PolicyAuthValue_fp.h"

#if CC_PolicyAuthValue  // Conditional expansion of this file

#  include "Policy_spt_fp.h"

/*(See part 3 specification)
// allows a policy to be bound to the authorization value of the authorized
// object
*/
TPM_RC
TPM2_PolicyAuthValue(PolicyAuthValue_In* in  // IN: input parameter list
		     )
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyAuthValue;
    HASH_STATE hashState;
    // Internal Data Update

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyAuthValue)
    //   Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  complete the hash and get the results
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update isAuthValueNeeded bit in the session context
    session->attributes.isAuthValueNeeded = SET;
    session->attributes.isPasswordNeeded  = CLEAR;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyAuthValue


#include "Tpm.h"
#include "PolicyPassword_fp.h"

#if CC_PolicyPassword  // Conditional expansion of this file

#  include "Policy_spt_fp.h"

/*(See part 3 specification)
// allows a policy to be bound to the authorization value of the authorized
// object
*/
TPM_RC
TPM2_PolicyPassword(PolicyPassword_In* in  // IN: input parameter list
		    )
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyAuthValue;
    HASH_STATE hashState;
    // Internal Data Update

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyAuthValue)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    //  Update isPasswordNeeded bit
    session->attributes.isPasswordNeeded  = SET;
    session->attributes.isAuthValueNeeded = CLEAR;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyPassword


#include "Tpm.h"
#include "PolicyGetDigest_fp.h"
#if CC_PolicyGetDigest  // Conditional expansion of this file
TPM_RC
TPM2_PolicyGetDigest(
		     PolicyGetDigest_In      *in,            // IN: input parameter list
		     PolicyGetDigest_Out     *out            // OUT: output parameter list
		     )
{
    SESSION     *session;
    // Command Output
    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    out->policyDigest = session->u2.policyDigest;
    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyGetDigest

#include "Tpm.h"
#include "PolicyNvWritten_fp.h"

#if CC_PolicyNvWritten  // Conditional expansion of this file

// Make an NV Index policy dependent on the state of the TPMA_NV_WRITTEN
// attribute of the index.
//  Return Type: TPM_RC
//      TPM_RC_VALUE         a conflicting request for the attribute has
//                           already been processed
TPM_RC
TPM2_PolicyNvWritten(PolicyNvWritten_In* in  // IN: input parameter list
		     )
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyNvWritten;
    HASH_STATE hashState;
    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // If already set is this a duplicate (the same setting)? If it
    // is a conflicting setting, it is an error
    if(session->attributes.checkNvWritten == SET)
	{
	    if(((session->attributes.nvWrittenState == SET) != (in->writtenSet == YES)))
		return TPM_RCS_VALUE + RC_PolicyNvWritten_writtenSet;
	}

    // Internal Data Update

    // Set session attributes so that the NV Index needs to be checked
    session->attributes.checkNvWritten = SET;
    session->attributes.nvWrittenState = (in->writtenSet == YES);

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyNvWritten
    //                          || writtenSet)
    // Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    // add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    // add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    // add the byte of writtenState
    CryptDigestUpdateInt(&hashState, sizeof(TPMI_YES_NO), in->writtenSet);

    // complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyNvWritten

#include "Tpm.h"
#include "PolicyTemplate_fp.h"

#if CC_PolicyTemplate  // Conditional expansion of this file

/*(See part 3 specification)
// Add a cpHash restriction to the policyDigest
*/
//  Return Type: TPM_RC
//      TPM_RC_CPHASH           cpHash of 'policySession' has previously been set
//                              to a different value
//      TPM_RC_SIZE             'templateHash' is not the size of a digest produced
//                              by the hash algorithm associated with
//                              'policySession'
TPM_RC
TPM2_PolicyTemplate(PolicyTemplate_In* in  // IN: input parameter list
		    )
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyTemplate;
    HASH_STATE hashState;
    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // error if the templateHash in session context is not empty and is not the
    // same as the input or is not a template
    if((IsCpHashUnionOccupied(session->attributes))
       && (!session->attributes.isTemplateHashDefined
	   || !MemoryEqual2B(&in->templateHash.b, &session->u1.templateHash.b)))
	return TPM_RC_CPHASH;

    // A valid templateHash must have the same size as session hash digest
    if(in->templateHash.t.size != CryptHashGetDigestSize(session->authHashAlg))
	return TPM_RCS_SIZE + RC_PolicyTemplate_templateHash;

    // Internal Data Update
    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyCpHash
    //  || cpHashA.buffer)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add cpHashA
    CryptDigestUpdate2B(&hashState, &in->templateHash.b);

    //  complete the digest and get the results
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update templateHash in session context
    session->u1.templateHash                  = in->templateHash;
    session->attributes.isTemplateHashDefined = SET;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyTemplate

#include "Tpm.h"

#if CC_PolicyAuthorizeNV  // Conditional expansion of this file

#  include "PolicyAuthorizeNV_fp.h"
#  include "Policy_spt_fp.h"
#  include "Marshal.h"

/*(See part 3 specification)
// Change policy by a signature from authority
*/
//  Return Type: TPM_RC
//      TPM_RC_HASH         hash algorithm in 'keyName' is not supported or is not
//                          the same as the hash algorithm of the policy session
//      TPM_RC_SIZE         'keyName' is not the correct size for its hash algorithm
//      TPM_RC_VALUE        the current policyDigest of 'policySession' does not
//                          match 'approvedPolicy'; or 'checkTicket' doesn't match
//                          the provided values
TPM_RC
TPM2_PolicyAuthorizeNV(PolicyAuthorizeNV_In* in)
{
    SESSION*   session;
    TPM_RC     result;
    NV_REF     locator;
    NV_INDEX*  nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    TPM2B_NAME name;
    TPMT_HA    policyInNv = {
                   .hashAlg = 0, // libpms added: Coverity
               };
    BYTE       nvTemp[sizeof(TPMT_HA)];
    BYTE*      buffer = nvTemp;
    INT32      size;
    // Input Validation
    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Skip checks if this is a trial policy
    if(!session->attributes.isTrialPolicy)
	{
	    // Check the authorizations for reading
	    // Common read access checks. NvReadAccessChecks() returns
	    // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
	    // error may be returned at this point
	    result = NvReadAccessChecks(
					in->authHandle, in->nvIndex, nvIndex->publicArea.attributes);
	    if(result != TPM_RC_SUCCESS)
		return result;

	    // Read the contents of the index into a temp buffer
	    size = MIN(nvIndex->publicArea.dataSize, sizeof(TPMT_HA));
	    NvGetIndexData(nvIndex, locator, 0, (UINT16)size, nvTemp);

	    // Unmarshal the contents of the buffer into the internal format of a
	    // TPMT_HA so that the hash and digest elements can be accessed from the
	    // structure rather than the byte array that is in the Index (written by
	    // user of the Index).
	    result = TPMT_HA_Unmarshal(&policyInNv, &buffer, &size, FALSE);
	    if(result != TPM_RC_SUCCESS)
		return result;

	    // Verify that the hash is the same
	    if(policyInNv.hashAlg != session->authHashAlg)
		return TPM_RC_HASH;

	    // See if the contents of the digest in the Index matches the value
	    // in the policy
	    if(!MemoryEqual(&policyInNv.digest,
			    &session->u2.policyDigest.t.buffer,
			    session->u2.policyDigest.t.size))
		return TPM_RC_VALUE;
	}

    // Internal Data Update

    // Set policyDigest to zero digest
    PolicyDigestClear(session);

    // Update policyDigest
    PolicyContextUpdate(TPM_CC_PolicyAuthorizeNV,
			EntityGetName(in->nvIndex, &name),
			NULL,
			NULL,
			0,
			session);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyAuthorizeNV

#include "Tpm.h"
#include "PolicyCapability_fp.h"
#include "Policy_spt_fp.h"
#include "ACT_spt_fp.h"
#include "AlgorithmCap_fp.h"
#include "CommandAudit_fp.h"
#include "CommandCodeAttributes_fp.h"
#include "CryptEccMain_fp.h"
#include "Handle_fp.h"
#include "NVDynamic_fp.h"
#include "Object_fp.h"
#include "PCR_fp.h"
#include "PP_fp.h"
#include "PropertyCap_fp.h"
#include "Session_fp.h"

#if CC_PolicyCapability  // Conditional expansion of this file

/*(See part 3 specification)
// This command performs an immediate policy assertion against the current
// value of a TPM Capability.
*/
//  Return Type: TPM_RC
//      TPM_RC_HANDLE       value of 'property' is in an unsupported handle range
//                          for the TPM_CAP_HANDLES 'capability' value
//      TPM_RC_VALUE        invalid 'capability'; or 'property' is not 0 for the
//                          TPM_CAP_PCRS 'capability' value
//      TPM_RC_SIZE         'operandB' is larger than the size of the capability
//                          data minus 'offset'.
TPM_RC
TPM2_PolicyCapability(PolicyCapability_In* in  // IN: input parameter list
		      )
{
    union
    {
	TPMS_ALG_PROPERTY      alg;
	TPM_HANDLE             handle;
	TPMA_CC                commandAttributes;
	TPM_CC                 command;
	TPMS_TAGGED_PCR_SELECT pcrSelect;
	TPMS_TAGGED_PROPERTY   tpmProperty;
#  if ALG_ECC
	TPM_ECC_CURVE curve;
#  endif  // ALG_ECC
	TPMS_TAGGED_POLICY policy;
#  if ACT_SUPPORT
	TPMS_ACT_DATA act;
#  endif  // ACT_SUPPORT
    } propertyUnion;

    SESSION*     session;
    BYTE         propertyData[sizeof(propertyUnion)];
    UINT16       propertySize = 0;
    BYTE*        buffer       = propertyData;
    INT32        bufferSize   = sizeof(propertyData);
    TPM_CC       commandCode  = TPM_CC_PolicyCapability;
    HASH_STATE   hashState;
    TPM2B_DIGEST argHash;

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    if(session->attributes.isTrialPolicy == CLEAR)
	{
	    switch(in->capability)
		{
		  case TPM_CAP_ALGS:
		    if(AlgorithmCapGetOneImplemented((TPM_ALG_ID)in->property,
						     &propertyUnion.alg))
			{
			    propertySize = TPMS_ALG_PROPERTY_Marshal
					   (&propertyUnion.alg, &buffer, &bufferSize);
			}
		    break;
		  case TPM_CAP_HANDLES: {			// libtpms changed: older gcc
		    BOOL foundHandle = FALSE;
		    switch(HandleGetType((TPM_HANDLE)in->property))
			{
			  case TPM_HT_TRANSIENT:
			    foundHandle = ObjectCapGetOneLoaded((TPM_HANDLE)in->property);
			    break;
			  case TPM_HT_PERSISTENT:
			    foundHandle = NvCapGetOnePersistent((TPM_HANDLE)in->property);
			    break;
			  case TPM_HT_NV_INDEX:
			    foundHandle = NvCapGetOneIndex((TPM_HANDLE)in->property);
			    break;
			  case TPM_HT_LOADED_SESSION:
			    foundHandle =
				SessionCapGetOneLoaded((TPM_HANDLE)in->property);
			    break;
			  case TPM_HT_SAVED_SESSION:
			    foundHandle = SessionCapGetOneSaved((TPM_HANDLE)in->property);
			    break;
			  case TPM_HT_PCR:
			    foundHandle = PCRCapGetOneHandle((TPM_HANDLE)in->property);
			    break;
			  case TPM_HT_PERMANENT:
			    foundHandle =
				PermanentCapGetOneHandle((TPM_HANDLE)in->property);
			    break;
			  default:
			    // Unsupported input handle type
			    return TPM_RCS_HANDLE + RC_PolicyCapability_property;
			    break;
			}					// libtpms added
		    if(foundHandle)
			{
			    TPM_HANDLE handle = (TPM_HANDLE)in->property;
			    propertySize = TPM_HANDLE_Marshal(&handle, &buffer, &bufferSize);
			}
		    break;
		  }
		  case TPM_CAP_COMMANDS:
		    if(CommandCapGetOneCC((TPM_CC)in->property,
					  &propertyUnion.commandAttributes))
			{
			    propertySize = TPMA_CC_Marshal
					   (&propertyUnion.commandAttributes, &buffer, &bufferSize);
			}
		    break;
		  case TPM_CAP_PP_COMMANDS:
		    if(PhysicalPresenceCapGetOneCC((TPM_CC)in->property))
			{
			    TPM_CC cc    = (TPM_CC)in->property;
			    propertySize = TPM_CC_Marshal(&cc, &buffer, &bufferSize);
			}
		    break;
		  case TPM_CAP_AUDIT_COMMANDS:
		    if(CommandAuditCapGetOneCC((TPM_CC)in->property))
			{
			    TPM_CC cc    = (TPM_CC)in->property;
			    propertySize = TPM_CC_Marshal(&cc, &buffer, &bufferSize);
			}
		    break;
		    // NOTE: TPM_CAP_PCRS can't work for PolicyCapability since CAP_PCRS
		    // requires property to be 0 and always returns all the PCR banks.
		  case TPM_CAP_PCR_PROPERTIES:
		    if(PCRGetProperty((TPM_PT_PCR)in->property, &propertyUnion.pcrSelect))
			{
			    propertySize = TPMS_TAGGED_PCR_SELECT_Marshal
					   (&propertyUnion.pcrSelect, &buffer, &bufferSize);
			}
		    break;
		  case TPM_CAP_TPM_PROPERTIES:
		    if(TPMCapGetOneProperty((TPM_PT)in->property,
					    &propertyUnion.tpmProperty))
			{
			    propertySize = TPMS_TAGGED_PROPERTY_Marshal
					   (&propertyUnion.tpmProperty, &buffer, &bufferSize);
			}
		    break;
#  if ALG_ECC
		  case TPM_CAP_ECC_CURVES: {			// libtpms changed: older gcc
		    TPM_ECC_CURVE curve = (TPM_ECC_CURVE)in->property;
		    if(CryptCapGetOneECCCurve(curve))
			{
			    propertySize =
				TPM_ECC_CURVE_Marshal(&curve, &buffer, &bufferSize);
			}
		    break;
		  }						// libtpms added: older gcc
#  endif  // ALG_ECC
		  case TPM_CAP_AUTH_POLICIES:
		    if(HandleGetType((TPM_HANDLE)in->property) != TPM_HT_PERMANENT)
			return TPM_RCS_VALUE + RC_PolicyCapability_property;
		    if(PermanentHandleGetOnePolicy((TPM_HANDLE)in->property,
						   &propertyUnion.policy))
			{
			    propertySize = TPMS_TAGGED_POLICY_Marshal
					   (&propertyUnion.policy, &buffer, &bufferSize);
			}
		    break;
#  ifndef __ACT_DISABLED		// libtpms: added
#  if ACT_SUPPORT
		  case TPM_CAP_ACT:
		    if(((TPM_RH)in->property < TPM_RH_ACT_0)
		       || ((TPM_RH)in->property > TPM_RH_ACT_F))
			return TPM_RCS_VALUE + RC_PolicyCapability_property;
		    if(ActGetOneCapability((TPM_HANDLE)in->property, &propertyUnion.act))
			{
			    propertySize = TPMS_ACT_DATA_Marshal
					   (&propertyUnion.act, &buffer, &bufferSize);
			}
		    break;
#  endif  // ACT_SUPPORT
#  endif  // __ACT_DISABLED		// libtpms: added
		  case TPM_CAP_VENDOR_PROPERTY:
		    // vendor property is not implemented
		  default:
		    // Unsupported TPM_CAP value
		    return TPM_RCS_VALUE + RC_PolicyCapability_capability;
		    break;
		}

	    if(propertySize == 0)
		{
		    // A property that doesn't exist trivially satisfies NEQ, and
		    // trivially can't satisfy any other operation.
		    if(in->operation != TPM_EO_NEQ)
			{
			    return TPM_RC_POLICY;
			}
		}
	    else
		{
		    // The property was found, so we need to perform the comparison.

		    // Make sure that offset is within range
		    if(in->offset > propertySize)
			{
			    return TPM_RCS_VALUE + RC_PolicyCapability_offset;
			}

		    // Property data size should not be smaller than input operandB size
		    if((propertySize - in->offset) < in->operandB.t.size)
			{
			    return TPM_RCS_SIZE + RC_PolicyCapability_operandB;
			}

		    if(!PolicySptCheckCondition(in->operation,
						propertyData + in->offset,
						in->operandB.t.buffer,
						in->operandB.t.size))
			{
			    return TPM_RC_POLICY;
			}
		}
	}
    // Internal Data Update

    // Start argument hash
    argHash.t.size = CryptHashStart(&hashState, session->authHashAlg);

    //  add operandB
    CryptDigestUpdate2B(&hashState, &in->operandB.b);

    //  add offset
    CryptDigestUpdateInt(&hashState, sizeof(UINT16), in->offset);

    //  add operation
    CryptDigestUpdateInt(&hashState, sizeof(TPM_EO), in->operation);

    //  add capability
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CAP), in->capability);

    //  add property
    CryptDigestUpdateInt(&hashState, sizeof(UINT32), in->property);

    //  complete argument digest
    CryptHashEnd2B(&hashState, &argHash.b);

    // Update policyDigest
    //  Start digest
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add argument digest
    CryptDigestUpdate2B(&hashState, &argHash.b);

    // complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyCapability

#include "Tpm.h"
#include "PolicyParameters_fp.h"

#if CC_PolicyParameters  // Conditional expansion of this file

/*(See part 3 specification)
// Add a parameters restriction to the policyDigest
*/
//  Return Type: TPM_RC
//      TPM_RC_CPHASH     cpHash of 'policySession' has previously been set
//                        to a different value
//      TPM_RC_SIZE       'pHash' is not the size of the digest produced by the
//                        hash algorithm associated with 'policySession'
TPM_RC
TPM2_PolicyParameters(PolicyParameters_In* in  // IN: input parameter list
		      )
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyParameters;
    HASH_STATE hashState;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // A valid pHash must have the same size as session hash digest
    // Since the authHashAlg for a session cannot be TPM_ALG_NULL, the digest size
    // is always non-zero.
    if(in->pHash.t.size != CryptHashGetDigestSize(session->authHashAlg))
	return TPM_RCS_SIZE + RC_PolicyParameters_pHash;

    // error if the pHash in session context is not empty
    if(IsCpHashUnionOccupied(session->attributes))
	return TPM_RC_CPHASH;

    // Internal Data Update

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyParameters || pHash)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add pHash
    CryptDigestUpdate2B(&hashState, &in->pHash.b);

    //  complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update pHash in session context
    session->u1.pHash                           = in->pHash;
    session->attributes.isParametersHashDefined = SET;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyParameters
