/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Policy_spt_fp.h 1490 2019-07-26 21:13:22Z kgoldman $			*/
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
/*  (c) Copyright IBM Corp. and others, 2016					*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar  4, 2020  Time: 02:36:44PM
 */

#ifndef _POLICY_SPT_FP_H_
#define _POLICY_SPT_FP_H_

//** Functions
//*** PolicyParameterChecks()
// This function validates the common parameters of TPM2_PolicySiged()
// and TPM2_PolicySecret(). The common parameters are 'nonceTPM',
// 'expiration', and 'cpHashA'.
TPM_RC
PolicyParameterChecks(SESSION*      session,
                      UINT64        authTimeout,
                      TPM2B_DIGEST* cpHashA,
                      TPM2B_NONCE*  nonce,
                      TPM_RC        blameNonce,
                      TPM_RC        blameCpHash,
                      TPM_RC        blameExpiration);

//*** PolicyContextUpdate()
// Update policy hash
//      Update the policyDigest in policy session by extending policyRef and
//      objectName to it. This will also update the cpHash if it is present.
//
//  Return Type: void
void PolicyContextUpdate(
    TPM_CC        commandCode,    // IN: command code
    TPM2B_NAME*   name,           // IN: name of entity
    TPM2B_NONCE*  ref,            // IN: the reference data
    TPM2B_DIGEST* cpHash,         // IN: the cpHash (optional)
    UINT64        policyTimeout,  // IN: the timeout value for the policy
    SESSION*      session         // IN/OUT: policy session to be updated
);

//*** ComputeAuthTimeout()
// This function is used to determine what the authorization timeout value for
// the session should be.
UINT64
ComputeAuthTimeout(SESSION* session,   // IN: the session containing the time
                                       //     values
                   INT32 expiration,   // IN: either the number of seconds from
                                       //     the start of the session or the
                                       //     time in g_timer;
                   TPM2B_NONCE* nonce  // IN: indicator of the time base
);

//*** PolicyDigestClear()
// Function to reset the policyDigest of a session
void PolicyDigestClear(SESSION* session);

//*** PolicySptCheckCondition()
// Checks to see if the condition in the policy is satisfied.
BOOL PolicySptCheckCondition(TPM_EO operation, BYTE* opA, BYTE* opB, UINT16 size);

#endif  // _POLICY_SPT_FP_H_
