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
/*  (c) Copyright IBM Corp. and others, 2023					*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _TICKET_FP_H_
#define _TICKET_FP_H_

//*** TicketIsSafe()
// This function indicates if producing a ticket is safe.
// It checks if the leading bytes of an input buffer is TPM_GENERATED_VALUE
// or its substring of canonical form.  If so, it is not safe to produce ticket
// for an input buffer claiming to be TPM generated buffer
//  Return Type: BOOL
//      TRUE(1)         safe to produce ticket
//      FALSE(0)        not safe to produce ticket
BOOL TicketIsSafe(TPM2B* buffer);

//*** TicketComputeVerified()
// This function creates a TPMT_TK_VERIFIED ticket.
TPM_RC TicketComputeVerified(
    TPMI_RH_HIERARCHY hierarchy,  // IN: hierarchy constant for ticket
    TPM2B_DIGEST*     digest,     // IN: digest
    TPM2B_NAME*       keyName,    // IN: name of key that signed the values
    TPMT_TK_VERIFIED* ticket      // OUT: verified ticket
);

//*** TicketComputeAuth()
// This function creates a TPMT_TK_AUTH ticket.
TPM_RC TicketComputeAuth(
    TPM_ST            type,            // IN: the type of ticket.
    TPMI_RH_HIERARCHY hierarchy,       // IN: hierarchy constant for ticket
    UINT64            timeout,         // IN: timeout
    BOOL              expiresOnReset,  // IN: flag to indicate if ticket expires on
                                       //      TPM Reset
    TPM2B_DIGEST* cpHashA,             // IN: input cpHashA
    TPM2B_NONCE*  policyRef,           // IN: input policyRef
    TPM2B_NAME*   entityName,          // IN: name of entity
    TPMT_TK_AUTH* ticket               // OUT: Created ticket
);

//*** TicketComputeHashCheck()
// This function creates a TPMT_TK_HASHCHECK ticket.
TPM_RC TicketComputeHashCheck(
    TPMI_RH_HIERARCHY  hierarchy,  // IN: hierarchy constant for ticket
    TPM_ALG_ID         hashAlg,    // IN: the hash algorithm for 'digest'
    TPM2B_DIGEST*      digest,     // IN: input digest
    TPMT_TK_HASHCHECK* ticket      // OUT: Created ticket
);

//*** TicketComputeCreation()
// This function creates a TPMT_TK_CREATION ticket.
TPM_RC TicketComputeCreation(TPMI_RH_HIERARCHY hierarchy,  // IN: hierarchy for ticket
                             TPM2B_NAME*       name,       // IN: object name
                             TPM2B_DIGEST*     creation,   // IN: creation hash
                             TPMT_TK_CREATION* ticket      // OUT: created ticket
);

#endif  // _TICKET_FP_H_
