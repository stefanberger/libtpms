/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Attest_spt_fp.h 1490 2019-07-26 21:13:22Z kgoldman $			*/
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
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _ATTEST_SPT_FP_H_
#define _ATTEST_SPT_FP_H_

//***FillInAttestInfo()
// Fill in common fields of TPMS_ATTEST structure.
void FillInAttestInfo(
    TPMI_DH_OBJECT   signHandle,  // IN: handle of signing object
    TPMT_SIG_SCHEME* scheme,      // IN/OUT: scheme to be used for signing
    TPM2B_DATA*      data,        // IN: qualifying data
    TPMS_ATTEST*     attest       // OUT: attest structure
);

//***SignAttestInfo()
// Sign a TPMS_ATTEST structure. If signHandle is TPM_RH_NULL, a null signature
// is returned.
//
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES   'signHandle' references not a signing key
//      TPM_RC_SCHEME       'scheme' is not compatible with 'signHandle' type
//      TPM_RC_VALUE        digest generated for the given 'scheme' is greater than
//                          the modulus of 'signHandle' (for an RSA key);
//                          invalid commit status or failed to generate "r" value
//                          (for an ECC key)
TPM_RC
SignAttestInfo(OBJECT*          signKey,         // IN: sign object
               TPMT_SIG_SCHEME* scheme,          // IN: sign scheme
               TPMS_ATTEST*     certifyInfo,     // IN: the data to be signed
               TPM2B_DATA*      qualifyingData,  // IN: extra data for the signing
                                                 //     process
               TPM2B_ATTEST* attest,             // OUT: marshaled attest blob to be
                                                 //     signed
               TPMT_SIGNATURE* signature         // OUT: signature
);

//*** IsSigningObject()
// Checks to see if the object is OK for signing. This is here rather than in
// Object_spt.c because all the attestation commands use this file but not
// Object_spt.c.
//  Return Type: BOOL
//      TRUE(1)         object may sign
//      FALSE(0)        object may not sign
BOOL IsSigningObject(OBJECT* object  // IN:
);

#endif  // _ATTEST_SPT_FP_H_
