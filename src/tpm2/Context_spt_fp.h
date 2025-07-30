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
/*  (c) Copyright IBM Corp. and others, 2016 - 2023				*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _CONTEXT_SPT_FP_H_
#define _CONTEXT_SPT_FP_H_

//*** ComputeContextProtectionKey()
// This function retrieves the symmetric protection key for context encryption
// It is used by TPM2_ConextSave and TPM2_ContextLoad to create the symmetric
// encryption key and iv
//  Return Type: TPM_RC
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM
//                              failed to derive the Firmware SVN Secret for the
//                              requested SVN.
TPM_RC ComputeContextProtectionKey(TPMS_CONTEXT*  contextBlob,  // IN: context blob
                                   TPM2B_SYM_KEY* symKey,  // OUT: the symmetric key
                                   TPM2B_IV*      iv       // OUT: the IV.
);

//*** ComputeContextIntegrity()
// Generate the integrity hash for a context
//       It is used by TPM2_ContextSave to create an integrity hash
//       and by TPM2_ContextLoad to compare an integrity hash
//  Return Type: TPM_RC
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM
//                              failed to derive the Firmware SVN Secret for the
//                              requested SVN.
TPM_RC ComputeContextIntegrity(TPMS_CONTEXT* contextBlob,  // IN: context blob
                               TPM2B_DIGEST* integrity     // OUT: integrity
);

//*** SequenceDataExport()
// This function is used scan through the sequence object and
// either modify the hash state data for export (contextSave) or to
// import it into the internal format (contextLoad).
// This function should only be called after the sequence object has been copied
// to the context buffer (contextSave) or from the context buffer into the sequence
// object. The presumption is that the context buffer version of the data is the
// same size as the internal representation so nothing outsize of the hash context
// area gets modified.
void SequenceDataExport(
    HASH_OBJECT*        object,       // IN: an internal hash object
    HASH_OBJECT_BUFFER* exportObject  // OUT: a sequence context in a buffer
);

//*** SequenceDataImport()
// This function is used scan through the sequence object and
// either modify the hash state data for export (contextSave) or to
// import it into the internal format (contextLoad).
// This function should only be called after the sequence object has been copied
// to the context buffer (contextSave) or from the context buffer into the sequence
// object. The presumption is that the context buffer version of the data is the
// same size as the internal representation so nothing outsize of the hash context
// area gets modified.
void SequenceDataImport(
    HASH_OBJECT*        object,       // IN/OUT: an internal hash object
    HASH_OBJECT_BUFFER* exportObject  // IN/OUT: a sequence context in a buffer
);

#endif  // _CONTEXT_SPT_FP_H_
