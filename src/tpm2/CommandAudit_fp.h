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
 *  Date: Apr  2, 2019  Time: 04:23:27PM
 */

#ifndef _COMMAND_AUDIT_FP_H_
#define _COMMAND_AUDIT_FP_H_

//*** CommandAuditPreInstall_Init()
// This function initializes the command audit list. This function simulates
// the behavior of manufacturing. A function is used instead of a structure
// definition because this is easier than figuring out the initialization value
// for a bit array.
//
// This function would not be implemented outside of a manufacturing or
// simulation environment.
void CommandAuditPreInstall_Init(void);

//*** CommandAuditStartup()
// This function clears the command audit digest on a TPM Reset.
BOOL CommandAuditStartup(STARTUP_TYPE type  // IN: start up type
);

//*** CommandAuditSet()
// This function will SET the audit flag for a command. This function
// will not SET the audit flag for a command that is not implemented. This
// ensures that the audit status is not SET when TPM2_GetCapability() is
// used to read the list of audited commands.
//
// This function is only used by TPM2_SetCommandCodeAuditStatus().
//
// The actions in TPM2_SetCommandCodeAuditStatus() are expected to cause the
// changes to be saved to NV after it is setting and clearing bits.
//  Return Type: BOOL
//      TRUE(1)         command code audit status was changed
//      FALSE(0)        command code audit status was not changed
BOOL CommandAuditSet(TPM_CC commandCode  // IN: command code
);

//*** CommandAuditClear()
// This function will CLEAR the audit flag for a command. It will not CLEAR the
// audit flag for TPM_CC_SetCommandCodeAuditStatus().
//
// This function is only used by TPM2_SetCommandCodeAuditStatus().
//
// The actions in TPM2_SetCommandCodeAuditStatus() are expected to cause the
// changes to be saved to NV after it is setting and clearing bits.
//  Return Type: BOOL
//      TRUE(1)         command code audit status was changed
//      FALSE(0)        command code audit status was not changed
BOOL CommandAuditClear(TPM_CC commandCode  // IN: command code
);

//*** CommandAuditIsRequired()
// This function indicates if the audit flag is SET for a command.
//  Return Type: BOOL
//      TRUE(1)         command is audited
//      FALSE(0)        command is not audited
BOOL CommandAuditIsRequired(COMMAND_INDEX commandIndex  // IN: command index
);

//*** CommandAuditCapGetCCList()
// This function returns a list of commands that have their audit bit SET.
//
// The list starts at the input commandCode.
//  Return Type: TPMI_YES_NO
//      YES         if there are more command code available
//      NO          all the available command code has been returned
TPMI_YES_NO
CommandAuditCapGetCCList(TPM_CC   commandCode,  // IN: start command code
                         UINT32   count,        // IN: count of returned TPM_CC
                         TPML_CC* commandList   // OUT: list of TPM_CC
);

//*** CommandAuditCapGetOneCC()
// This function returns true if a command has its audit bit set.
BOOL CommandAuditCapGetOneCC(TPM_CC commandCode  // IN: command code
);

//*** CommandAuditGetDigest
// This command is used to create a digest of the commands being audited. The
// commands are processed in ascending numeric order with a list of TPM_CC being
// added to a hash. This operates as if all the audited command codes were
// concatenated and then hashed.
void CommandAuditGetDigest(TPM2B_DIGEST* digest  // OUT: command digest
);

#endif  // _COMMAND_AUDIT_FP_H_
