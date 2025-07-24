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
 *  Date: Mar  7, 2020  Time: 07:17:48PM
 */

#ifndef _SESSION_PROCESS_FP_H_
#define _SESSION_PROCESS_FP_H_

//*** IsDAExempted()
// This function indicates if a handle is exempted from DA logic.
// A handle is exempted if it is:
//  a) a primary seed handle;
//  b) an object with noDA bit SET;
//  c) an NV Index with TPMA_NV_NO_DA bit SET; or
//  d) a PCR handle.
//
//  Return Type: BOOL
//      TRUE(1)         handle is exempted from DA logic
//      FALSE(0)        handle is not exempted from DA logic
BOOL IsDAExempted(TPM_HANDLE handle  // IN: entity handle
);

//*** ClearCpRpHashes()
void ClearCpRpHashes(COMMAND* command);

//*** CompareNameHash()
// This function computes the name hash and compares it to the nameHash in the
// session data, returning true if they are equal.
BOOL CompareNameHash(COMMAND* command,  // IN: main parsing structure
                     SESSION* session   // IN: session structure with nameHash
);

//*** CompareParametersHash()
// This function computes the parameters hash and compares it to the pHash in
// the session data, returning true if they are equal.
BOOL CompareParametersHash(COMMAND* command,  // IN: main parsing structure
                           SESSION* session   // IN: session structure with pHash
);

//*** ParseSessionBuffer()
// This function is the entry function for command session processing.
// It iterates sessions in session area and reports if the required authorization
// has been properly provided. It also processes audit session and passes the
// information of encryption sessions to parameter encryption module.
//
//  Return Type: TPM_RC
//        various           parsing failure or authorization failure
//
TPM_RC
ParseSessionBuffer(COMMAND* command  // IN: the structure that contains
);

//*** CheckAuthNoSession()
// Function to process a command with no session associated.
// The function makes sure all the handles in the command require no authorization.
//
//  Return Type: TPM_RC
//      TPM_RC_AUTH_MISSING         failure - one or more handles require
//                                  authorization
TPM_RC
CheckAuthNoSession(COMMAND* command  // IN: command parsing structure
);

//*** BuildResponseSession()
// Function to build Session buffer in a response. The authorization data is added
// to the end of command->responseBuffer. The size of the authorization area is
// accumulated in command->authSize.
// When this is called, command->responseBuffer is pointing at the next location
// in the response buffer to be filled. This is where the authorization sessions
// will go, if any. command->parameterSize is the number of bytes that have been
// marshaled as parameters in the output buffer.
TPM_RC
BuildResponseSession(COMMAND* command  // IN: structure that has relevant command
                                       //     information
);

//*** SessionRemoveAssociationToHandle()
// This function deals with the case where an entity associated with an authorization
// is deleted during command processing. The primary use of this is to support
// UndefineSpaceSpecial().
void SessionRemoveAssociationToHandle(TPM_HANDLE handle);

#endif  // _SESSION_PROCESS_FP_H_
