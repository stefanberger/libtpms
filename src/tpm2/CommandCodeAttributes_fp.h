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
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _COMMAND_CODE_ATTRIBUTES_FP_H_
#define _COMMAND_CODE_ATTRIBUTES_FP_H_

//*** GetClosestCommandIndex()
// This function returns the command index for the command with a value that is
// equal to or greater than the input value
//  Return Type: COMMAND_INDEX
//  UNIMPLEMENTED_COMMAND_INDEX     command is not implemented
//  other                           index of a command
COMMAND_INDEX
GetClosestCommandIndex(TPM_CC commandCode  // IN: the command code to start at
);

//*** CommandCodeToComandIndex()
// This function returns the index in the various attributes arrays of the
// command.
//  Return Type: COMMAND_INDEX
//  UNIMPLEMENTED_COMMAND_INDEX     command is not implemented
//  other                           index of the command
COMMAND_INDEX
CommandCodeToCommandIndex(TPM_CC commandCode  // IN: the command code to look up
);

//*** GetNextCommandIndex()
// This function returns the index of the next implemented command.
//  Return Type: COMMAND_INDEX
//  UNIMPLEMENTED_COMMAND_INDEX     no more implemented commands
//  other                           the index of the next implemented command
COMMAND_INDEX
GetNextCommandIndex(COMMAND_INDEX commandIndex  // IN: the starting index
);

//*** GetCommandCode()
// This function returns the commandCode associated with the command index
TPM_CC
GetCommandCode(COMMAND_INDEX commandIndex  // IN: the command index
);

//*** CommandAuthRole()
//
//  This function returns the authorization role required of a handle.
//
//  Return Type: AUTH_ROLE
//  AUTH_NONE       no authorization is required
//  AUTH_USER       user role authorization is required
//  AUTH_ADMIN      admin role authorization is required
//  AUTH_DUP        duplication role authorization is required
AUTH_ROLE
CommandAuthRole(COMMAND_INDEX commandIndex,  // IN: command index
                UINT32        handleIndex    // IN: handle index (zero based)
);

//*** EncryptSize()
// This function returns the size of the decrypt size field. This function returns
// 0 if encryption is not allowed
//  Return Type: int
//  0       encryption not allowed
//  2       size field is two bytes
//  4       size field is four bytes
int EncryptSize(COMMAND_INDEX commandIndex  // IN: command index
);

//*** DecryptSize()
// This function returns the size of the decrypt size field. This function returns
// 0 if decryption is not allowed
//  Return Type: int
//  0       encryption not allowed
//  2       size field is two bytes
//  4       size field is four bytes
int DecryptSize(COMMAND_INDEX commandIndex  // IN: command index
);

//*** IsSessionAllowed()
//
// This function indicates if the command is allowed to have sessions.
//
// This function must not be called if the command is not known to be implemented.
//
//  Return Type: BOOL
//      TRUE(1)         session is allowed with this command
//      FALSE(0)        session is not allowed with this command
BOOL IsSessionAllowed(COMMAND_INDEX commandIndex  // IN: the command to be checked
);

//*** IsHandleInResponse()
// This function determines if a command has a handle in the response
BOOL IsHandleInResponse(COMMAND_INDEX commandIndex);

//*** IsWriteOperation()
// Checks to see if an operation will write to an NV Index and is subject to being
// blocked by read-lock
BOOL IsWriteOperation(COMMAND_INDEX commandIndex  // IN: Command to check
);

//*** IsReadOperation()
// Checks to see if an operation will write to an NV Index and is
// subject to being blocked by write-lock.
BOOL IsReadOperation(COMMAND_INDEX commandIndex  // IN: Command to check
);

//*** CommandCapGetCCList()
// This function returns a list of implemented commands and command attributes
// starting from the command in 'commandCode'.
//  Return Type: TPMI_YES_NO
//      YES         more command attributes are available
//      NO          no more command attributes are available
TPMI_YES_NO
CommandCapGetCCList(TPM_CC commandCode,  // IN: start command code
                    UINT32 count,        // IN: maximum count for number of entries in
                                         //     'commandList'
                    TPML_CCA* commandList  // OUT: list of TPMA_CC
);

//*** CommandCapGetOneCC()
// This function checks whether a command is implemented, and returns its
// attributes if so.
BOOL CommandCapGetOneCC(TPM_CC   commandCode,       // IN: command code
                        TPMA_CC* commandAttributes  // OUT: Command attributes
);

#if 0  /* libtpms added */

//*** IsVendorCommand()
// Function indicates if a command index references a vendor command.
//  Return Type: BOOL
//      TRUE(1)         command is a vendor command
//      FALSE(0)        command is not a vendor command
BOOL IsVendorCommand(COMMAND_INDEX commandIndex  // IN: command index to check
);

#endif /* libtpms added */

#endif  // _COMMAND_CODE_ATTRIBUTES_FP_H_
