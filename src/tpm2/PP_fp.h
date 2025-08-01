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

#ifndef _PP_FP_H_
#define _PP_FP_H_

//*** PhysicalPresencePreInstall_Init()
// This function is used to initialize the array of commands that always require
// confirmation with physical presence. The array is an array of bits that
// has a correspondence with the command code.
//
// This command should only ever be executable in a manufacturing setting or in
// a simulation.
//
// When set, these cannot be cleared.
//
void PhysicalPresencePreInstall_Init(void);

//*** PhysicalPresenceCommandSet()
// This function is used to set the indicator that a command requires
// PP confirmation.
void PhysicalPresenceCommandSet(TPM_CC commandCode  // IN: command code
);

//*** PhysicalPresenceCommandClear()
// This function is used to clear the indicator that a command requires PP
// confirmation.
void PhysicalPresenceCommandClear(TPM_CC commandCode  // IN: command code
);

//*** PhysicalPresenceIsRequired()
// This function indicates if PP confirmation is required for a command.
//  Return Type: BOOL
//      TRUE(1)         physical presence is required
//      FALSE(0)        physical presence is not required
BOOL PhysicalPresenceIsRequired(COMMAND_INDEX commandIndex  // IN: command index
);

//*** PhysicalPresenceCapGetCCList()
// This function returns a list of commands that require PP confirmation. The
// list starts from the first implemented command that has a command code that
// the same or greater than 'commandCode'.
//  Return Type: TPMI_YES_NO
//      YES         if there are more command codes available
//      NO          all the available command codes have been returned
TPMI_YES_NO
PhysicalPresenceCapGetCCList(TPM_CC   commandCode,  // IN: start command code
                             UINT32   count,        // IN: count of returned TPM_CC
                             TPML_CC* commandList   // OUT: list of TPM_CC
);

//*** PhysicalPresenceCapGetOneCC()
// This function returns true if the command requires Physical Presence.
BOOL PhysicalPresenceCapGetOneCC(TPM_CC commandCode  // IN: command code
);

#endif  // _PP_FP_H_
