/********************************************************************************/
/*										*/
/*			 ACT Command Support   					*/
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
/*  (c) Copyright IBM Corp. and others, 2019 - 2023				*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes 1.00
 *  Date: Oct 24, 2019  Time: 10:38:43AM
 */

#ifndef _ACT_SPT_FP_H_
#define _ACT_SPT_FP_H_

//*** ActStartup()
// This function is called by TPM2_Startup() to initialize the ACT counter values.
BOOL ActStartup(STARTUP_TYPE type);

//*** ActGetSignaled()
// This function returns the state of the signaled flag associated with an ACT.
BOOL ActGetSignaled(TPM_RH actHandle);

//***ActShutdown()
// This function saves the current state of the counters
BOOL ActShutdown(TPM_SU state  //IN: the type of the shutdown.
		 );

//*** ActIsImplemented()
// This function determines if an ACT is implemented in both the TPM and the platform
// code.
BOOL ActIsImplemented(UINT32 act);

//***ActCounterUpdate()
// This function updates the ACT counter. If the counter already has a pending update,
// it returns TPM_RC_RETRY so that the update can be tried again later.
TPM_RC
ActCounterUpdate(TPM_RH handle,   //IN: the handle of the act
		 UINT32 newValue  //IN: the value to set in the ACT
		 );

//*** ActGetCapabilityData()
// This function returns the list of ACT data
//  Return Type: TPMI_YES_NO
//      YES             if more ACT data is available
//      NO              if no more ACT data to
TPMI_YES_NO
ActGetCapabilityData(TPM_HANDLE     actHandle,  // IN: the handle for the starting ACT
		     UINT32         maxCount,   // IN: maximum allowed return values
		     TPML_ACT_DATA* actList     // OUT: ACT data list
		     );

//*** ActGetOneCapability()
// This function returns an ACT's capability, if present.
BOOL ActGetOneCapability(TPM_HANDLE     actHandle,  // IN: the handle for the ACT
			 TPMS_ACT_DATA* actData     // OUT: ACT data
			 );

#endif  // _ACT_SPT_FP_H_
