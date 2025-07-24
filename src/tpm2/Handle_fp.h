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
/*  (c) Copyright IBM Corp. and others, 2016 -2023				*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _HANDLE_FP_H_
#define _HANDLE_FP_H_

//*** HandleGetType()
// This function returns the type of a handle which is the MSO of the handle.
TPM_HT
HandleGetType(TPM_HANDLE handle  // IN: a handle to be checked
);

//*** NextPermanentHandle()
// This function returns the permanent handle that is equal to the input value or
// is the next higher value. If there is no handle with the input value and there
// is no next higher value, it returns 0:
TPM_HANDLE
NextPermanentHandle(TPM_HANDLE inHandle  // IN: the handle to check
);

//*** PermanentCapGetHandles()
// This function returns a list of the permanent handles of PCR, started from
// 'handle'. If 'handle' is larger than the largest permanent handle, an empty list
// will be returned with 'more' set to NO.
//  Return Type: TPMI_YES_NO
//      YES         if there are more handles available
//      NO          all the available handles has been returned
TPMI_YES_NO
PermanentCapGetHandles(TPM_HANDLE   handle,     // IN: start handle
                       UINT32       count,      // IN: count of returned handles
                       TPML_HANDLE* handleList  // OUT: list of handle
);

//*** PermanentCapGetOneHandle()
// This function returns whether a permanent handle exists.
BOOL PermanentCapGetOneHandle(TPM_HANDLE handle  // IN: handle
);

//*** PermanentHandleGetPolicy()
// This function returns a list of the permanent handles of PCR, started from
// 'handle'. If 'handle' is larger than the largest permanent handle, an empty list
// will be returned with 'more' set to NO.
//  Return Type: TPMI_YES_NO
//      YES         if there are more handles available
//      NO          all the available handles has been returned
TPMI_YES_NO
PermanentHandleGetPolicy(TPM_HANDLE handle,  // IN: start handle
                         UINT32     count,   // IN: max count of returned handles
                         TPML_TAGGED_POLICY* policyList  // OUT: list of handle
);

//*** PermanentHandleGetOnePolicy()
// This function returns a permanent handle's policy, if present.
BOOL PermanentHandleGetOnePolicy(TPM_HANDLE          handle,  // IN: handle
                                 TPMS_TAGGED_POLICY* policy   // OUT: tagged policy
);

#endif  // _HANDLE_FP_H_
