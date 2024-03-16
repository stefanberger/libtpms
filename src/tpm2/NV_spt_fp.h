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

#ifndef NV_SPT_FP_H
#define NV_SPT_FP_H

TPM_RC
NvReadAccessChecks(
		   TPM_HANDLE       authHandle,    // IN: the handle that provided the
		   //     authorization
		   TPM_HANDLE       nvHandle,      // IN: the handle of the NV index to be read
		   TPMA_NV          attributes     // IN: the attributes of 'nvHandle'
		   );
TPM_RC
NvWriteAccessChecks(
		    TPM_HANDLE       authHandle,    // IN: the handle that provided the
		    //     authorization
		    TPM_HANDLE       nvHandle,      // IN: the handle of the NV index to be written
		    TPMA_NV          attributes     // IN: the attributes of 'nvHandle'
		    );
TPM_RC
NvClearOrderly(
	       void
	       );
BOOL
NvIsPinPassIndex(
		 TPM_HANDLE          index       // IN: Handle to check
		 );
TPM2B_NAME* NvGetIndexName(
			   NV_INDEX* nvIndex,  // IN: the index over which the name is to be
			   //     computed
			   TPM2B_NAME* name    // OUT: name of the index
			   );
TPM_RC NvPublic2FromNvPublic(
			     TPMS_NV_PUBLIC*   nvPublic,  // IN: the source S-form NV public area
			     TPMT_NV_PUBLIC_2* nvPublic2  // OUT: the T-form NV public area to populate
			     );
TPM_RC NvPublicFromNvPublic2(
			     TPMT_NV_PUBLIC_2* nvPublic2,  // IN: the source T-form NV public area
			     TPMS_NV_PUBLIC*   nvPublic    // OUT: the S-form NV public area to populate
			     );
TPM_RC NvDefineSpace(TPMI_RH_PROVISION authHandle,
		     TPM2B_AUTH*       auth,
		     TPMS_NV_PUBLIC*   publicInfo,
		     TPM_RC            blameAuthHandle,
		     TPM_RC            blameAuth,
		     TPM_RC            blamePublic);
#endif
