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

#ifndef _HIERARCHY_FP_H_
#define _HIERARCHY_FP_H_

//*** HierarchyPreInstall()
// This function performs the initialization functions for the hierarchy
// when the TPM is simulated. This function should not be called if the
// TPM is not in a manufacturing mode at the manufacturer, or in a simulated
// environment.
void HierarchyPreInstall_Init(void);

//*** HierarchyStartup()
// This function is called at TPM2_Startup() to initialize the hierarchy
// related values.
BOOL HierarchyStartup(STARTUP_TYPE type  // IN: start up type
		      );

//*** HierarchyGetProof()
// This function derives the proof value associated with a hierarchy. It returns a
// buffer containing the proof value.
//
//  Return Type: TPM_RC
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM failed
//                              to derive the Firmware SVN Secret for the requested
//                              SVN.
TPM_RC HierarchyGetProof(TPMI_RH_HIERARCHY hierarchy,  // IN: hierarchy constant
			 TPM2B_PROOF*      proof       // OUT: proof buffer
			 );

//*** HierarchyGetPrimarySeed()
// This function derives the primary seed of a hierarchy.
//
//  Return Type: TPM_RC
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM failed
//                              to derive the Firmware SVN Secret for the requested
//                              SVN.
TPM_RC HierarchyGetPrimarySeed(TPMI_RH_HIERARCHY hierarchy,  // IN: hierarchy
			       TPM2B_SEED*       seed        // OUT: seed buffer
			       );

//*** ValidateHierarchy()
// This function ensures a given hierarchy is valid and enabled.
//  Return Type: TPM_RC
//      TPM_RC_HIERARCHY        Hierarchy is disabled
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the given SVN
//                              is greater than the TPM's current SVN.
//      TPM_RC_VALUE            Hierarchy is not valid
TPM_RC ValidateHierarchy(TPMI_RH_HIERARCHY hierarchy  // IN: hierarchy
			 );

// libtpms added begin
SEED_COMPAT_LEVEL
HierarchyGetPrimarySeedCompatLevel(
                                   TPMI_RH_HIERARCHY    hierarchy     // IN: hierarchy
                                   );
// libtpms added end

//*** HierarchyIsEnabled()
// This function checks to see if a hierarchy is enabled.
// NOTE: The TPM_RH_NULL hierarchy is always enabled.
//  Return Type: BOOL
//      TRUE(1)         hierarchy is enabled
//      FALSE(0)        hierarchy is disabled
BOOL HierarchyIsEnabled(TPMI_RH_HIERARCHY hierarchy  // IN: hierarchy
			);

//*** HierarchyNormalizeHandle
// This function accepts a handle that may or may not be FW- or SVN-bound,
// and returns the base hierarchy to which the handle refers.
TPMI_RH_HIERARCHY HierarchyNormalizeHandle(TPMI_RH_HIERARCHY handle  // IN
					   );

//*** HierarchyIsFirmwareLimited
// This function accepts a hierarchy handle and returns whether it is firmware-
// limited.
BOOL HierarchyIsFirmwareLimited(TPMI_RH_HIERARCHY handle  // IN
				);

//*** HierarchyIsSvnLimited
// This function accepts a hierarchy handle and returns whether it is SVN-
// limited.
BOOL HierarchyIsSvnLimited(TPMI_RH_HIERARCHY handle  // IN
			   );

#endif  // _HIERARCHY_FP_H_
