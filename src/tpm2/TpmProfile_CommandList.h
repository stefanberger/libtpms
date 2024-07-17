/********************************************************************************/
/*										*/
/*						*/
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
/*  (c) Copyright IBM Corp. and others, 2023				  	*/
/*										*/
/********************************************************************************/

// this file defines the desired command list that should be built into the
// Tpm Core Lib.

#ifndef _TPM_PROFILE_COMMAND_LIST_H_
#define _TPM_PROFILE_COMMAND_LIST_H_

#if(YES != 1 || NO != 0)
#  error YES and NO must be correctly set before including TpmProfile_CommandList.h
#endif
#if defined(CC_YES) || defined(CC_NO)
#  error CC_YES and CC_NO should be defined by the command line file, not before
#endif

#define CC_YES YES
#define CC_NO  NO

//
// Defines for Implemented Commands
//

// Commands that are defined in the spec, but not implemented for various
// reasons:

// The TPM reference implementation does not implement attached-component
// features, and the Compliance test suite has no test cases.
#define CC_AC_GetCapability CC_NO
#define CC_AC_Send          CC_NO

// The TPM reference implementation does not implement firmware upgrade.
#define CC_FieldUpgradeData  CC_NO
#define CC_FieldUpgradeStart CC_NO
#define CC_FirmwareRead      CC_NO

// A prototype of CertifyX509 is provided here for informative purposes only.
// While all of the TPM reference implementation is provided "AS IS" without any
// warranty, the current design and implementation of CertifyX509 are considered
// to be especially unsuitable for product use.
#define CC_CertifyX509 CC_YES

// Normal commands:

#define CC_ACT_SetTimeout             CC_NO		/* libtpms: NO */
#define CC_ActivateCredential         CC_YES
#define CC_Certify                    CC_YES
#define CC_CertifyCreation            CC_YES
#define CC_ChangeEPS                  CC_YES
#define CC_ChangePPS                  CC_YES
#define CC_Clear                      CC_YES
#define CC_ClearControl               CC_YES
#define CC_ClockRateAdjust            CC_YES
#define CC_ClockSet                   CC_YES
#define CC_Commit                     (CC_YES && ALG_ECC)
#define CC_ContextLoad                CC_YES
#define CC_ContextSave                CC_YES
#define CC_Create                     CC_YES
#define CC_CreateLoaded               CC_YES
#define CC_CreatePrimary              CC_YES
#define CC_DictionaryAttackLockReset  CC_YES
#define CC_DictionaryAttackParameters CC_YES
#define CC_Duplicate                  CC_YES
#define CC_ECC_Decrypt                (CC_YES)		/* libtpms: YES since v0.10 */
#define CC_ECC_Encrypt                (CC_YES)		/* libtpms: YES since v0.10 */
#define CC_ECC_Parameters             (CC_YES && ALG_ECC)
#define CC_ECDH_KeyGen                (CC_YES && ALG_ECC)
#define CC_ECDH_ZGen                  (CC_YES && ALG_ECC)
#define CC_EC_Ephemeral               (CC_YES && ALG_ECC)
#define CC_EncryptDecrypt             CC_YES
#define CC_EncryptDecrypt2            CC_YES
#define CC_EventSequenceComplete      CC_YES
#define CC_EvictControl               CC_YES
#define CC_FlushContext               CC_YES
#define CC_GetCapability              CC_YES
#define CC_GetCommandAuditDigest      CC_YES
#define CC_GetRandom                  CC_YES
#define CC_GetSessionAuditDigest      CC_YES
#define CC_GetTestResult              CC_YES
#define CC_GetTime                    CC_YES
#define CC_HMAC                       (CC_YES && !ALG_CMAC)
#define CC_HMAC_Start                 (CC_YES && !ALG_CMAC)
#define CC_Hash                       CC_YES
#define CC_HashSequenceStart          CC_YES
#define CC_HierarchyChangeAuth        CC_YES
#define CC_HierarchyControl           CC_YES
#define CC_Import                     CC_YES
#define CC_IncrementalSelfTest        CC_YES
#define CC_Load                       CC_YES
#define CC_LoadExternal               CC_YES
#define CC_MAC                        (CC_YES && ALG_CMAC)
#define CC_MAC_Start                  (CC_YES && ALG_CMAC)
#define CC_MakeCredential             CC_YES
#define CC_NV_Certify                 CC_YES
#define CC_NV_ChangeAuth              CC_YES
#define CC_NV_DefineSpace             CC_YES
#define CC_NV_Extend                  CC_YES
#define CC_NV_GlobalWriteLock         CC_YES
#define CC_NV_Increment               CC_YES
#define CC_NV_Read                    CC_YES
#define CC_NV_ReadLock                CC_YES
#define CC_NV_ReadPublic              CC_YES
#define CC_NV_SetBits                 CC_YES
#define CC_NV_UndefineSpace           CC_YES
#define CC_NV_UndefineSpaceSpecial    CC_YES
#define CC_NV_Write                   CC_YES
#define CC_NV_WriteLock               CC_YES
#define CC_ObjectChangeAuth           CC_YES
#define CC_PCR_Allocate               CC_YES
#define CC_PCR_Event                  CC_YES
#define CC_PCR_Extend                 CC_YES
#define CC_PCR_Read                   CC_YES
#define CC_PCR_Reset                  CC_YES
#define CC_PCR_SetAuthPolicy          CC_YES
#define CC_PCR_SetAuthValue           CC_YES
#define CC_PP_Commands                CC_YES
#define CC_PolicyAuthValue            CC_YES
#define CC_PolicyAuthorize            CC_YES
#define CC_PolicyAuthorizeNV          CC_YES
#define CC_PolicyCapability           CC_YES	/* libtpms: YES; since v0.10, StateFormatLevel 5 */
#define CC_PolicyCommandCode          CC_YES
#define CC_PolicyCounterTimer         CC_YES
#define CC_PolicyCpHash               CC_YES
#define CC_PolicyDuplicationSelect    CC_YES
#define CC_PolicyGetDigest            CC_YES
#define CC_PolicyLocality             CC_YES
#define CC_PolicyNV                   CC_YES
#define CC_PolicyNameHash             CC_YES
#define CC_PolicyNvWritten            CC_YES
#define CC_PolicyOR                   CC_YES
#define CC_PolicyPCR                  CC_YES
#define CC_PolicyPassword             CC_YES
#define CC_PolicyParameters           CC_YES 	/* libtpms: YES; since v0.10, StateFormatLevel 5 */
#define CC_PolicyPhysicalPresence     CC_YES
#define CC_PolicyRestart              CC_YES
#define CC_PolicySecret               CC_YES
#define CC_PolicySigned               CC_YES
#define CC_PolicyTemplate             CC_YES
#define CC_PolicyTicket               CC_YES
#define CC_Policy_AC_SendSelect       CC_NO	/* kgold *//* libtpms: NO */
#define CC_Quote                      CC_YES
#define CC_RSA_Decrypt                (CC_YES && ALG_RSA)
#define CC_RSA_Encrypt                (CC_YES && ALG_RSA)
#define CC_ReadClock                  CC_YES
#define CC_ReadPublic                 CC_YES
#define CC_Rewrap                     CC_YES
#define CC_SelfTest                   CC_YES
#define CC_SequenceComplete           CC_YES
#define CC_SequenceUpdate             CC_YES
#define CC_SetAlgorithmSet            CC_YES
#define CC_SetCommandCodeAuditStatus  CC_YES
#define CC_SetPrimaryPolicy           CC_YES
#define CC_Shutdown                   CC_YES
#define CC_Sign                       CC_YES
#define CC_StartAuthSession           CC_YES
#define CC_Startup                    CC_YES
#define CC_StirRandom                 CC_YES
#define CC_TestParms                  CC_YES
#define CC_Unseal                     CC_YES
#define CC_Vendor_TCG_Test            CC_NO	/* libtpms: NO */
#define CC_VerifySignature            CC_YES
#define CC_ZGen_2Phase                (CC_YES && ALG_ECC)
#define CC_NV_DefineSpace2            CC_NO	/* libtpms: NO */
#define CC_NV_ReadPublic2             CC_NO	/* libtpms: NO */
#define CC_SetCapability              CC_NO	/* libtpms: NO */

/* kgold */
#if 0						// libtpms: added
#define CC_NTC2_PreConfig             CC_YES
#define CC_NTC2_LockPreConfig         CC_YES
#define CC_NTC2_GetConfig             CC_YES
#endif						// libtpms: added

#endif  // _TPM_PROFILE_COMMAND_LIST_H_
