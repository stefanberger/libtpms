/********************************************************************************/
/*										*/
/*			Managing and accessing the hierarchy-related values   	*/
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

//** Introduction
// This file contains the functions used for managing and accessing the
// hierarchy-related values.

//** Includes

#include "Tpm.h"

//**HIERARCHY_MODIFIER_TYPE
// This enumerates the possible hierarchy modifiers.
typedef enum
    {
	HM_NONE = 0,
	HM_FW_LIMITED,  // Hierarchy is firmware-limited.
	HM_SVN_LIMITED  // Hierarchy is SVN-limited.
    } HIERARCHY_MODIFIER_TYPE;

//*** HIERARCHY_MODIFIER Structure
// A HIERARCHY_MODIFIER structure holds metadata about an OBJECT's
// hierarchy modifier.
typedef struct HIERARCHY_MODIFIER
{
    HIERARCHY_MODIFIER_TYPE type;  // The type of modification.
    uint16_t min_svn;  // The minimum SVN to which the hierarchy is limited.
    // Only valid if 'type' is HM_SVN_LIMITED.
} HIERARCHY_MODIFIER;

//** Functions

//*** HierarchyPreInstall()
// This function performs the initialization functions for the hierarchy
// when the TPM is simulated. This function should not be called if the
// TPM is not in a manufacturing mode at the manufacturer, or in a simulated
// environment.
void HierarchyPreInstall_Init(void)
{
    // Allow lockout clear command
    gp.disableClear = FALSE;

    // Initialize Primary Seeds
    gp.EPSeed.t.size = sizeof(gp.EPSeed.t.buffer);
    gp.SPSeed.t.size = sizeof(gp.SPSeed.t.buffer);
    gp.PPSeed.t.size = sizeof(gp.PPSeed.t.buffer);
#if(defined USE_PLATFORM_EPS) && (USE_PLATFORM_EPS != NO)
    _plat__GetEPS(gp.EPSeed.t.size, gp.EPSeed.t.buffer);
#else
    CryptRandomGenerate(gp.EPSeed.t.size, gp.EPSeed.t.buffer);
#endif
    CryptRandomGenerate(gp.SPSeed.t.size, gp.SPSeed.t.buffer);
    CryptRandomGenerate(gp.PPSeed.t.size, gp.PPSeed.t.buffer);

    gp.EPSeedCompatLevel = RuntimeProfileGetSeedCompatLevel();   // libtpms added begin
    gp.SPSeedCompatLevel = RuntimeProfileGetSeedCompatLevel();
    gp.PPSeedCompatLevel = RuntimeProfileGetSeedCompatLevel();   // libtpms added end
    // Initialize owner, endorsement and lockout authorization
    gp.ownerAuth.t.size       = 0;
    gp.endorsementAuth.t.size = 0;
    gp.lockoutAuth.t.size     = 0;

    // Initialize owner, endorsement, and lockout policy
    gp.ownerAlg                 = TPM_ALG_NULL;
    gp.ownerPolicy.t.size       = 0;
    gp.endorsementAlg           = TPM_ALG_NULL;
    gp.endorsementPolicy.t.size = 0;
    gp.lockoutAlg               = TPM_ALG_NULL;
    gp.lockoutPolicy.t.size     = 0;

    // Initialize ehProof, shProof and phProof
    gp.phProof.t.size = sizeof(gp.phProof.t.buffer);
    gp.shProof.t.size = sizeof(gp.shProof.t.buffer);
    gp.ehProof.t.size = sizeof(gp.ehProof.t.buffer);
    CryptRandomGenerate(gp.phProof.t.size, gp.phProof.t.buffer);
    CryptRandomGenerate(gp.shProof.t.size, gp.shProof.t.buffer);
    CryptRandomGenerate(gp.ehProof.t.size, gp.ehProof.t.buffer);

    // Write hierarchy data to NV
    NV_SYNC_PERSISTENT(disableClear);
    NV_SYNC_PERSISTENT(EPSeed);
    NV_SYNC_PERSISTENT(SPSeed);
    NV_SYNC_PERSISTENT(PPSeed);
    NV_SYNC_PERSISTENT(EPSeedCompatLevel);  // libtpms added begin
    NV_SYNC_PERSISTENT(SPSeedCompatLevel);
    NV_SYNC_PERSISTENT(PPSeedCompatLevel);  // libtpms added end
    NV_SYNC_PERSISTENT(ownerAuth);
    NV_SYNC_PERSISTENT(endorsementAuth);
    NV_SYNC_PERSISTENT(lockoutAuth);
    NV_SYNC_PERSISTENT(ownerAlg);
    NV_SYNC_PERSISTENT(ownerPolicy);
    NV_SYNC_PERSISTENT(endorsementAlg);
    NV_SYNC_PERSISTENT(endorsementPolicy);
    NV_SYNC_PERSISTENT(lockoutAlg);
    NV_SYNC_PERSISTENT(lockoutPolicy);
    NV_SYNC_PERSISTENT(phProof);
    NV_SYNC_PERSISTENT(shProof);
    NV_SYNC_PERSISTENT(ehProof);

    return;
}

//*** HierarchyStartup()
// This function is called at TPM2_Startup() to initialize the hierarchy
// related values.
BOOL HierarchyStartup(STARTUP_TYPE type  // IN: start up type
		      )
{
    // phEnable is SET on any startup
    g_phEnable = TRUE;

    // Reset platformAuth, platformPolicy; enable SH and EH at TPM_RESET and
    // TPM_RESTART
    if(type != SU_RESUME)
	{
	    gc.platformAuth.t.size   = 0;
	    gc.platformPolicy.t.size = 0;
	    gc.platformAlg           = TPM_ALG_NULL;

	    // enable the storage and endorsement hierarchies and the platformNV
	    gc.shEnable = gc.ehEnable = gc.phEnableNV = TRUE;
	}

    // nullProof and nullSeed are updated at every TPM_RESET
    if((type != SU_RESTART) && (type != SU_RESUME))
	{
	    gr.nullProof.t.size = sizeof(gr.nullProof.t.buffer);
	    CryptRandomGenerate(gr.nullProof.t.size, gr.nullProof.t.buffer);
	    gr.nullSeed.t.size = sizeof(gr.nullSeed.t.buffer);
	    CryptRandomGenerate(gr.nullSeed.t.size, gr.nullSeed.t.buffer);
	    gr.nullSeedCompatLevel = RuntimeProfileGetSeedCompatLevel();  // libtpms added
	}

    return TRUE;
}

//*** DecomposeHandle()
// This function extracts the base hierarchy and modifier from a given handle.
// Returns the base hierarchy.
static TPMI_RH_HIERARCHY DecomposeHandle(TPMI_RH_HIERARCHY   handle,   // IN
					 HIERARCHY_MODIFIER* modifier  // OUT
					 )
{
    modifier->type                   = HM_NONE;

    // Handle is neither FW- nor SVN-bound; return it unmodified.
    return handle;
}

//***MixAdditionalSecret()
// This function obtains the additional secret for the hierarchy and
// mixes it into the base secret. The output buffer must have the same
// capacity as the base secret. The output buffer's size is set to the
// base secret size. If no additional secret is needed, the base secret
// is copied to the output buffer.
//
//  Return Type: TPM_RC
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM failed
//                              to derive the Firmware SVN Secret for the requested
//                              SVN.
static
TPM_RC MixAdditionalSecret(const TPM2B*              base_secret,        // IN
			   TPM2B*                    output_secret       // OUT
			   )
{
    output_secret->size = base_secret->size;

    if(1)
	{
	    memcpy(output_secret->buffer, base_secret->buffer, base_secret->size);
	}
    return TPM_RC_SUCCESS;
}

//*** HierarchyGetProof()
// This function derives the proof value associated with a hierarchy. It returns a
// buffer containing the proof value.
TPM_RC HierarchyGetProof(TPMI_RH_HIERARCHY hierarchy,  // IN: hierarchy constant
			 TPM2B_PROOF*      proof       // OUT: proof buffer
			 )
{
    TPM2B_PROOF*       base_proof = NULL;
    HIERARCHY_MODIFIER modifier;

    switch(DecomposeHandle(hierarchy, &modifier))
	{
	  case TPM_RH_PLATFORM:
	    // phProof for TPM_RH_PLATFORM
	    base_proof = &gp.phProof;
	    break;
	  case TPM_RH_ENDORSEMENT:
	    // ehProof for TPM_RH_ENDORSEMENT
	    base_proof = &gp.ehProof;
	    break;
	  case TPM_RH_OWNER:
	    // shProof for TPM_RH_OWNER
	    base_proof = &gp.shProof;
	    break;
	  default:
	    // nullProof for TPM_RH_NULL or anything else
	    base_proof = &gr.nullProof;
	    break;
	}

    return MixAdditionalSecret(&base_proof->b, &proof->b);
}

//*** HierarchyGetPrimarySeed()
// This function derives the primary seed of a hierarchy.
TPM_RC HierarchyGetPrimarySeed(TPMI_RH_HIERARCHY hierarchy,  // IN: hierarchy
			       TPM2B_SEED*       seed        // OUT: seed buffer
			       )
{
    TPM2B_SEED*        base_seed = NULL;
    HIERARCHY_MODIFIER modifier;

    switch(DecomposeHandle(hierarchy, &modifier))
	{
	  case TPM_RH_PLATFORM:
	    base_seed = &gp.PPSeed;
	    break;
	  case TPM_RH_OWNER:
	    base_seed = &gp.SPSeed;
	    break;
	  case TPM_RH_ENDORSEMENT:
	    base_seed = &gp.EPSeed;
	    break;
	  default:
	    base_seed = &gr.nullSeed;
	    break;
	}

    return MixAdditionalSecret(&base_seed->b, &seed->b);
}

// libtpms added begin
SEED_COMPAT_LEVEL
HierarchyGetPrimarySeedCompatLevel(
				   TPMI_RH_HIERARCHY    hierarchy     // IN: hierarchy
			           )
{
    HIERARCHY_MODIFIER modifier;

    switch(DecomposeHandle(hierarchy, &modifier))
	{
	  case TPM_RH_PLATFORM:
	    return gp.PPSeedCompatLevel;
	    break;
	  case TPM_RH_OWNER:
	    return gp.SPSeedCompatLevel;
	    break;
	  case TPM_RH_ENDORSEMENT:
	    return gp.EPSeedCompatLevel;
	    break;
	  case TPM_RH_NULL:
	    return gr.nullSeedCompatLevel;
	  default:
	    return RuntimeProfileGetSeedCompatLevel();
	    break;
	}
}
// libtpms added end

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
			 )
{
    BOOL               enabled;
    HIERARCHY_MODIFIER modifier;

    hierarchy = DecomposeHandle(hierarchy, &modifier);

    switch(hierarchy)
	{
	  case TPM_RH_PLATFORM:
	    enabled = g_phEnable;
	    break;
	  case TPM_RH_OWNER:
	    enabled = gc.shEnable;
	    break;
	  case TPM_RH_ENDORSEMENT:
	    enabled = gc.ehEnable;
	    break;
	  case TPM_RH_NULL:
	    enabled = TRUE;
	    break;
	  default:
	    return TPM_RC_VALUE;
	}

    return enabled ? TPM_RC_SUCCESS : TPM_RC_HIERARCHY;
}

//*** HierarchyIsEnabled()
// This function checks to see if a hierarchy is enabled.
// NOTE: The TPM_RH_NULL hierarchy is always enabled.
//  Return Type: BOOL
//      TRUE(1)         hierarchy is enabled
//      FALSE(0)        hierarchy is disabled
BOOL HierarchyIsEnabled(TPMI_RH_HIERARCHY hierarchy  // IN: hierarchy
			)
{
    return ValidateHierarchy(hierarchy) == TPM_RC_SUCCESS;
}

//*** HierarchyNormalizeHandle
// This function accepts a handle that may or may not be FW- or SVN-bound,
// and returns the base hierarchy to which the handle refers.
TPMI_RH_HIERARCHY HierarchyNormalizeHandle(TPMI_RH_HIERARCHY handle  // IN: handle
					   )
{
    HIERARCHY_MODIFIER unused_modifier;

    return DecomposeHandle(handle, &unused_modifier);
}

