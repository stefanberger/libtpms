/********************************************************************************/
/*										*/
/*		For accessing the TPM_CAP_TPM_PROPERTY values	  		*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2025				*/
/*										*/
/********************************************************************************/
//** Description
// This file contains the functions that are used for accessing the
// TPM_CAP_TPM_PROPERTY values.

//** Includes

#include "Tpm.h"

#define TPM_HAVE_TPM2_DECLARATIONS
#include "tpm_library_intern.h"  // libtpms added
//** Functions

//*** TPMPropertyIsDefined()
// This function accepts a property selection and, if so, sets 'value'
// to the value of the property.
//
// All the fixed values are vendor dependent or determined by a
// platform-specific specification. The values in the table below
// are examples and should be changed by the vendor.
//  Return Type: BOOL
//      TRUE(1)         referenced property exists and 'value' set
//      FALSE(0)        referenced property does not exist
static BOOL TPMPropertyIsDefined(TPM_PT  property,  // IN: property
                                 UINT32* value      // OUT: property value
)
{
    switch(property)
    {
        case TPM_PT_FAMILY_INDICATOR:
            // from the title page of the specification
            // For this specification, the value is "2.0".
            *value = TPM_SPEC_FAMILY;
            break;
        case TPM_PT_LEVEL:
            // from the title page of the specification
            *value = TPM_SPEC_LEVEL;
            break;
        case TPM_PT_REVISION:
            // from the title page of the specification
            *value = TPM_SPEC_VERSION;
            break;
        case TPM_PT_DAY_OF_YEAR:
            // computed from the date value on the title page of the specification
            *value = TPM_SPEC_DAY_OF_YEAR;
            break;
        case TPM_PT_YEAR:
            // from the title page of the specification
            *value = TPM_SPEC_YEAR;
            break;

        case TPM_PT_MANUFACTURER:
            // the vendor ID unique to each TPM manufacturer
            *value = _plat__GetManufacturerCapabilityCode();
            break;

        case TPM_PT_VENDOR_STRING_1:
            // the first four characters of the vendor ID string
            *value = _plat__GetVendorCapabilityCode(1);
            break;

        case TPM_PT_VENDOR_STRING_2:
            // the second four characters of the vendor ID string
            *value = _plat__GetVendorCapabilityCode(2);
            break;

        case TPM_PT_VENDOR_STRING_3:
            // the third four characters of the vendor ID string
            *value = _plat__GetVendorCapabilityCode(3);
            break;

        case TPM_PT_VENDOR_STRING_4:
            // the fourth four characters of the vendor ID string
            *value = _plat__GetVendorCapabilityCode(4);
            break;

        case TPM_PT_VENDOR_TPM_TYPE:
            // vendor-defined value indicating the TPM model
            // We just make up a number here
            *value = _plat__GetTpmType();
            break;

        case TPM_PT_FIRMWARE_VERSION_1:
            // more significant 32-bits of a vendor-specific value
            *value = gp.firmwareV1;
            break;
        case TPM_PT_FIRMWARE_VERSION_2:
            // less significant 32-bits of a vendor-specific value
            *value = gp.firmwareV2;
            break;
        case TPM_PT_INPUT_BUFFER:
            // maximum size of TPM2B_MAX_BUFFER
            *value = MAX_DIGEST_BUFFER;
            break;
        case TPM_PT_HR_TRANSIENT_MIN:
            // minimum number of transient objects that can be held in TPM
            // RAM
            *value = MAX_LOADED_OBJECTS;
            break;
        case TPM_PT_HR_PERSISTENT_MIN:
            // minimum number of persistent objects that can be held in
            // TPM NV memory
            // In this implementation, there is no minimum number of
            // persistent objects.
            *value = MIN_EVICT_OBJECTS;
            break;
        case TPM_PT_HR_LOADED_MIN:
            // minimum number of authorization sessions that can be held in
            // TPM RAM
            *value = MAX_LOADED_SESSIONS;
            break;
        case TPM_PT_ACTIVE_SESSIONS_MAX:
            // number of authorization sessions that may be active at a time
            *value = MAX_ACTIVE_SESSIONS;
            break;
        case TPM_PT_PCR_COUNT:
            // number of PCR implemented
            *value = IMPLEMENTATION_PCR;
            break;
        case TPM_PT_PCR_SELECT_MIN:
            // minimum number of bytes in a TPMS_PCR_SELECT.sizeOfSelect
            *value = PCR_SELECT_MIN;
            break;
        case TPM_PT_CONTEXT_GAP_MAX:
            // maximum allowed difference (unsigned) between the contextID
            // values of two saved session contexts
#if 0					// libtpms added
            *value = ((UINT32)1 << (sizeof(CONTEXT_SLOT) * 8)) - 1;
#endif					// libtpms added
            *value = s_ContextSlotMask; // libtpms added; the mask is either 0xff (old state) or 0xffff
            break;
        case TPM_PT_NV_COUNTERS_MAX:
            // maximum number of NV indexes that are allowed to have the
            // TPMA_NV_COUNTER attribute SET
            // In this implementation, there is no limitation on the number
            // of counters, except for the size of the NV Index memory.
            *value = 0;
            break;
        case TPM_PT_NV_INDEX_MAX:
            // maximum size of an NV index data area
            *value = MAX_NV_INDEX_SIZE;
            break;
        case TPM_PT_MEMORY:
            // a TPMA_MEMORY indicating the memory management method for the TPM
            {
                union
                {
                    TPMA_MEMORY att;
                    UINT32      u32;
                } attributes = {TPMA_ZERO_INITIALIZER()};
                SET_ATTRIBUTE(attributes.att, TPMA_MEMORY, sharedNV);
                SET_ATTRIBUTE(attributes.att, TPMA_MEMORY, objectCopiedToRam);

                // Note: For a LSb0 machine, the bits in a bit field are in the correct
                // order even if the machine is MSB0. For a MSb0 machine, a TPMA will
                // be an integer manipulated by masking (USE_BIT_FIELD_STRUCTURES will
                // be NO) so the bits are manipulate correctly.
                *value = attributes.u32;
                break;
            }
        case TPM_PT_CLOCK_UPDATE:
            // interval, in seconds, between updates to the copy of
            // TPMS_TIME_INFO .clock in NV
            *value = (1 << NV_CLOCK_UPDATE_INTERVAL);
            break;
        case TPM_PT_CONTEXT_HASH:
            // algorithm used for the integrity hash on saved contexts and
            // for digesting the fuData of TPM2_FirmwareRead()
            *value = CONTEXT_INTEGRITY_HASH_ALG;
            break;
        case TPM_PT_CONTEXT_SYM:
            // algorithm used for encryption of saved contexts
            *value = CONTEXT_ENCRYPT_ALG;
            break;
        case TPM_PT_CONTEXT_SYM_SIZE:
            // size of the key used for encryption of saved contexts
            *value = CONTEXT_ENCRYPT_KEY_BITS;
            break;
        case TPM_PT_ORDERLY_COUNT:
            // maximum difference between the volatile and non-volatile
            // versions of TPMA_NV_COUNTER that have TPMA_NV_ORDERLY SET
            *value = MAX_ORDERLY_COUNT;
            break;
        case TPM_PT_MAX_COMMAND_SIZE:
            // maximum value for 'commandSize'
            *value = MAX_COMMAND_SIZE;
            break;
        case TPM_PT_MAX_RESPONSE_SIZE:
            // maximum value for 'responseSize'
            *value = MAX_RESPONSE_SIZE;
            break;
        case TPM_PT_MAX_DIGEST:
            // maximum size of a digest that can be produced by the TPM
            *value = sizeof(TPMU_HA);
            break;
        case TPM_PT_MAX_OBJECT_CONTEXT:
// Header has 'sequence', 'handle' and 'hierarchy'
#define SIZE_OF_CONTEXT_HEADER \
    sizeof(UINT64) + sizeof(TPMI_DH_CONTEXT) + sizeof(TPMI_RH_HIERARCHY)
#define SIZE_OF_CONTEXT_INTEGRITY (sizeof(UINT16) + CONTEXT_INTEGRITY_HASH_SIZE)
#define SIZE_OF_FINGERPRINT       sizeof(UINT64)
#define SIZE_OF_CONTEXT_BLOB_OVERHEAD \
    (sizeof(UINT16) + SIZE_OF_CONTEXT_INTEGRITY + SIZE_OF_FINGERPRINT)
#define SIZE_OF_CONTEXT_OVERHEAD \
    (SIZE_OF_CONTEXT_HEADER + SIZE_OF_CONTEXT_BLOB_OVERHEAD)
#if 0
            // maximum size of a TPMS_CONTEXT that will be returned by
            // TPM2_ContextSave for object context
            *value = 0;
            // adding sequence, saved handle and hierarchy
            *value += sizeof(UINT64) + sizeof(TPMI_DH_CONTEXT) +
                sizeof(TPMI_RH_HIERARCHY);
            // add size field in TPM2B_CONTEXT
            *value += sizeof(UINT16);
            // add integrity hash size
            *value += sizeof(UINT16) +
                CryptHashGetDigestSize(CONTEXT_INTEGRITY_HASH_ALG);
            // Add fingerprint size, which is the same as sequence size
            *value += sizeof(UINT64);
            // Add OBJECT structure size
            *value += sizeof(OBJECT);
#else
            // the maximum size of a TPMS_CONTEXT that will be returned by
            // TPM2_ContextSave for object context
            *value = SIZE_OF_CONTEXT_OVERHEAD + sizeof(OBJECT);
#endif
            break;
        case TPM_PT_MAX_SESSION_CONTEXT:
#if 0

            // the maximum size of a TPMS_CONTEXT that will be returned by
            // TPM2_ContextSave for object context
            *value = 0;
            // adding sequence, saved handle and hierarchy
            *value += sizeof(UINT64) + sizeof(TPMI_DH_CONTEXT) +
                sizeof(TPMI_RH_HIERARCHY);
            // Add size field in TPM2B_CONTEXT
            *value += sizeof(UINT16);
// Add integrity hash size
            *value += sizeof(UINT16) +
                CryptHashGetDigestSize(CONTEXT_INTEGRITY_HASH_ALG);
      // Add fingerprint size, which is the same as sequence size
            *value += sizeof(UINT64);
            // Add SESSION structure size
            *value += sizeof(SESSION);
#else
            // the maximum size of a TPMS_CONTEXT that will be returned by
            // TPM2_ContextSave for object context
            *value = SIZE_OF_CONTEXT_OVERHEAD + sizeof(SESSION);
#endif
            break;
        case TPM_PT_PS_FAMILY_INDICATOR:
            // platform specific values for the TPM_PT_PS parameters from
            // the relevant platform-specific specification
            // In this reference implementation, all of these values are 0.
            *value = PLATFORM_FAMILY;
            break;
        case TPM_PT_PS_LEVEL:
            // level of the platform-specific specification
            *value = PLATFORM_LEVEL;
            break;
        case TPM_PT_PS_REVISION:
            // specification Revision times 100 for the platform-specific
            // specification
            *value = PLATFORM_VERSION;
            break;
        case TPM_PT_PS_DAY_OF_YEAR:
            // platform-specific specification day of year using TCG calendar
            *value = PLATFORM_DAY_OF_YEAR;
            break;
        case TPM_PT_PS_YEAR:
            // platform-specific specification year using the CE
            *value = PLATFORM_YEAR;
            break;
        case TPM_PT_SPLIT_MAX:
            // number of split signing operations supported by the TPM
            *value = 0;
#if ALG_ECC
            *value = sizeof(gr.commitArray) * 8;
#endif
            break;
        case TPM_PT_TOTAL_COMMANDS:
            // total number of commands implemented in the TPM
            // Since the reference implementation does not have any
            // vendor-defined commands, this will be the same as the
            // number of library commands.
            {
#if COMPRESSED_LISTS
                (*value) = RuntimeCommandsCountEnabled(&g_RuntimeProfile.RuntimeCommands); // libtpms changed: was COMMAND_COUNT
#else
                COMMAND_INDEX commandIndex;
                *value = 0;

                // scan all implemented commands
                for(commandIndex = GetClosestCommandIndex(0);
                    commandIndex != UNIMPLEMENTED_COMMAND_INDEX;
                    commandIndex = GetNextCommandIndex(commandIndex))
                {
                    (*value)++;  // count of all implemented
                }
#endif
                break;
            }
        case TPM_PT_LIBRARY_COMMANDS:
            // number of commands from the TPM library that are implemented
            {
#if COMPRESSED_LISTS
                *value = RuntimeCommandsCountEnabled(&g_RuntimeProfile.RuntimeCommands); // libtpms changed: was LIBRARY_COMMAND_ARRAY_SIZE
#else
                COMMAND_INDEX commandIndex;
                *value = 0;

                // scan all implemented commands
                for(commandIndex = GetClosestCommandIndex(0);
                    commandIndex < LIBRARY_COMMAND_ARRAY_SIZE;
                    commandIndex = GetNextCommandIndex(commandIndex))
                {
                    (*value)++;
                }
#endif
                break;
            }
        case TPM_PT_VENDOR_COMMANDS:
            // number of vendor commands that are implemented
            *value = VENDOR_COMMAND_ARRAY_SIZE;
            break;
        case TPM_PT_NV_BUFFER_MAX:
            // Maximum data size in an NV write command
            *value = MAX_NV_BUFFER_SIZE;
            break;
        case TPM_PT_MODES:
        {
            union
            {
                TPMA_MODES attr;
                UINT32     u32;
            } flags = {TPMA_ZERO_INITIALIZER()};
#if FIPS_COMPLIANT
            SET_ATTRIBUTE(flags.attr, TPMA_MODES, FIPS_140_2);
#endif
            *value = flags.u32;
            break;
        }
        case TPM_PT_MAX_CAP_BUFFER:
            *value = MAX_CAP_BUFFER;
            break;
        case TPM_PT_FIRMWARE_SVN:
            *value = _plat__GetTpmFirmwareSvn();
            break;
        case TPM_PT_FIRMWARE_MAX_SVN:
            *value = _plat__GetTpmFirmwareMaxSvn();
            break;

        // Start of variable commands
        case TPM_PT_PERMANENT:
            // TPMA_PERMANENT
            {
                union
                {
                    TPMA_PERMANENT attr;
                    UINT32         u32;
                } flags = {TPMA_ZERO_INITIALIZER()};
                if(gp.ownerAuth.t.size != 0)
                    SET_ATTRIBUTE(flags.attr, TPMA_PERMANENT, ownerAuthSet);
                if(gp.endorsementAuth.t.size != 0)
                    SET_ATTRIBUTE(flags.attr, TPMA_PERMANENT, endorsementAuthSet);
                if(gp.lockoutAuth.t.size != 0)
                    SET_ATTRIBUTE(flags.attr, TPMA_PERMANENT, lockoutAuthSet);
                if(gp.disableClear)
                    SET_ATTRIBUTE(flags.attr, TPMA_PERMANENT, disableClear);
                if(gp.failedTries >= gp.maxTries)
                    SET_ATTRIBUTE(flags.attr, TPMA_PERMANENT, inLockout);
                // In this implementation, EPS is always generated by TPM
                SET_ATTRIBUTE(flags.attr, TPMA_PERMANENT, tpmGeneratedEPS);

                // Note: For a LSb0 machine, the bits in a bit field are in the correct
                // order even if the machine is MSB0. For a MSb0 machine, a TPMA will
                // be an integer manipulated by masking (USE_BIT_FIELD_STRUCTURES will
                // be NO) so the bits are manipulate correctly.
                *value = flags.u32;
                break;
            }
        case TPM_PT_STARTUP_CLEAR:
            // TPMA_STARTUP_CLEAR
            {
                union
                {
                    TPMA_STARTUP_CLEAR attr;
                    UINT32             u32;
                } flags = {TPMA_ZERO_INITIALIZER()};
                //
                if(g_phEnable)
                    SET_ATTRIBUTE(flags.attr, TPMA_STARTUP_CLEAR, phEnable);
                if(gc.shEnable)
                    SET_ATTRIBUTE(flags.attr, TPMA_STARTUP_CLEAR, shEnable);
                if(gc.ehEnable)
                    SET_ATTRIBUTE(flags.attr, TPMA_STARTUP_CLEAR, ehEnable);
                if(gc.phEnableNV)
                    SET_ATTRIBUTE(flags.attr, TPMA_STARTUP_CLEAR, phEnableNV);
                if(g_prevOrderlyState != SU_NONE_VALUE)
                    SET_ATTRIBUTE(flags.attr, TPMA_STARTUP_CLEAR, orderly);

                // Note: For a LSb0 machine, the bits in a bit field are in the correct
                // order even if the machine is MSB0. For a MSb0 machine, a TPMA will
                // be an integer manipulated by masking (USE_BIT_FIELD_STRUCTURES will
                // be NO) so the bits are manipulate correctly.
                *value = flags.u32;
                break;
            }
        case TPM_PT_HR_NV_INDEX:
            // number of NV indexes currently defined
            *value = NvCapGetIndexNumber();
            break;
        case TPM_PT_HR_LOADED:
            // number of authorization sessions currently loaded into TPM
            // RAM
            *value = SessionCapGetLoadedNumber();
            break;
        case TPM_PT_HR_LOADED_AVAIL:
            // number of additional authorization sessions, of any type,
            // that could be loaded into TPM RAM
            *value = SessionCapGetLoadedAvail();
            break;
        case TPM_PT_HR_ACTIVE:
            // number of active authorization sessions currently being
            // tracked by the TPM
            *value = SessionCapGetActiveNumber();
            break;
        case TPM_PT_HR_ACTIVE_AVAIL:
            // number of additional authorization sessions, of any type,
            // that could be created
            *value = SessionCapGetActiveAvail();
            break;
        case TPM_PT_HR_TRANSIENT_AVAIL:
            // estimate of the number of additional transient objects that
            // could be loaded into TPM RAM
            *value = ObjectCapGetTransientAvail();
            break;
        case TPM_PT_HR_PERSISTENT:
            // number of persistent objects currently loaded into TPM
            // NV memory
            *value = NvCapGetPersistentNumber();
            break;
        case TPM_PT_HR_PERSISTENT_AVAIL:
            // number of additional persistent objects that could be loaded
            // into NV memory
            *value = NvCapGetPersistentAvail();
            break;
        case TPM_PT_NV_COUNTERS:
            // number of defined NV indexes that have NV TPMA_NV_COUNTER
            // attribute SET
            *value = NvCapGetCounterNumber();
            break;
        case TPM_PT_NV_COUNTERS_AVAIL:
            // number of additional NV indexes that can be defined with their
            // TPMA_NV_COUNTER attribute SET
            *value = NvCapGetCounterAvail();
            break;
        case TPM_PT_ALGORITHM_SET:
            // region code for the TPM
            *value = gp.algorithmSet;
            break;
        case TPM_PT_LOADED_CURVES:
#if ALG_ECC
            // number of loaded ECC curves
            *value = ECC_CURVE_COUNT;
#else   // ALG_ECC
            *value = 0;
#endif  // ALG_ECC
            break;
        case TPM_PT_LOCKOUT_COUNTER:
            // current value of the lockout counter
            *value = gp.failedTries;
            break;
        case TPM_PT_MAX_AUTH_FAIL:
            // number of authorization failures before DA lockout is invoked
            *value = gp.maxTries;
            break;
        case TPM_PT_LOCKOUT_INTERVAL:
            // number of seconds before the value reported by
            // TPM_PT_LOCKOUT_COUNTER is decremented
            *value = gp.recoveryTime;
            break;
        case TPM_PT_LOCKOUT_RECOVERY:
            // number of seconds after a lockoutAuth failure before use of
            // lockoutAuth may be attempted again
            *value = gp.lockoutRecovery;
            break;
        case TPM_PT_NV_WRITE_RECOVERY:
            // number of milliseconds before the TPM will accept another command
            // that will modify NV.
            // This should make a call to the platform code that is doing rate
            // limiting of NV. Rate limiting is not implemented in the reference
            // code so no call is made.
            *value = 0;
            break;
        case TPM_PT_AUDIT_COUNTER_0:
            // high-order 32 bits of the command audit counter
            *value = (UINT32)(gp.auditCounter >> 32);
            break;
        case TPM_PT_AUDIT_COUNTER_1:
            // low-order 32 bits of the command audit counter
            *value = (UINT32)(gp.auditCounter);
            break;
        default:
            // property is not defined
            return FALSE;
            break;
    }
    return TRUE;
}

//*** TPMCapGetProperties()
// This function is used to get the TPM_PT values. The search of properties will
// start at 'property' and continue until 'propertyList' has as many values as
// will fit, or the last property has been reported, or the list has as many
// values as requested in 'count'.
//  Return Type: TPMI_YES_NO
//  YES        more properties are available
//  NO         no more properties to be reported
TPMI_YES_NO
TPMCapGetProperties(TPM_PT property,  // IN: the starting TPM property
                    UINT32 count,     // IN: maximum number of returned
                                      //     properties
                    TPML_TAGGED_TPM_PROPERTY* propertyList  // OUT: property list
)
{
    TPMI_YES_NO more = NO;
    UINT32      i;
    UINT32      nextGroup;

    // initialize output property list
    propertyList->count = 0;

    // maximum count of properties we may return is MAX_PCR_PROPERTIES
    if(count > MAX_TPM_PROPERTIES)
        count = MAX_TPM_PROPERTIES;

    // if property is less than PT_FIXED, start from PT_FIXED
    if(property < PT_FIXED)
        property = PT_FIXED;
    // There is only the fixed and variable groups with the variable group coming
    // last
    if(property >= (PT_VAR + PT_GROUP))
        return more;

    // Don't read past the end of the selected group
    nextGroup = ((property / PT_GROUP) * PT_GROUP) + PT_GROUP;

    // Scan through the TPM properties of the requested group.
    for(i = property; i < nextGroup; i++)
    {
        UINT32 value;
        // if we have hit the end of the group, quit
        if(i != property && ((i % PT_GROUP) == 0))
            break;
        if(TPMPropertyIsDefined((TPM_PT)i, &value))
        {
            if(propertyList->count < count)
            {
                // If the list is not full, add this property
                propertyList->tpmProperty[propertyList->count].property = (TPM_PT)i;
                propertyList->tpmProperty[propertyList->count].value    = value;
                propertyList->count++;
            }
            else
            {
                // If the return list is full but there are more properties
                // available, set the indication and exit the loop.
                more = YES;
                break;
            }
        }
    }
    return more;
}

//*** TPMCapGetOneProperty()
// This function returns a single TPM property, if present.
BOOL TPMCapGetOneProperty(TPM_PT                pt,       // IN: the TPM property
                          TPMS_TAGGED_PROPERTY* property  // OUT: tagged property
)
{
    UINT32 value;

    if(TPMPropertyIsDefined((TPM_PT)pt, &value))
    {
        property->property = (TPM_PT)pt;
        property->value    = value;
        return TRUE;
    }

    return FALSE;
}
