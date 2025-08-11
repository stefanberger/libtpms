// SPDX-License-Identifier: BSD-2-Clause


#ifndef _TPM_PROFILE_COMMAND_LIST_H_
#  error This file should be included only within TpmProfile_CommandList.h
#endif

#define CC_Vendor_TCG_Test CC_NO	/* libtpms: NO */

#define VENDOR_COMMAND_ARRAY_COUNT (CC_Vendor_TCG_Test)

// actually define vendor command IDs here
#if CC_Vendor_TCG_Test == YES
#  define TPM_CC_Vendor_TCG_Test (TPM_CC)(CC_VEND | 0x0000)
#else
// nothing
#endif
// and command attributes must be defined in TpmProfile_CommandList_AttributeData.inl
