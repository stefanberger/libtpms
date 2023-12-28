/********************************************************************************/
/*										*/
/*			     	Vendor String					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: VendorString.h 1519 2019-11-15 20:43:51Z kgoldman $		*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2019				*/
/*										*/
/********************************************************************************/

#ifndef VENDORSTRING_H
#define VENDORSTRING_H

#include "tpm_library_intern.h"

/*      To customize the MANUFACTURER macro, use the configure option "--with-manufacturer=XXXX"
        Define up to a 4-byte string for MANUFACTURER.  This string defines the response for
        TPM_PT_MANUFACTURER in TPM2_GetCapability().
        Must be in the TPM Vendor ID Registry: https://trustedcomputinggroup.org/resource/vendor-id-registry/ */
#ifndef CONFIG_MANUFACTURER
#define MANUFACTURER    "IBM"
#else
#define MANUFACTURER STRINGIFY(CONFIG_MANUFACTURER)
#endif
_Static_assert(sizeof(MANUFACTURER) - 1U <= 4U, "MANUFACTURER string can be up to 4-bytes");

/*      To customize the MANUFACTURER_ID macro, use the configure option "--with-manufacturer-id=XXXX"
        Define up to a 4-byte hex value for MANUFACTURER_ID.  This value defines the response for
        manufacturer in TPMAttributes for TPM2_GetInfo().
        Must be in the TPM Vendor ID Registry: https://trustedcomputinggroup.org/resource/vendor-id-registry/ */
#ifndef MANUFACTURER_ID
#define MANUFACTURER_ID    0x1014
#endif
_Static_assert((sizeof(MANUFACTURER_ID) <= 4U), "MANUFACTURER_ID can be up to 4-bytes");

/*      To customize the VENDOR_STRING_[1-4] macros, use the configure options "--with-vendor-string-[1-4]=XXXX"
        Define up to 4, 4-byte, vendor-specific strings. The strings must each be 4 bytes long.
        These values define the response for TPM_PT_VENDOR_STRING_(1-4) in TPM2_GetCapability(). */
#ifndef CONFIG_VENDOR_STRING_1
#define VENDOR_STRING_1     "SW  "
#define VENDOR_STRING_2     " TPM"
#else
#define VENDOR_STRING_1 STRINGIFY(CONFIG_VENDOR_STRING_1)
#endif
_Static_assert(sizeof(VENDOR_STRING_1) - 1U == 4U, "VENDOR_STRING_1 must be 4-bytes");

#ifdef CONFIG_VENDOR_STRING_2
#define VENDOR_STRING_2 STRINGIFY(CONFIG_VENDOR_STRING_2)
#endif
_Static_assert(sizeof(VENDOR_STRING_2) - 1U == 4U, "VENDOR_STRING_2 must be 4-bytes");

#ifdef CONFIG_VENDOR_STRING_3
#define VENDOR_STRING_3 STRINGIFY(CONFIG_VENDOR_STRING_3)
_Static_assert(sizeof(VENDOR_STRING_3) - 1U == 4U, "VENDOR_STRING_3 must be 4-bytes");
#endif
#ifdef CONFIG_VENDOR_STRING_4
#define VENDOR_STRING_4 STRINGIFY(CONFIG_VENDOR_STRING_4)
_Static_assert(sizeof(VENDOR_STRING_4) - 1U == 4U, "VENDOR_STRING_4 must be 4-bytes");
#endif

/*      To customize the FIRMWARE_V[1-2] macros, use the configure options "--with-firmware-v[1-2]=XXXX"
        Define the more significant 32-bits of a vendor-specific value indicating the
        version of the firmware in FIRMWARE_V1. The less significant 32-bits of a vendor-specific
        value indicating the version of the firmware can use the FIRMWARE_V2 macro. */
#ifndef FIRMWARE_V1
#define FIRMWARE_V1     (0x20191023)
#endif
_Static_assert(sizeof(FIRMWARE_V1) == 4U, "FIRMWARE_V1 must be 4-bytes");

#ifndef FIRMWARE_V2
#define FIRMWARE_V2     (0x00163636)
#endif
_Static_assert(sizeof(FIRMWARE_V2) == 4U, "FIRMWARE_V2 must be 4-bytes");

#endif
