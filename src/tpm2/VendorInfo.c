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
/*  (c) Copyright IBM Corp. and others, 2023					*/
/*										*/
/********************************************************************************/

//** Introduction
// Provide vendor-specific version and identifiers to core TPM library for
// return in capabilities.  These may not be compile time constants and therefore
// are provided by platform callbacks.  These platform functions are expected to
// always be available, even in failure mode.
//
//** Includes
#include "Platform.h"

// In this sample platform, these are compile time constants, but are not required to be.
#define MANUFACTURER    "IBM"
#define VENDOR_STRING_1 "SW  "
#define VENDOR_STRING_2 " TPM"
#define VENDOR_STRING_3 "\0\0\0\0"
#define VENDOR_STRING_4 "\0\0\0\0"
#define FIRMWARE_V1     (0x20240125)
#define FIRMWARE_V2     (0x00120000)
#define MAX_SVN         255

#if SIMULATION	// libtpms added
static uint32_t currentHash = FIRMWARE_V2;
#endif
static uint16_t currentSvn  = 10;

// Similar to the Core Library's ByteArrayToUint32, but usable in Platform code.
static uint32_t StringToUint32(const char s[4])		// libtpms changed: added const
{
    uint8_t* b = (uint8_t*)s;  // Avoid promotion to a signed integer type
    return (((uint32_t)b[0] << 8 | b[1]) << 8 | b[2]) << 8 | b[3];
}

// return the 4 character Manufacturer Capability code.  This
// should come from the platform library since that is provided by the manufacturer
LIB_EXPORT uint32_t _plat__GetManufacturerCapabilityCode()
{
    return StringToUint32(MANUFACTURER);
}

// return the 4 character VendorStrings for Capabilities.
// Index is ONE-BASED, and may be in the range [1,4] inclusive.
// Any other index returns all zeros. The return value will be interpreted
// as an array of 4 ASCII characters (with no null terminator)
LIB_EXPORT uint32_t _plat__GetVendorCapabilityCode(int index)
{
    switch(index)
	{
	  case 1:
	    return StringToUint32(VENDOR_STRING_1);
	  case 2:
	    return StringToUint32(VENDOR_STRING_2);
	  case 3:
	    return StringToUint32(VENDOR_STRING_3);
	  case 4:
	    return StringToUint32(VENDOR_STRING_4);
	}
    return 0;
}

// return the most-significant 32-bits of the TPM Firmware Version reported by
// getCapability.
LIB_EXPORT uint32_t _plat__GetTpmFirmwareVersionHigh()
{
    return FIRMWARE_V1;
}

// return the least-significant 32-bits of the TPM Firmware Version reported by
// getCapability.
LIB_EXPORT uint32_t _plat__GetTpmFirmwareVersionLow()
{
    return FIRMWARE_V2;
}

// return the TPM Firmware SVN reported by getCapability.
LIB_EXPORT uint16_t _plat__GetTpmFirmwareSvn(void)
{
    return currentSvn;
}

// return the TPM Firmware maximum SVN reported by getCapability.
LIB_EXPORT uint16_t _plat__GetTpmFirmwareMaxSvn(void)
{
    return MAX_SVN;
}

// Called by the simulator to set the TPM Firmware SVN reported by
// getCapability.
#if SIMULATION		// libtpms added
LIB_EXPORT void _plat__SetTpmFirmwareHash(uint32_t hash)
{
    currentHash = hash;
}

// Called by the simulator to set the TPM Firmware SVN reported by
// getCapability.
LIB_EXPORT void _plat__SetTpmFirmwareSvn(uint16_t svn)
{
    currentSvn = MIN(svn, MAX_SVN);
}
#endif			// libtpms added

#if SVN_LIMITED_SUPPORT
// Dummy implmenentation for obtaining a Firmware SVN Secret bound
// to the given SVN.
LIB_EXPORT int _plat__GetTpmFirmwareSvnSecret(uint16_t  svn,
					      uint16_t  secret_buf_size,
					      uint8_t*  secret_buf,
					      uint16_t* secret_size)
{
    int i;

    if(svn > currentSvn)
	{
	    return -1;
	}

    // INSECURE dummy implementation: repeat the SVN into the secret buffer.
    for(i = 0; i < secret_buf_size; ++i)
	{
	    secret_buf[i] = ((uint8_t*)&svn)[i % sizeof(svn)];
	}

    *secret_size = secret_buf_size;

    return 0;
}
#endif  // SVN_LIMITED_SUPPORT

#if FW_LIMITED_SUPPORT
// Dummy implmenentation for obtaining a Firmware Secret bound
// to the current firmware image.
LIB_EXPORT int _plat__GetTpmFirmwareSecret
    (uint16_t secret_buf_size, uint8_t* secret_buf, uint16_t* secret_size)
{
    int i;

    // INSECURE dummy implementation: repeat the firmware hash into the
    // secret buffer.
    for(i = 0; i < secret_buf_size; ++i)
	{
	    secret_buf[i] = ((uint8_t*)&currentHash)[i % sizeof(currentHash)];
	}

    *secret_size = secret_buf_size;

    return 0;
}
#endif  // FW_LIMITED_SUPPORT

	// return the TPM Type returned by TPM_PT_VENDOR_TPM_TYPE
LIB_EXPORT uint32_t _plat__GetTpmType()
{
    return 1;  // just the value the reference code has returned in the past.
}

