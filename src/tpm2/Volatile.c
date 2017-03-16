/********************************************************************************/
/*										*/
/*			  Marshalling and unmarshalling of state		*/
/*			     Written by Stefan Berger				*/
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
/*  (c) Copyright IBM Corp. and others, 2012-2015				*/
/*										*/
/********************************************************************************/

#include <endian.h>
#include <string.h>

#include "config.h"

#include "assert.h"
#include "NVMarshal.h"
#include "Volatile.h"

#include "tpm_library_intern.h"

TPM_RC
VolatileState_Load(BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    BYTE hash[SHA1_DIGEST_SIZE], acthash[SHA1_DIGEST_SIZE];
    UINT16 hashAlg = TPM_ALG_SHA1;

    if (rc == TPM_RC_SUCCESS) {
        CryptHashBlock(hashAlg, *size - sizeof(hash), *buffer,
                       sizeof(acthash), acthash);
        rc = VolatileState_Unmarshal(buffer, size);
        if (rc != TPM_RC_SUCCESS)
            TPMLIB_LogTPM2Error("Error unmarshalling volatile state: 0x%02x",
                                rc);
    }

    if (rc == TPM_RC_SUCCESS) {
        /*
         * advance pointer towards hash if we have a later version of
         * the state that has extra data we didn't read
         */
        if (*size > 0 && (UINT32)*size > sizeof(hash)) {
            *buffer += *size - sizeof(hash);
            *size = sizeof(hash);
        }
        rc = Array_Unmarshal(hash, sizeof(hash), buffer, size);
        if (rc != TPM_RC_SUCCESS)
            TPMLIB_LogTPM2Error("Error unmarshalling volatile state hash: "
                                "0x%02x", rc);
    }

    if (rc == TPM_RC_SUCCESS) {
        if (memcmp(acthash, hash, sizeof(hash))) {
            rc = TPM_RC_HASH;
            TPMLIB_LogTPM2Error("Volatile state checksum error: 0x%02x\n",
                                rc);
        }
    }

    if (rc != TPM_RC_SUCCESS)
        g_inFailureMode = TRUE;

    return rc;
}

UINT16
VolatileState_Save(BYTE **buffer, INT32 *size)
{
    UINT16 written;
    const BYTE *start;
    BYTE hash[SHA1_DIGEST_SIZE];
    TPM_ALG_ID hashAlg = TPM_ALG_SHA1;

    start = *buffer;
    written = VolatileState_Marshal(buffer, size);

    /* append the checksum */
    CryptHashBlock(hashAlg, written, start, sizeof(hash), hash);
    written += Array_Marshal(hash, sizeof(hash), buffer, size);

    return written;
}
