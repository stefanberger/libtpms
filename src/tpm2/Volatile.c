// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation 2017,2018.

#if defined __FreeBSD__ || defined __DragonFly__
# include <sys/endian.h>
#elif defined __APPLE__
# include <libkern/OSByteOrder.h>
#else
# include <endian.h>
#endif
#include <string.h>

#include "config.h"

#include "assert.h"
#include "Marshal.h"
#include "Volatile.h"
#include "RuntimeAlgorithm_fp.h"

#define TPM_HAVE_TPM2_DECLARATIONS
#include "tpm_library_intern.h"

TPM_RC
VolatileState_Load(BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS, irc;
    BYTE hash[SHA1_DIGEST_SIZE], acthash[SHA1_DIGEST_SIZE];
    unsigned int stateFormatLevel = 0; // ignored
    UINT16 hashAlg = TPM_ALG_SHA1;
    char *oldProfile = NULL;

    if (rc == TPM_RC_SUCCESS) {
        if ((UINT32)*size < sizeof(hash))
            return TPM_RC_INSUFFICIENT;

        rc = RuntimeAlgorithmSwitchProfile(&g_RuntimeProfile.RuntimeAlgorithm,
                                           NULL, ~0, &oldProfile);
        if (rc != TPM_RC_SUCCESS)
            return rc;
    }

    if (rc == TPM_RC_SUCCESS) {

        CryptHashBlock(hashAlg, *size - sizeof(hash), *buffer,
                       sizeof(acthash), acthash);
        rc = VolatileState_Unmarshal(buffer, size);
        /* specific error has already been reported */
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
                                "0x%02x\n", rc);
    }

    if (rc == TPM_RC_SUCCESS) {
        if (memcmp(acthash, hash, sizeof(hash))) {
            rc = TPM_RC_HASH;
            TPMLIB_LogTPM2Error("Volatile state checksum error: 0x%02x\n",
                                rc);
        }
    }

    irc = RuntimeAlgorithmSetProfile(&g_RuntimeProfile.RuntimeAlgorithm, oldProfile,
                                     &stateFormatLevel, ~0);
    free(oldProfile);
    if (irc != TPM_RC_SUCCESS && rc == TPM_RC_SUCCESS)
        rc = irc;

    if (rc != TPM_RC_SUCCESS)
        _plat__SetInFailureMode(TRUE);

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
    written = VolatileState_Marshal(buffer, size, &g_RuntimeProfile);

    /* append the checksum */
    CryptHashBlock(hashAlg, written, start, sizeof(hash), hash);
    written += Array_Marshal(hash, sizeof(hash), buffer, size);

    return written;
}
