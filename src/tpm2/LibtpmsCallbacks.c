// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation 2018.

#include <stdint.h>
#include <string.h>

#include "Platform.h"
#include "LibtpmsCallbacks.h"
#include "NVMarshal.h"

#define TPM_HAVE_TPM2_DECLARATIONS
#include "tpm_library_intern.h"
#include "tpm_error.h"
#include "tpm_nvfilename.h"

int
libtpms_plat__NVEnable(void)
{
    unsigned char *data = NULL;
    uint32_t length = 0;
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
    TPM_RC rc;
    bool is_empty_state;

    /* try to get state blob set via TPMLIB_SetState() */
    GetCachedState(TPMLIB_STATE_PERMANENT, &data, &length, &is_empty_state);
    if (is_empty_state) {
        memset(s_NV, 0, NV_MEMORY_SIZE);
        return 0;
    }

    if (data == NULL && cbs->tpm_nvram_loaddata) {
        uint32_t tpm_number = 0;
        const char *name = TPM_PERMANENT_ALL_NAME;
        TPM_RESULT ret;

        ret = cbs->tpm_nvram_loaddata(&data, &length, tpm_number, name);
        switch (ret) {
        case TPM_RETRY:
            if (!cbs->tpm_nvram_storedata) {
                return -1;
            }
            memset(s_NV, 0, NV_MEMORY_SIZE);
            return 0;

        case TPM_SUCCESS:
            /* got the data -- unmarshal them... */
            break;

        case TPM_FAIL:
        default:
            return -1;
        }
    }

    if (data) {
        unsigned char *buffer = data;
        INT32 size = length;

        rc = PERSISTENT_ALL_Unmarshal(&buffer, &size);
        free(data);
        if (rc != TPM_RC_SUCCESS)
            return -1;
         return 0;
    }
    return LIBTPMS_CALLBACK_FALLTHROUGH; /* -2 */
}

int
libtpms_plat__NVDisable(
		 void
		 )
{
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();

    if (cbs->tpm_nvram_loaddata)
        return 0;
    return LIBTPMS_CALLBACK_FALLTHROUGH; /* -2 */
}

int
libtpms_plat__IsNvAvailable(
		     void
		     )
{
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();

    if (cbs->tpm_nvram_loaddata &&
        cbs->tpm_nvram_storedata) {
        return 1;
    }
    return LIBTPMS_CALLBACK_FALLTHROUGH; /* -2 */
}

int
libtpms_plat__NvCommit(
		void
		)
{
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();

    if (cbs->tpm_nvram_storedata) {
        uint32_t tpm_number = 0;
        const char *name = TPM_PERMANENT_ALL_NAME;
        TPM_RESULT ret;
        BYTE *buf;
        uint32_t buflen;

        ret = TPM2_PersistentAllStore(&buf, &buflen);
        if (ret != TPM_SUCCESS)
            return ret;

        ret = cbs->tpm_nvram_storedata(buf, buflen,
                                       tpm_number, name);
        free(buf);
        if (ret == TPM_SUCCESS)
            return 0;

        return -1;
    }
    return LIBTPMS_CALLBACK_FALLTHROUGH; /* -2 */
}

int
libtpms_plat__PhysicalPresenceAsserted(
				BOOL *pp
				)
{
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();

    if (cbs->tpm_io_getphysicalpresence) {
        uint32_t tpm_number = 0;
        TPM_RESULT res;
        unsigned char mypp;

        res = cbs->tpm_io_getphysicalpresence(&mypp, tpm_number);
        if (res == TPM_SUCCESS) {
            *pp = mypp;
            return 0;
        }
    }
    return LIBTPMS_CALLBACK_FALLTHROUGH;
}
