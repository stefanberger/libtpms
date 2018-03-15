#include <stdlib.h>

#include "config.h"

#include "tpm_library_intern.h"
#include "tpm_nvfilename.h"
#include "tpm_error.h"
#include "tpm_memory.h"

#include "StateMarshal.h"
#include "Volatile.h"

UINT16
VolatileSave(BYTE **buffer, INT32 *size)
{
    return VolatileState_Save(buffer, size);
}

TPM_RC
VolatileLoad(void)
{
    TPM_RC rc = TPM_RC_SUCCESS;

#ifdef TPM_LIBTPMS_CALLBACKS
    unsigned char *data = NULL;
    uint32_t length = 0;
    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
    TPM_RESULT ret = TPM_SUCCESS;
    bool is_empty_state;

    /* try to get state blob set via TPMLIB_SetState() */
    GetCachedState(TPMLIB_STATE_VOLATILE, &data, &length, &is_empty_state);
    if (is_empty_state)
        return rc;

    if (!data && cbs->tpm_nvram_loaddata) {
        uint32_t tpm_number = 0;
        const char *name = TPM_VOLATILESTATE_NAME;

        ret = cbs->tpm_nvram_loaddata(&data, &length, tpm_number, name);
    }

    if (data && ret == TPM_SUCCESS) {
        unsigned char *p = data;
        rc = VolatileState_Load(&data, (INT32 *)&length);
        /*
         * if this failed, VolatileState_Load will have started
         * failure mode.
         */
        TPM_Free(p);
    }
#endif /* TPM_LIBTPMS_CALLBACKS */

    return rc;
}
