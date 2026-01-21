// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation 2017,2018.

#ifndef NVMARSHAL_H
#define NVMARSHAL_H

#include <stdbool.h>

#include "Tpm.h"
#include "tpm_public/TpmTypes.h"
#include "RuntimeProfile_fp.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

// Maximum size of buffer ANY_OBJECT_Marshal() will require to marshal an OBJECT
// This is not an exact number but gives a 'safe' buffer size
#define MAX_MARSHALLED_OBJECT_SIZE \
    (sizeof(OBJECT) + 32 /* marshalling headers */)

UINT16 VolatileState_Marshal(BYTE **buffer, INT32 *size,
                             struct RuntimeProfile *RuntimeProfile);
TPM_RC VolatileState_Unmarshal(BYTE **buffer, INT32 *size);

UINT32 PERSISTENT_ALL_Marshal(BYTE **buffer, INT32 *size);
TPM_RC PERSISTENT_ALL_Unmarshal(BYTE **buffer, INT32 *size);

void NVShadowRestore(void);

UINT16 ANY_OBJECT_Marshal(OBJECT *data, BYTE **buffer, INT32 *size,
                          struct RuntimeProfile *RuntimeProfile);
TPM_RC ANY_OBJECT_Unmarshal(OBJECT *data, BYTE **buffer, INT32 *size, BOOL verbose);

#endif /* NVMARSHAL_H */

