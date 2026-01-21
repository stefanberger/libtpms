// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation 2017,2018.

#ifndef STATE_MARSHAL_H
#define STATE_MARSHAL_H

#include "Tpm.h"
#include <tpm_public/TpmTypes.h>

/*
 * we keep these in a separate file to avoid symbol clashes when
 * included from the interface code.
 */
TPM_RC VolatileLoad(BOOL *restored);
UINT16 VolatileSave(BYTE **buffer, INT32 *size);

#endif /* STATE_MARSHAL_H */

