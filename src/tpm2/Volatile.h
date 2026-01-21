// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation 2017,2018.

#ifndef VOLATILE_H
#define VOLATILE_H

#include <tpm_public/BaseTypes.h>

TPM_RC VolatileState_Load(BYTE **buffer, INT32 *size);
UINT16 VolatileState_Save(BYTE **buffer, INT32 *size);

#endif /* VOLATILE_H */
