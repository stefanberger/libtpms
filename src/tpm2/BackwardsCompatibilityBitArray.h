// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation 2023.

#ifndef BACKWARDS_COMPATIBILITY_BIT_ARRAY_H
#define BACKWARDS_COMPATIBILITY_BIT_ARRAY_H

#include "Tpm.h"
#include <tpm_public/TpmTypes.h>

TPM_RC
ConvertFromCompressedBitArray(BYTE         *inAuditCommands,
                              size_t        inAuditCommandsLen,
                              BYTE         *outAuditCommands,
                              size_t        outAuditCommandsLen);

TPM_RC
ConvertToCompressedBitArray(BYTE         *inAuditCommands,
                            size_t        inAuditCommandsLen,
                            BYTE         *outAuditCommands,
                            size_t        outAuditCommandsLen);

#endif
