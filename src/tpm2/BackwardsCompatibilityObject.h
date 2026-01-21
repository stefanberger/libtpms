// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation 2017,2018.

#ifndef BACKWARDS_COMPATIBILITY_OBJECT_H
#define BACKWARDS_COMPATIBILITY_OBJECT_H

#include "Tpm.h"

TPM_RC RSA2048_OBJECT_Buffer_To_OBJECT(OBJECT* object, BYTE* buffer, INT32 size);

TPM_RC RSA3072_OBJECT_Buffer_To_OBJECT(OBJECT* object, BYTE* buffer, INT32 size);
UINT32 OBJECT_To_Buffer_As_RSA3072_OBJECT(OBJECT* object, BYTE* buffer, UINT32 size);

TPMI_RH_HIERARCHY ObjectGetHierarchyFromAttributes(OBJECT* object);

#endif /* BACKWARDS_COMPATIBILITY_OBJECT_H */
