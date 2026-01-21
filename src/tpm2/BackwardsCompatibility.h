// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation 2017,2018.

#ifndef BACKWARDS_COMPATIBILITY_H
#define BACKWARDS_COMPATIBILITY_H

#include "compiler.h"

typedef UINT8 SEED_COMPAT_LEVEL;
enum {
    SEED_COMPAT_LEVEL_ORIGINAL = 0,   /* original TPM 2 code up to rev155 */
    SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX = 1, /* RsaAdjustPrimeCandidate was fixed */
    SEED_COMPAT_LEVEL_LAST = SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX
};

#endif /* BACKWARDS_COMPATIBILITY_H */
