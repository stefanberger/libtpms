// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation, 2021-2025

#ifndef DCACHE_FP_H
#define DCACHE_FP_H

#include <openssl/bn.h>

BIGNUM *ExpDCacheFind(const BIGNUM *P, const BIGNUM *N, const BIGNUM *E,
                      BIGNUM **Q);

void ExpDCacheAdd(const BIGNUM *P, const BIGNUM *N, const BIGNUM *E,
                  const BIGNUM *Q, const BIGNUM *D);

void ExpDCacheFree(void);

#endif /* DCACHE_FP_H */

