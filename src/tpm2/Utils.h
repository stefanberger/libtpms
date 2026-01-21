// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation 2017,2018.

#ifndef UTILS_H
#define UTILS_H

#include "prototypes/Memory_fp.h"

#define TPM2_ROUNDUP(VAL, SIZE) \
  ( ( (VAL) + (SIZE) - 1) / (SIZE) ) * (SIZE)

__attribute__((unused)) static inline void clear_and_free(void *ptr, size_t size) {
    if (ptr) {
        MemorySet(ptr, 0, size);
        free(ptr);
    }
}

#endif /* UTILS_H */
