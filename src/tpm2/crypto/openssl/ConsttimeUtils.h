/********************************************************************************/
/*										*/
/*			 Constant time debugging helper functions		*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  (c) Copyright IBM Corporation, 2020-2025					*/
/*										*/
/* All rights reserved.								*/
/*										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/*										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/*										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/*										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/*										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/*										*/
/********************************************************************************/

#ifndef CONSTTIME_UTILS_H
#define CONSTTIME_UTILS_H

#include <assert.h>
#include <stdio.h>

#include "BnValues.h"

#include <openssl/bn.h>

static __inline__ unsigned long long rdtsc() {
    unsigned long h, l;

    __asm__ __volatile__ ("rdtsc" : "=a"(l), "=d"(h));

    return  (unsigned long long)l |
           ((unsigned long long)h << 32 );
}

// Make sure that the given BIGNUM has the given number of expected bytes.
// Skip over any leading zeros the BIGNUM may have.
static inline void assert_ossl_num_bytes(const BIGNUM *a,
                                         unsigned int num_bytes,
                                         int verbose,
                                         const char *caller) {
    unsigned char buffer[LARGEST_NUMBER] = { 0, };
    int len, i;

    len = BN_bn2bin(a, buffer);
    for (i = 0; i < len; i++) {
        if (buffer[i])
            break;
    }
    len -= i;
    if (num_bytes != (unsigned int)len) {
        printf("%s: Expected %u bytes but found %d (caller: %s)\n", __func__, num_bytes, len, caller);
    } else {
        if (verbose)
            printf("%s: check passed; num_bytes = %d (caller: %s)\n",__func__, num_bytes, caller);
    }
    assert(num_bytes == (unsigned int)len);
}

// Make sure that the bigNum has the expected number of bytes after it was
// converted to an OpenSSL BIGNUM.
static inline void assert_bn_ossl_num_bytes(bigNum tpmb,
                                            unsigned int num_bytes,
                                            int verbose,
                                            const char *caller) {
    BIG_INITIALIZED(osslb, tpmb);

    assert_ossl_num_bytes(osslb, num_bytes, verbose, caller);

    BN_free(osslb);
}

#endif /* CONSTTIME_UTILS_H */
