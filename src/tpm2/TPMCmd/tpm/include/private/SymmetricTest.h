// SPDX-License-Identifier: BSD-2-Clause

//** Introduction

// This file contains the structures and data definitions for the symmetric tests.
// This file references the header file that contains the actual test vectors. This
// organization was chosen so that the program that is used to generate the test
// vector values does not have to also re-generate this data.
#ifndef SELF_TEST_DATA
#  error "This file may only be included in AlgorithmTests.c"
#endif

#ifndef _SYMMETRIC_TEST_H
#  define _SYMMETRIC_TEST_H
#  include "SymmetricTestData.h"

//** Symmetric Test Structures

const SYMMETRIC_TEST_VECTOR c_symTestValues[NUM_SYMS + 1] = {
#  if ALG_AES && AES_128
    {TPM_ALG_AES,
     128,
     key_AES128,
     16,
     sizeof(dataIn_AES128),
     dataIn_AES128,
     {dataOut_AES128_CTR,
      dataOut_AES128_OFB,
      dataOut_AES128_CBC,
      dataOut_AES128_CFB,
      dataOut_AES128_ECB}},
#  endif
#  if ALG_AES && AES_192
    {TPM_ALG_AES,
     192,
     key_AES192,
     16,
     sizeof(dataIn_AES192),
     dataIn_AES192,
     {dataOut_AES192_CTR,
      dataOut_AES192_OFB,
      dataOut_AES192_CBC,
      dataOut_AES192_CFB,
      dataOut_AES192_ECB}},
#  endif
#  if ALG_AES && AES_256
    {TPM_ALG_AES,
     256,
     key_AES256,
     16,
     sizeof(dataIn_AES256),
     dataIn_AES256,
     {dataOut_AES256_CTR,
      dataOut_AES256_OFB,
      dataOut_AES256_CBC,
      dataOut_AES256_CFB,
      dataOut_AES256_ECB}},
#  endif
#  if ALG_SM4 && SM4_128 // libtpms activated
    {TPM_ALG_SM4,
     128,
     key_SM4128,
     16,
     sizeof(dataIn_SM4128),
     dataIn_SM4128,
     {dataOut_SM4128_CTR,
      dataOut_SM4128_OFB,
      dataOut_SM4128_CBC,
      dataOut_SM4128_CFB,
      dataOut_AES128_ECB}},
#  endif
// libtpms added begin
#if ALG_TDES && TDES_128
    {TPM_ALG_TDES, 128, key_TDES128, 8, sizeof(dataIn_TDES128), dataIn_TDES128,
     {dataOut_TDES128_CTR, dataOut_TDES128_OFB, dataOut_TDES128_CBC,
      dataOut_TDES128_CFB, dataOut_TDES128_ECB}},
    {TPM_ALG_TDES, 128, key_TDES128, 8, sizeof(dataInShort_TDES128), dataInShort_TDES128,
     {NULL, dataOutShort_TDES128_OFB, NULL,
      dataOutShort_TDES128_CFB, NULL}},
#endif
#if ALG_TDES && TDES_192
    {TPM_ALG_TDES, 192, key_TDES192, 8, sizeof(dataIn_TDES192), dataIn_TDES192,
     {dataOut_TDES192_CTR, dataOut_TDES192_OFB, dataOut_TDES192_CBC,
      dataOut_TDES192_CFB, dataOut_TDES192_ECB}},
    {TPM_ALG_TDES, 192, key_TDES192, 8, sizeof(dataInShort_TDES192), dataInShort_TDES192,
     {NULL, dataOutShort_TDES192_OFB, NULL,
      dataOutShort_TDES192_CFB, NULL}},
#endif
#if ALG_CAMELLIA && CAMELLIA_128
    {TPM_ALG_CAMELLIA, 128, key_CAMELLIA128, 16, sizeof(dataIn_CAMELLIA128), dataIn_CAMELLIA128,
     {dataOut_CAMELLIA128_CTR, dataOut_CAMELLIA128_OFB, dataOut_CAMELLIA128_CBC,
      dataOut_CAMELLIA128_CFB, dataOut_CAMELLIA128_ECB}},
#endif
#if 0 && ALG_CAMELLIA && CAMELLIA_192
    {TPM_ALG_CAMELLIA, 192, key_CAMELLIA192, 16, sizeof(dataIn_CAMELLIA192), dataIn_CAMELLIA192,
     {dataOut_CAMELLIA192_CTR, dataOut_CAMELLIA192_OFB, dataOut_CAMELLIA192_CBC,
      dataOut_CAMELLIA192_CFB, dataOut_CAMELLIA192_ECB}},
#endif
#if ALG_CAMELLIA && CAMELLIA_256
    {TPM_ALG_CAMELLIA, 256, key_CAMELLIA256, 16, sizeof(dataIn_CAMELLIA256), dataIn_CAMELLIA256,
     {dataOut_CAMELLIA256_CTR, dataOut_CAMELLIA256_OFB, dataOut_CAMELLIA256_CBC,
      dataOut_CAMELLIA256_CFB, dataOut_CAMELLIA256_ECB}},
#endif
// libtpms added end
    {0}};

#endif  // _SYMMETRIC_TEST_H
