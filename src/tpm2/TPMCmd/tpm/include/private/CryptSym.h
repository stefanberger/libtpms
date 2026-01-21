// SPDX-License-Identifier: BSD-2-Clause

//** Introduction
//
// This file contains the implementation of the symmetric block cipher modes
// allowed for a TPM. These functions only use the single block encryption functions
// of the selected symmetric cryptographic library.

//** Includes, Defines, and Typedefs
#ifndef CRYPT_SYM_H
#define CRYPT_SYM_H

#if ALG_AES
#  define IF_IMPLEMENTED_AES(op) op(AES, aes)
#else
#  define IF_IMPLEMENTED_AES(op)
#endif
#if ALG_SM4
#  define IF_IMPLEMENTED_SM4(op) op(SM4, sm4)
#else
#  define IF_IMPLEMENTED_SM4(op)
#endif
#if ALG_CAMELLIA
#  define IF_IMPLEMENTED_CAMELLIA(op) op(CAMELLIA, camellia)
#else
#  define IF_IMPLEMENTED_CAMELLIA(op)
#endif
#if ALG_TDES				// libtpms added begin
#   define IF_IMPLEMENTED_TDES(op)    op(TDES, tdes)
#else
#   define IF_IMPLEMENTED_TDES(op)
#endif					// libtpms added end

#define FOR_EACH_SYM(op)   \
    IF_IMPLEMENTED_AES(op) \
    IF_IMPLEMENTED_SM4(op) \
    IF_IMPLEMENTED_CAMELLIA(op) \
    IF_IMPLEMENTED_TDES(op)

						/* libtpms added begin */
#define FOR_EACH_SYM_WITHOUT_TDES(op) \
    IF_IMPLEMENTED_AES(op)            \
    IF_IMPLEMENTED_SM4(op)            \
    IF_IMPLEMENTED_CAMELLIA(op)			/* libtpms added end */

// Macros for creating the key schedule union
#define KEY_SCHEDULE(SYM, sym) tpmKeySchedule##SYM sym;
typedef union tpmCryptKeySchedule_t {
    FOR_EACH_SYM_WITHOUT_TDES(KEY_SCHEDULE)	/* libtpms changed from FOR_EACH_SYM */

    tpmKeyScheduleTDES  tdes[3];		/* libtpms added */

#if SYMMETRIC_ALIGNMENT == 8
    uint64_t alignment;
#else
    uint32_t alignment;
# if defined(__x86_64__)	// libtpms added begin
# error Bad SYMMETRIC_ALIGNMENT
# endif				// libtpms added end
#endif
} tpmCryptKeySchedule_t;

// Each block cipher within a library is expected to conform to the same calling
// conventions with three parameters ('keySchedule', 'in', and 'out') in the same
// order. That means that all algorithms would use the same order of the same
// parameters. The code is written assuming the ('keySchedule', 'in', and 'out')
// order. However, if the library uses a different order, the order can be changed
// with a SWIZZLE macro that puts the parameters in the correct order.
// Note that all algorithms have to use the same order and number of parameters
// because the code to build the calling list is common for each call to encrypt
// or decrypt with the algorithm chosen by setting a function pointer to select
// the algorithm that is used.

#define ENCRYPT(keySchedule, in, out) encrypt(SWIZZLE(keySchedule, in, out))

#define DECRYPT(keySchedule, in, out) decrypt(SWIZZLE(keySchedule, in, out))

// Note that the macros rely on 'encrypt' as local values in the
// functions that use these macros. Those parameters are set by the macro that
// set the key schedule to be used for the call.

#define ENCRYPT_CASE(ALG, alg)                                            \
    case TPM_ALG_##ALG:                                                   \
        TpmCryptSetEncryptKey##ALG(key, keySizeInBits, &keySchedule.alg); \
        encrypt = (TpmCryptSetSymKeyCall_t)TpmCryptEncrypt##ALG;          \
        break;
#define DECRYPT_CASE(ALG, alg)                                            \
    case TPM_ALG_##ALG:                                                   \
        TpmCryptSetDecryptKey##ALG(key, keySizeInBits, &keySchedule.alg); \
        decrypt = (TpmCryptSetSymKeyCall_t)TpmCryptDecrypt##ALG;          \
        break;

#endif  // CRYPT_SYM_H
