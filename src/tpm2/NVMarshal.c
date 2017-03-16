/********************************************************************************/
/*										*/
/*			  Marshalling and unmarshalling of state		*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2012-2015				*/
/*										*/
/********************************************************************************/

#include <endian.h>
#include <string.h>

#include "assert.h"

#define SESSION_PROCESS_C
#define NV_C
#define OBJECT_C
#define PCR_C
#define SESSION_C
#include "PlatformData.h"
#include "Implementation.h"
#include "NVMarshal.h"
#include "Marshal_fp.h"
#include "Unmarshal_fp.h"
#include "Global.h"

UINT16
TPM2B_PROOF_Marshal(TPM2B_PROOF *source, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

TPM_RC
TPM2B_PROOF_Unmarshal(TPM2B_PROOF *target, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TPM2B_Unmarshal(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

static UINT16
DRBG_STATE_Marshal(DRBG_STATE *data, BYTE **buffer, INT32 *size)
{
    UINT16 written;
    size_t i;

    written = UINT64_Marshal(&data->reseedCounter, buffer, size);
    written += UINT32_Marshal(&data->magic, buffer, size);
    written += Array_Marshal(&data->seed.bytes[0], sizeof(data->seed.bytes), buffer, size);
    for (i = 0; i < ARRAY_SIZE(data->lastValue); i++) {
        written += UINT32_Marshal(&data->lastValue[i], buffer, size);
    }

    return written;
}

static TPM_RC
DRBG_STATE_Unmarshal(DRBG_STATE *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc= TPM_RC_SUCCESS;
    size_t i;

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->reseedCounter, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal(&data->magic, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal(&data->seed.bytes[0], sizeof(data->seed.bytes), buffer, size);
    }

    for (i = 0; i < ARRAY_SIZE(data->lastValue) && rc == TPM_RC_SUCCESS; i++) {
        rc = UINT32_Unmarshal(&data->lastValue[i], buffer, size);
    }

    return rc;
}

static void
DRBG_STATE_SWAP(DRBG_STATE *t, DRBG_STATE *s)
{
    size_t i;

    t->reseedCounter = htobe64(s->reseedCounter);
    t->magic = htobe32(s->magic);
    memcpy(t->seed.bytes, s->seed.bytes, sizeof(t->seed.bytes));
    for (i = 0; i < ARRAY_SIZE(s->lastValue); i++)
        t->lastValue[i] = htobe32(s->lastValue[i]);
}

UINT16
ORDERLY_DATA_Marshal(ORDERLY_DATA *data, BYTE **buffer, INT32 *size)
{
    UINT16 written;

    written = UINT64_Marshal(&data->clock, buffer, size);
    written += UINT8_Marshal(&data->clockSafe, buffer, size);

    written += DRBG_STATE_Marshal(&data->drbgState, buffer, size);

#ifdef ACCUMULATE_SELF_HEAL_TIMER
    written += UINT64_Marshal(&data->selfHealTimer, buffer, size);
    written += UINT64_Marshal(&data->lockoutTimer, buffer, size);
    written += UINT64_Marshal(&data->time, buffer, size);
#endif // ACCUMULATE_SELF_HEAL_TIMER

    return written;
}

TPM_RC
ORDERLY_DATA_Unmarshal(ORDERLY_DATA *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->clock, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal(&data->clockSafe, buffer, size);
    }

    if (rc == TPM_RC_SUCCESS) {
        rc = DRBG_STATE_Unmarshal(&data->drbgState, buffer, size);
    }

#ifdef ACCUMULATE_SELF_HEAL_TIMER
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->selfHealTimer, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->lockoutTimer, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->time, buffer, size);
    }
#endif // ACCUMULATE_SELF_HEAL_TIMER

    return rc;
}

static UINT16
PCR_SAVE_Marshal(PCR_SAVE *data, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;

#ifdef TPM_ALG_SHA1
    written = Array_Marshal((BYTE *)&data->sha1, sizeof(data->sha1),
                            buffer, size);
#endif
#ifdef TPM_ALG_SHA256
    written += Array_Marshal((BYTE *)&data->sha256, sizeof(data->sha256),
                              buffer, size);
#endif
#ifdef TPM_ALG_SHA384
    written += Array_Marshal((BYTE *)&data->sha384, sizeof(data->sha384),
                             buffer, size);
#endif
#ifdef TPM_ALG_SHA512
    written += Array_Marshal((BYTE *)&data->sha512, sizeof(data->sha512),
                             buffer, size);
#endif
#ifdef TPM_ALG_SM3_256
    written += Array_Marshal((BYTE *)&data->sm3_256, sizeof(data->sm3_256),
                             buffer, size);
#endif

    return written;
}

static TPM_RC
PCR_SAVE_Unmarshal(PCR_SAVE *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

#ifdef TPM_ALG_SHA1
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha1, sizeof(data->sha1),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SHA256
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha256, sizeof(data->sha256),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SHA384
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha384, sizeof(data->sha384),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SHA512
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha512, sizeof(data->sha512),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SM3_256
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sm3_256, sizeof(data->sm3_256),
                              buffer, size);
    }
#endif

    return rc;
}


#ifdef PCR_C
static UINT16
PCR_Marshal(PCR *data, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;

#ifdef TPM_ALG_SHA1
    written = Array_Marshal((BYTE *)&data->sha1Pcr, sizeof(data->sha1Pcr),
                            buffer, size);
#endif
#ifdef TPM_ALG_SHA256
    written += Array_Marshal((BYTE *)&data->sha256Pcr, sizeof(data->sha256Pcr),
                              buffer, size);
#endif
#ifdef TPM_ALG_SHA384
    written += Array_Marshal((BYTE *)&data->sha384Pcr, sizeof(data->sha384Pcr),
                             buffer, size);
#endif
#ifdef TPM_ALG_SHA512
    written += Array_Marshal((BYTE *)&data->sha512Pcr, sizeof(data->sha512Pcr),
                             buffer, size);
#endif
#ifdef TPM_ALG_SM3_256
    written += Array_Marshal((BYTE *)&data->sm3_256Pcr, sizeof(data->sm3_256Pcr),
                             buffer, size);
#endif

    return written;
}

static TPM_RC
PCR_Unmarshal(PCR *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

#ifdef TPM_ALG_SHA1
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha1Pcr, sizeof(data->sha1Pcr),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SHA256
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha256Pcr, sizeof(data->sha256Pcr),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SHA384
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha384Pcr, sizeof(data->sha384Pcr),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SHA512
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sha512Pcr, sizeof(data->sha512Pcr),
                              buffer, size);
    }
#endif
#ifdef TPM_ALG_SM3_256
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->sm3_256Pcr, sizeof(data->sm3_256Pcr),
                              buffer, size);
    }
#endif

    return rc;
}
#endif

static UINT16
PCR_AUTHVALUE_Marshal(PCR_AUTHVALUE *data, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(data->auth); i++) {
        written += TPM2B_DIGEST_Marshal(&data->auth[i], buffer, size);
    }

    return written;
}

static TPM_RC
PCR_AUTHVALUE_Unmarshal(PCR_AUTHVALUE *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(data->auth) && rc == TPM_RC_SUCCESS; i++) {
        rc = TPM2B_DIGEST_Unmarshal(&data->auth[i], buffer, size);
    }

    return rc;
}

static void
PCR_AUTHVALUE_SWAP(PCR_AUTHVALUE *t, PCR_AUTHVALUE *s)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(s->auth); i++) {
        TPM2B_SWAP(&t->auth[i].b, &s->auth[i].b, sizeof(t->auth[i].t.buffer));
    }
}

UINT16
STATE_CLEAR_DATA_Marshal(STATE_CLEAR_DATA *data, BYTE **buffer, INT32 *size)
{
    UINT16 written;

    written = UINT8_Marshal((UINT8 *)&data->shEnable, buffer, size);
    written += UINT8_Marshal((UINT8 *)&data->ehEnable, buffer, size);
    written += UINT8_Marshal((UINT8 *)&data->phEnableNV, buffer, size);
    written += UINT16_Marshal(&data->platformAlg, buffer, size);
    written += TPM2B_DIGEST_Marshal(&data->platformPolicy, buffer, size);
    written += TPM2B_AUTH_Marshal(&data->platformAuth, buffer, size);
    written += PCR_SAVE_Marshal(&data->pcrSave, buffer, size);
    written += PCR_AUTHVALUE_Marshal(&data->pcrAuthValues, buffer, size);

    return written;
}

TPM_RC
STATE_CLEAR_DATA_Unmarshal(STATE_CLEAR_DATA *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&data->shEnable, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&data->ehEnable, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&data->phEnableNV, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT16_Unmarshal(&data->platformAlg, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_DIGEST_Unmarshal(&data->platformPolicy, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_AUTH_Unmarshal(&data->platformAuth, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = PCR_SAVE_Unmarshal(&data->pcrSave, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = PCR_AUTHVALUE_Unmarshal(&data->pcrAuthValues, buffer, size);
    }

    return rc;
}

TPM_RC
STATE_RESET_DATA_Unmarshal(STATE_RESET_DATA *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_PROOF_Unmarshal(&data->nullProof, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_Unmarshal(&data->nullSeed.b, PRIMARY_SEED_SIZE, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal(&data->clearCount, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->objectContextID, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->contextArray, sizeof(data->contextArray),
                              buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->contextCounter, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_DIGEST_Unmarshal(&data->commandAuditDigest,
                              buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal(&data->restartCount, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal(&data->pcrCounter, buffer, size);
    }
#ifdef TPM_ALG_ECC
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->commitCounter, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_AUTH_Unmarshal(&data->commitNonce, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal((BYTE *)&data->commitArray,
                              sizeof(data->commitArray),
                              buffer, size);
    }
#endif

    return rc;
}

UINT16
STATE_RESET_DATA_Marshal(STATE_RESET_DATA *data, BYTE **buffer, INT32 *size)
{
    UINT16 written;

    written = TPM2B_PROOF_Marshal(&data->nullProof, buffer, size);
    written += TPM2B_Marshal(&data->nullSeed.b, buffer, size);
    written += UINT32_Marshal(&data->clearCount, buffer, size);
    written += UINT64_Marshal(&data->objectContextID, buffer, size);
    written += Array_Marshal((BYTE *)&data->contextArray, sizeof(data->contextArray),
                              buffer, size);
    written += UINT64_Marshal(&data->contextCounter, buffer, size);
    written += TPM2B_DIGEST_Marshal(&data->commandAuditDigest,
                              buffer, size);
    written += UINT32_Marshal(&data->restartCount, buffer, size);
    written += UINT32_Marshal(&data->pcrCounter, buffer, size);
#ifdef TPM_ALG_ECC
    written += UINT64_Marshal(&data->commitCounter, buffer, size);
    written += TPM2B_AUTH_Marshal(&data->commitNonce, buffer, size);
    written += Array_Marshal((BYTE *)&data->commitArray,
                             sizeof(data->commitArray),
                              buffer, size);
#endif

    return written;
}

static UINT16
bn_prime_t_Marshal(bn_prime_t *data, BYTE **buffer, INT32 *size)
{
    UINT16 written, numbytes;
    size_t i, idx;

    /* we do not write 'allocated' */

    numbytes = data->size * sizeof(crypt_uword_t);
    written = UINT16_Marshal(&numbytes, buffer, size);

    for (i = 0, idx = 0;
         i < numbytes;
         i += sizeof(crypt_uword_t), idx += 1) {
#if RADIX_BITS == 64
        written += UINT64_Marshal(&data->d[idx], buffer, size);
#elif RADIX_BITS == 32
        written += UINT32_Marshal(&data->d[idx], buffer, size);
#else
#error RADIX_BYTES it no defined
#endif
    }

    return written;
}

static TPM_RC
bn_prime_t_Unmarshal(bn_prime_t *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    size_t i, idx;
    UINT16 numbytes;
    UINT32 word;

    data->allocated = ARRAY_SIZE(data->d);

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT16_Unmarshal(&numbytes, buffer, size);
        data->size = (numbytes + sizeof(crypt_uword_t) - 1) / sizeof(crypt_word_t);
        if (data->size > data->allocated) {
            rc = TPM_RC_SIZE;
        }
    }

    for (i = 0, idx = 0;
         i < numbytes && rc == TPM_RC_SUCCESS;
         i += sizeof(UINT32), idx += 1) {
        rc = UINT32_Unmarshal(&word, buffer, size);
#if RADIX_BITS == 64
        data->d[idx / 2] <<= 32;
        data->d[idx / 2] |= word;
#elif RADIX_BITS == 32
        data->d[idx] = word;
#endif
    }

#if RADIX_BITS == 64
    if (rc == TPM_RC_SUCCESS) {
        if (idx & 1)
            data->d[idx / 2] <<= 32;
    }
#endif

    return rc;
}

static void
bn_prime_t_SWAP(bn_prime_t *t, bn_prime_t *s)
{
    size_t i;

#if RADIX_BITS == 64
    t->allocated = htobe64(s->allocated);
    t->size = htobe64(s->size);

    for (i = 0; i < ARRAY_SIZE(t->d); i++) {
        t->d[i] = htobe64(s->d[i]);
    }
#elif RADIX_BITS == 32
    t->allocated = htobe32(s->allocated);
    t->size = htobe32(s->size);

    for (i = 0; i < ARRAY_SIZE(t->d); i++) {
        t->d[i] = htobe32(s->d[i]);
    }
#endif
}

static UINT16
privateExponent_t_Marshal(privateExponent_t *data, BYTE **buffer, INT32 *size)
{
    UINT16 written = 0;

#if CRT_FORMAT_RSA == NO
#error Missing code
#else
    written += bn_prime_t_Marshal(&data->Q, buffer, size);
    written += bn_prime_t_Marshal(&data->dP, buffer, size);
    written += bn_prime_t_Marshal(&data->dQ, buffer, size);
    written += bn_prime_t_Marshal(&data->qInv, buffer, size);
#endif

    return written;
}

static TPM_RC
privateExponent_t_Unmarshal(privateExponent_t *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

#if CRT_FORMAT_RSA == NO
#error Missing code
#else
    if (rc == TPM_RC_SUCCESS) {
        rc = bn_prime_t_Unmarshal(&data->Q, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = bn_prime_t_Unmarshal(&data->dP, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = bn_prime_t_Unmarshal(&data->dQ, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = bn_prime_t_Unmarshal(&data->qInv, buffer, size);
    }
#endif

    return rc;
}

static void
privateExponent_t_SWAP(privateExponent_t *t, privateExponent_t *s)
{
#if CRT_FORMAT_RSA == NO
#error Missing code
#else
    bn_prime_t_SWAP(&t->Q, &s->Q);
    bn_prime_t_SWAP(&t->dP, &s->dP);
    bn_prime_t_SWAP(&t->dQ, &s->dQ);
    bn_prime_t_SWAP(&t->qInv, &s->qInv);
#endif
}

static UINT16
OBJECT_Marshal(OBJECT *data, BYTE **buffer, INT32 *size)
{
    UINT16 written;
    UINT16 *ptr = (UINT16 *)&data->attributes;

    written = UINT16_Marshal(ptr, buffer, size);
    /* the slot must be occupied, otherwise the rest may not be initialized */
    if (!data->attributes.occupied)
        return written;

    written += TPMT_PUBLIC_Marshal(&data->publicArea, buffer, size);
    written += TPMT_SENSITIVE_Marshal(&data->sensitive, buffer, size);
#ifdef TPM_ALG_RSA
    written += privateExponent_t_Marshal(&data->privateExponent,
                                         buffer, size);
#endif
    written += TPM2B_NAME_Marshal(&data->qualifiedName, buffer, size);
    written += TPM_HANDLE_Marshal(&data->evictHandle, buffer, size);
    written += TPM2B_NAME_Marshal(&data->name, buffer, size);

    return written;
}

static TPM_RC
OBJECT_Unmarshal(OBJECT *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 *ptr = (UINT16 *)&data->attributes;

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT16_Unmarshal(ptr, buffer, size);
    }

    if (!data->attributes.occupied)
        return rc;

    if (rc == TPM_RC_SUCCESS) {
        rc = TPMT_PUBLIC_Unmarshal(&data->publicArea, buffer, size, TRUE);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPMT_SENSITIVE_Unmarshal(&data->sensitive, buffer, size);
    }
#ifdef TPM_ALG_RSA
    if (rc == TPM_RC_SUCCESS) {
        rc = privateExponent_t_Unmarshal(&data->privateExponent,
                                         buffer, size);
    }
#endif
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_NAME_Unmarshal(&data->qualifiedName, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM_HANDLE_Unmarshal(&data->evictHandle, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_NAME_Unmarshal(&data->name, buffer, size);
    }

    return rc;
}

static UINT16
TPMT_SYM_DEF_Marshal(TPMT_SYM_DEF *data, BYTE **buffer, INT32 *size)
{
    UINT16 written;

    written = UINT16_Marshal(&data->algorithm, buffer, size);
    written += TPMU_SYM_KEY_BITS_Marshal(&data->keyBits, buffer, size, data->algorithm);
    written += TPMU_SYM_MODE_Marshal(&data->mode, buffer, size, data->algorithm);

    return written;
}

static UINT16
SESSION_Marshal(SESSION *data, BYTE **buffer, INT32 *size)
{
    UINT16 written;

    written = UINT32_Marshal((UINT32 *)&data->attributes, buffer, size);
    written += UINT32_Marshal(&data->pcrCounter, buffer, size);
    written += UINT64_Marshal(&data->startTime, buffer, size);
    written += UINT64_Marshal(&data->timeout, buffer, size);
#ifdef CLOCK_STOPS
    written += UINT64_Marshal(&data->epoch, buffer, size);
#else
    written += UINT32_Marshal(&data->epoch, buffer, size);
#endif
    written += UINT32_Marshal(&data->commandCode, buffer, size);
    written += UINT16_Marshal(&data->authHashAlg, buffer, size);
    written += UINT8_Marshal(&data->commandLocality, buffer, size);
    written += TPMT_SYM_DEF_Marshal(&data->symmetric, buffer, size);
    written += TPM2B_AUTH_Marshal(&data->sessionKey, buffer, size);
    written += TPM2B_NONCE_Marshal(&data->nonceTPM, buffer, size);
    // TPM2B_NAME or TPM2B_DIGEST could be used for marshalling
    written += TPM2B_NAME_Marshal(&data->u1.boundEntity, buffer, size);
    written += TPM2B_DIGEST_Marshal(&data->u2.auditDigest, buffer, size);

    return written;
}

static TPM_RC
SESSION_Unmarshal(SESSION *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal((UINT32 *)&data->attributes, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal(&data->pcrCounter, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->startTime, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&data->timeout, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
#ifdef CLOCK_STOPS
        rc = UINT64_Unmarshal(&data->epoch, buffer, size);
#else
        rc = UINT32_Unmarshal(&data->epoch, buffer, size);
#endif
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal(&data->commandCode, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT16_Unmarshal(&data->authHashAlg, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal(&data->commandLocality, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPMT_SYM_DEF_Unmarshal(&data->symmetric, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_AUTH_Unmarshal(&data->sessionKey, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_NONCE_Unmarshal(&data->nonceTPM, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_NAME_Unmarshal(&data->u1.boundEntity, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_DIGEST_Unmarshal(&data->u2.auditDigest, buffer, size);
    }

    return rc;
}

static UINT16
SESSION_SLOT_Marshal(SESSION_SLOT *data, BYTE **buffer, INT32* size)
{
    UINT16 written;

    written = UINT8_Marshal((UINT8 *)&data->occupied, buffer, size);
    if (!data->occupied)
        return written;

    written += SESSION_Marshal(&data->session, buffer, size);

    return written;
}

static TPM_RC
SESSION_SLOT_Unmarshal(SESSION_SLOT *data, BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&data->occupied, buffer, size);
    }
    if (!data->occupied)
        return rc;

    if (rc == TPM_RC_SUCCESS) {
        rc = SESSION_Unmarshal(&data->session, buffer, size);
    }
    return rc;
}

UINT16
VolatileState_Marshal(BYTE **buffer, INT32 *size)
{
    UINT16 written;
    UINT16 version = 1; /* blob version */
    size_t i;

    written = UINT16_Marshal(&version, buffer, size);

    /* skip g_rcIndex: these are 'constants' */
    written += TPM_HANDLE_Marshal(&g_exclusiveAuditSession, buffer, size); /* line 423 */
    /* g_time: may not be necessary */
    written += UINT64_Marshal(&g_time, buffer, size); /* line 426 */
    /* g_timeEpoch: skipped so far -- needs investigation */
    /* g_phEnable: since we won't call TPM2_Starup, we need to write it */
    written += UINT8_Marshal((UINT8 *)&g_phEnable, buffer, size); /* line 439 */
    /* g_pcrReconfig: must write */
    written += UINT8_Marshal((UINT8 *)&g_pcrReConfig, buffer, size); /* line 443 */
    /* g_DRTMHandle: must write */
    written += TPM_HANDLE_Marshal(&g_DRTMHandle, buffer, size); /* line 448 */
    /* g_DrtmPreStartup: must write */
    written += UINT8_Marshal((UINT8 *)&g_DrtmPreStartup, buffer, size); /* line 453 */
    /* g_StartupLocality3: must write */
    written += UINT8_Marshal((UINT8 *)&g_StartupLocality3, buffer, size); /* line 458 */
    /* g_daUsed: must write */
    written += UINT8_Marshal((UINT8 *)&g_daUsed, buffer, size); /* line 484 */
    /* g_updateNV: can skip since it seems to only be valid during execution of a command*/
    /* g_powerWasLost: must write */
    written += UINT8_Marshal((UINT8 *)&g_powerWasLost, buffer, size); /* line 504 */
    /* g_clearOrderly: can skip since it seems to only be valid during execution of a command */
    /* g_prevOrderlyState: must write */
    written += UINT16_Marshal(&g_prevOrderlyState, buffer, size); /* line 516 */
    /* g_nvOk: must write */
    written += UINT8_Marshal((UINT8 *)&g_nvOk, buffer, size); /* line 522 */
    /* g_NvStatus: can skip since it seems to only be valid during execution of a command */

#if 0 /* does not exist */
    written += TPM2B_AUTH_Marshal(&g_platformUniqueAuthorities, buffer, size); /* line 535 */
#endif
    written += TPM2B_AUTH_Marshal(&g_platformUniqueDetails, buffer, size); /* line 536 */

    /* gp (persistent_data): skip; we assume its latest states in the persistent data file */

    /* we store the next 3 because they may not have been written to NVRAM */
    written += ORDERLY_DATA_Marshal(&go, buffer, size); /* line 707 */
    written += STATE_CLEAR_DATA_Marshal(&gc, buffer, size); /* line 738 */
    written += STATE_RESET_DATA_Marshal(&gr, buffer, size); /* line 826 */

    /* g_manufactured: needs more investigation */
    written += UINT8_Marshal((UINT8 *)&g_manufactured, buffer, size); /* line 928 */
    /* g_initialized: must write */
    written += UINT8_Marshal((UINT8 *)&g_initialized, buffer, size); /* line 932 */

#if defined SESSION_PROCESS_C || defined GLOBAL_C || defined MANUFACTURE_C
    /*
     * The session related variables may only be valid during the execution
     * of a single command; FIXME: needs more investigation
     */
    for (i = 0; i < ARRAY_SIZE(s_sessionHandles); i++) {
        written += TPM_HANDLE_Marshal(&s_sessionHandles[i], buffer, size);
        written += TPMA_SESSION_Marshal(&s_attributes[i], buffer, size);
        written += TPM_HANDLE_Marshal(&s_associatedHandles[i], buffer, size);
        written += TPM2B_NONCE_Marshal(&s_nonceCaller[i], buffer, size);
        written += TPM2B_AUTH_Marshal(&s_inputAuthValues[i], buffer, size);
        /* s_usedSessions: cannot serialize this since it is a pointer; also, isn't used */
    }
    written += TPM_HANDLE_Marshal(&s_encryptSessionIndex, buffer, size);
    written += TPM_HANDLE_Marshal(&s_decryptSessionIndex, buffer, size);
    written += TPM_HANDLE_Marshal(&s_auditSessionIndex, buffer, size);
#ifdef  TPM_CC_GetCommandAuditDigest
    /* s_cpHashForCommandAudit: seems not used; better to write it */
    written += TPM2B_DIGEST_Marshal(&s_cpHashForCommandAudit, buffer, size);
#endif
    /* s_DAPendingOnNV: needs investigation ... */
    written += UINT8_Marshal((UINT8 *)&s_DAPendingOnNV, buffer, size);
#endif
#ifndef ACCUMULATE_SELF_HEAL_TIMER
    written += UINT64_Marshal(&s_selfHealTimer, buffer, size); /* line 975 */
    written += UINT64_Marshal(&s_lockoutTimer, buffer, size); /* line 977 */
#endif

#if defined NV_C || defined GLOBAL_C
    /* s_evictNvEnd set in NvInitStatic called by NvPowerOn in case g_powerWasLost
     * Unless we set g_powerWasLost=TRUE and call NvPowerOn, we have to include it.
     */
    written += UINT32_Marshal(&s_evictNvEnd, buffer, size); /* line 984 */
    /* s_indexOrderlyRam read from NVRAM in NvEntityStartup and written to it
     * in NvUpdateIndexOrderlyData called by TPM2_Shutdown and initialized
     * in NvManufacture -- since we don't call TPM2_Shutdown we serialize it here
     */
    written += Array_Marshal(s_indexOrderlyRam, sizeof(s_indexOrderlyRam), buffer, size);
    written += UINT64_Marshal(&s_maxCounter, buffer, size); /* line 992 */
    /* not sure about the following; NvIndexCacheInit initializes them partly */
    //written += NV_INDEX_Marshal(&s_cachedNvIndex, buffer, size); /* line 1003 */
    //written += UINT32_Marshal(&s_cachedNvRef, buffer, size); /* line 1004 */
    //written += UINT8_Marshal(s_cachedNvRamRef, buffer, size); /* line 1005 */
#endif
#if defined OBJECT_C || defined GLOBAL_C
    /* used in many places; it doesn't look like TPM2_Shutdown writes this into
     * persistent memory, so what is lost upon TPM2_Shutdown?
     */
    for (i = 0; i < ARRAY_SIZE(s_objects); i++) {
        written += OBJECT_Marshal(&s_objects[i], buffer, size);
    }
#endif

#if defined PCR_C || defined GLOBAL_C
    /* s_pcrs: Marshal *all* PCRs, even those for which stateSave bit is not set */
    for (i = 0; i < ARRAY_SIZE(s_pcrs); i++) {
        written += PCR_Marshal(&s_pcrs[i], buffer, size);
    }
#endif

#if defined SESSION_C || defined GLOBAL_C
    /* s_sessions: */
    for (i = 0; i < ARRAY_SIZE(s_sessions); i++) {
        written += SESSION_SLOT_Marshal(&s_sessions[i], buffer, size);
    }
    /* s_oldestSavedSession: */
    written += UINT32_Marshal(&s_oldestSavedSession, buffer, size);
    /* s_freeSessionSlots: */
    written += UINT32_Marshal((UINT32 *)&s_freeSessionSlots, buffer, size);
#endif

#if defined IO_BUFFER_C || defined GLOBAL_C
    /* s_actionInputBuffer: skip; only used during a single command */
    /* s_actionOutputBuffer: skip; only used during a single command */
#endif
    written += UINT8_Marshal((UINT8 *)&g_inFailureMode, buffer, size); /* line 1078 */

    return written;
}

TPM_RC
VolatileState_Unmarshal(BYTE **buffer, INT32 *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    UINT16 version;
    size_t i;

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT16_Unmarshal(&version, buffer, size); /* line 426 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM_HANDLE_Unmarshal(&g_exclusiveAuditSession, buffer, size); /* line 423 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&g_time, buffer, size); /* line 426 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&g_phEnable, buffer, size); /* line 439 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&g_pcrReConfig, buffer, size); /* line 443 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM_HANDLE_Unmarshal(&g_DRTMHandle, buffer, size); /* line 448 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&g_DrtmPreStartup, buffer, size); /* line 453 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&g_StartupLocality3, buffer, size); /* line 458 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&g_daUsed, buffer, size); /* line 484 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&g_powerWasLost, buffer, size); /* line 504 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT16_Unmarshal(&g_prevOrderlyState, buffer, size); /* line 516 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&g_nvOk, buffer, size); /* line 522 */
    }
#if 0 /* does not exist */
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_AUTH_Unmarshal(&g_platformUniqueAuthorities, buffer, size); /* line 535 */
    }
#endif
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_AUTH_Unmarshal(&g_platformUniqueDetails, buffer, size); /* line 536 */
    }

    if (rc == TPM_RC_SUCCESS) {
        rc = ORDERLY_DATA_Unmarshal(&go, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = STATE_CLEAR_DATA_Unmarshal(&gc, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
       rc = STATE_RESET_DATA_Unmarshal(&gr, buffer, size);
    }

    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&g_manufactured, buffer, size); /* line 928 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&g_initialized, buffer, size); /* line 932 */
    }

#if defined SESSION_PROCESS_C || defined GLOBAL_C || defined MANUFACTURE_C
    for (i = 0; i < ARRAY_SIZE(s_sessionHandles) && rc == TPM_RC_SUCCESS; i++) {
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM_HANDLE_Unmarshal(&s_sessionHandles[i], buffer, size);
        }
        if (rc == TPM_RC_SUCCESS) {
            rc = TPMA_SESSION_Unmarshal(&s_attributes[i], buffer, size);
        }
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM_HANDLE_Unmarshal(&s_associatedHandles[i], buffer, size);
        }
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2B_NONCE_Unmarshal(&s_nonceCaller[i], buffer, size);
        }
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2B_AUTH_Unmarshal(&s_inputAuthValues[i], buffer, size);
        }
    }

    if (rc == TPM_RC_SUCCESS) {
        rc = TPM_HANDLE_Unmarshal(&s_encryptSessionIndex, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM_HANDLE_Unmarshal(&s_decryptSessionIndex, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM_HANDLE_Unmarshal(&s_auditSessionIndex, buffer, size);
    }
#ifdef  TPM_CC_GetCommandAuditDigest
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2B_DIGEST_Unmarshal(&s_cpHashForCommandAudit, buffer, size);
    }
#endif
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&s_DAPendingOnNV, buffer, size);
    }
#endif
#ifndef ACCUMULATE_SELF_HEAL_TIMER
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&s_selfHealTimer, buffer, size); /* line 975 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&s_lockoutTimer, buffer, size); /* line 977 */
    }
#endif
#if defined NV_C || defined GLOBAL_C
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal(&s_evictNvEnd, buffer, size); /* line 984 */
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = Array_Unmarshal(s_indexOrderlyRam, sizeof(s_indexOrderlyRam), buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT64_Unmarshal(&s_maxCounter, buffer, size); /* line 992 */
    }
    /* not sure about the following; NvIndexCacheInit initializes them partly */
    if (rc == TPM_RC_SUCCESS) {
        //rc = NV_INDEX_Unmarshal(&s_cachedNvIndex, buffer, size); /* line 1003 */
    }
    if (rc == TPM_RC_SUCCESS) {
        //rc = UINT32_Unmarshal(&s_cachedNvRef, buffer, size); /* line 1004 */
    }
    if (rc == TPM_RC_SUCCESS) {
        //rc = UINT8_Unmarshal(s_cachedNvRamRef, buffer, size); /* line 1005 */
    }
#endif
#if defined OBJECT_C || defined GLOBAL_C
    for (i = 0; i < ARRAY_SIZE(s_objects) && rc == TPM_RC_SUCCESS; i++) {
        rc = OBJECT_Unmarshal(&s_objects[i], buffer, size);
    }
#endif

#if defined PCR_C || defined GLOBAL_C
    for (i = 0; i < ARRAY_SIZE(s_pcrs) && rc == TPM_RC_SUCCESS; i++) {
        rc = PCR_Unmarshal(&s_pcrs[i], buffer, size);
    }
#endif

#if defined SESSION_C || defined GLOBAL_C
    /* s_sessions: */
    for (i = 0; i < ARRAY_SIZE(s_sessions) && rc == TPM_RC_SUCCESS; i++) {
        rc = SESSION_SLOT_Unmarshal(&s_sessions[i], buffer, size);
    }
    /* s_oldestSavedSession: */
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal(&s_oldestSavedSession, buffer, size);
    }
    /* s_freeSessionSlots: */
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT32_Unmarshal((UINT32 *)&s_freeSessionSlots, buffer, size);
    }
#endif
    if (rc == TPM_RC_SUCCESS) {
        rc = UINT8_Unmarshal((UINT8 *)&g_inFailureMode, buffer, size); /* line 1078 */
    }

    return rc;
}

/*******************************************************************
  Functions to write NVRAM in big endian byte order

  Since the original TPM 2 code writes data structures into NVRAM
  we do the same but we endianess-swap the data on the way.
  Using endianess-swapping rather than marshalling avoids problems
  when the code later on tries to access fields of data structure
  using offsetof().
*******************************************************************/

/******** functions similar to those in Marshal.c *******/
static void
TPMU_SCHEME_KEYEDHASH_SWAP(TPMU_SCHEME_KEYEDHASH *t, TPMU_SCHEME_KEYEDHASH *s,
                           TPMI_ALG_KEYEDHASH_SCHEME type);

static inline void
TPM_KEY_BITS_SWAP(TPM_KEY_BITS *t, TPM_KEY_BITS *s)
{
    *t = htobe16(*s);
}

static inline void
TPM_ALG_ID_SWAP(TPM_ALG_ID *t, TPM_ALG_ID *s)
{
    *t = htobe16(*s);
}

static inline void
TPM_ECC_CURVE_SWAP(TPM_ECC_CURVE *t, TPM_ECC_CURVE *s)
{
    *t = htobe16(*s);
}

static inline void
TPMA_OBJECT_SWAP(TPMA_OBJECT *t, TPMA_OBJECT *s)
{
    UINT32 _t = htobe32(*(UINT32 *)s);
    *( UINT32 *)t = _t;
}

static inline void
TPMI_ALG_HASH_SWAP(TPMI_ALG_HASH *t, TPMI_ALG_HASH *s)
{
    TPM_ALG_ID_SWAP(t, s);
}

static inline void
TPMI_ALG_SYM_OBJECT_SWAP(TPMI_ALG_SYM_OBJECT *t, TPMI_ALG_SYM_OBJECT *s)
{
    TPM_ALG_ID_SWAP(t, s);
}

static inline void
TPMI_ALG_SYM_MODE_SWAP(TPMI_ALG_SYM_MODE *t, TPMI_ALG_SYM_MODE *s)
{
    TPM_ALG_ID_SWAP(t, s);
}

static inline void
TPMI_ALG_KDF_SWAP(TPMI_ALG_KDF *t, TPMI_ALG_KDF *s)
{
    TPM_ALG_ID_SWAP(t, s);
}

static void
TPMS_PCR_SELECTION_SWAP(TPMS_PCR_SELECTION *t, TPMS_PCR_SELECTION *s)
{
    TPMI_ALG_HASH_SWAP(&t->hash, &s->hash);
    t->sizeofSelect = s->sizeofSelect;
    memcpy(t->pcrSelect, s->pcrSelect, sizeof(t->pcrSelect));
}

static void
TPML_PCR_SELECTION_SWAP(TPML_PCR_SELECTION *t, TPML_PCR_SELECTION *s)
{
    size_t i;

    t->count = htobe32(s->count);
    for (i = 0; i < ARRAY_SIZE(t->pcrSelections); i++)
        TPMS_PCR_SELECTION_SWAP(&t->pcrSelections[i], &s->pcrSelections[i]);
}

static inline void
TPMI_AES_KEY_BITS_SWAP(TPMI_AES_KEY_BITS *t, TPMI_AES_KEY_BITS *s)
{
    TPM_KEY_BITS_SWAP(t, s);
}

static void
TPMU_SYM_KEY_BITS_SWAP(TPMU_SYM_KEY_BITS *t, TPMU_SYM_KEY_BITS *s,
                       TPMI_ALG_SYM type)
{
    switch (type) {
#ifdef TPM_ALG_AES
      case TPM_ALG_AES:
        TPMI_AES_KEY_BITS_SWAP(&t->aes, &s->aes);
	break;
#endif
#ifdef TPM_ALG_SM4
      case TPM_ALG_SM4:
        TPMI_SM4_KEY_BITS_SWAP(&t->sm4, &s->sm4);
	break;
#endif
#ifdef TPM_ALG_CAMELLIA
      case TPM_ALG_CAMELLIA:
        TPMI_CAMELLIA_KEY_BITS_SWAP(&t->camellia, &s->camellia);
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
        TPMI_ALG_HASH_SWAP(&t->xorr, &s->xorr);
	break;
#endif
      case TPM_ALG_NULL:
        break;
      default:
        pAssert(FALSE);
    }
}

static void
TPMU_SYM_MODE_SWAP(TPMU_SYM_MODE *t, TPMU_SYM_MODE *s, TPMI_ALG_SYM type)
{
    switch (type) {
#ifdef TPM_ALG_AES
      case TPM_ALG_AES:
        TPMI_ALG_SYM_MODE_SWAP(&t->aes, &s->aes);
	break;
#endif
#ifdef TPM_ALG_SM4
      case TPM_ALG_SM4:
        TPMI_ALG_SYM_MODE_SWAP(&t->sm4, &s->sm4);
	break;
#endif
#ifdef TPM_ALG_CAMELLIA
      case TPM_ALG_CAMELLIA:
        TPMI_ALG_SYM_MODE_SWAP(&t->camellia, &s->camellia);
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
#endif
      case TPM_ALG_NULL:
	break;
      default:
        pAssert(FALSE);
    }
}

static void
TPMT_SYM_DEF_OBJECT_SWAP(TPMT_SYM_DEF_OBJECT *t, TPMT_SYM_DEF_OBJECT *s,
                         bool to_native)
{
    TPMI_ALG_SYM_OBJECT_SWAP(&t->algorithm, &s->algorithm);
    TPMU_SYM_KEY_BITS_SWAP(&t->keyBits, &s->keyBits,
                           to_native ? t->algorithm : s->algorithm);
    TPMU_SYM_MODE_SWAP(&t->mode, &s->mode,
                       to_native ? t->algorithm : s->algorithm);
}

static inline void
TPMS_SYMCIPHER_PARMS_SWAP(TPMS_SYMCIPHER_PARMS *t, TPMS_SYMCIPHER_PARMS *s,
                          bool to_native)
{
    TPMT_SYM_DEF_OBJECT_SWAP(&t->sym, &s->sym, to_native);
}

static inline void
TPMS_SCHEME_HASH_SWAP(TPMS_SCHEME_HASH *t, TPMS_SCHEME_HASH *s)
{
    TPMI_ALG_HASH_SWAP(&t->hashAlg, &s->hashAlg);
}

static inline void
TPMS_SCHEME_ECDAA_SWAP(TPMS_SCHEME_ECDAA *t, TPMS_SCHEME_ECDAA *s)
{
    TPMI_ALG_HASH_SWAP(&t->hashAlg, &s->hashAlg);
    t->count = htobe16(s->count);
}

static inline void
TPMI_ALG_KEYEDHASH_SCHEME_SWAP(TPMI_ALG_KEYEDHASH_SCHEME *t, TPMI_ALG_KEYEDHASH_SCHEME *s)
{
    TPM_ALG_ID_SWAP(t, s);
}

static inline void
TPMS_SCHEME_HMAC_SWAP(TPMS_SCHEME_HMAC *t, TPMS_SCHEME_HMAC *s)
{
    TPMS_SCHEME_HASH_SWAP(t, s);
}

static inline void
TPMS_SCHEME_XOR_SWAP(TPMS_SCHEME_XOR *t, TPMS_SCHEME_XOR *s)
{
    TPMI_ALG_HASH_SWAP(&t->hashAlg, &s->hashAlg);
    TPMI_ALG_KDF_SWAP(&t->kdf, &s->kdf);
}

static inline void
TPMT_KEYEDHASH_SCHEME_SWAP(TPMT_KEYEDHASH_SCHEME *t, TPMT_KEYEDHASH_SCHEME *s,
                           bool to_native)
{
    TPMI_ALG_KEYEDHASH_SCHEME_SWAP(&t->scheme, &s->scheme);
    TPMU_SCHEME_KEYEDHASH_SWAP(&t->details, &s->details,
                               to_native ? t->scheme : s->scheme);
}

static inline void
TPMS_SIG_SCHEME_RSASSA_SWAP(TPMS_SIG_SCHEME_RSASSA *t, TPMS_SIG_SCHEME_RSASSA *s)
{
    TPMS_SCHEME_HASH_SWAP(t, s);
}

static inline void
TPMS_SIG_SCHEME_RSAPSS_SWAP(TPMS_SIG_SCHEME_RSAPSS *t, TPMS_SIG_SCHEME_RSAPSS *s)
{
    TPMS_SCHEME_HASH_SWAP(t, s);
}

static inline void
TPMS_SIG_SCHEME_ECDSA_SWAP(TPMS_SIG_SCHEME_ECDSA *t, TPMS_SIG_SCHEME_ECDSA *s)
{
    TPMS_SCHEME_HASH_SWAP(t, s);
}

static inline void
TPMS_SIG_SCHEME_ECSCHNORR_SWAP(TPMS_SIG_SCHEME_ECSCHNORR *t, TPMS_SIG_SCHEME_ECSCHNORR *s)
{
    TPMS_SCHEME_HASH_SWAP(t, s);
}

static inline void
TPMS_SIG_SCHEME_ECDAA_SWAP(TPMS_SIG_SCHEME_ECDAA *t, TPMS_SIG_SCHEME_ECDAA *s)
{
    TPMS_SCHEME_ECDAA_SWAP(t, s);
}

static inline void
TPMS_ENC_SCHEME_OAEP_SWAP(TPMS_ENC_SCHEME_OAEP *t, TPMS_ENC_SCHEME_OAEP *s)
{
    TPMS_SCHEME_HASH_SWAP(t, s);
}

static inline void
TPMS_ENC_SCHEME_RSAES_SWAP(TPMS_ENC_SCHEME_RSAES *t, TPMS_ENC_SCHEME_RSAES *s)
{
    // nothing to do
}

static void
TPMU_SCHEME_KEYEDHASH_SWAP(TPMU_SCHEME_KEYEDHASH *t, TPMU_SCHEME_KEYEDHASH *s,
                           TPMI_ALG_KEYEDHASH_SCHEME type)
{
    switch (type) {
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	TPMS_SCHEME_HMAC_SWAP(&t->hmac, &s->hmac);
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
        TPMS_SCHEME_XOR_SWAP(&t->xorr, &s->xorr);
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	pAssert(FALSE);
    }
}

static inline void
TPMS_KEY_SCHEME_ECDH_SWAP(TPMS_KEY_SCHEME_ECDH *t, TPMS_KEY_SCHEME_ECDH *s)
{
    TPMS_SCHEME_HASH_SWAP(t, s);
}

#ifdef TPM_ALG_MGF1
static inline void
TPMS_SCHEME_MGF1_SWAP(TPMS_SCHEME_MGF1 *t, TPMS_SCHEME_MGF1 *s)
{
   TPMS_SCHEME_HASH_SWAP(t, s);
}
#endif

#ifdef TPM_ALG_KDF1_SP800_56A
static inline void
TPMS_SCHEME_KDF1_SP800_56A_SWAP(TPMS_SCHEME_KDF1_SP800_56A *t, TPMS_SCHEME_KDF1_SP800_56A *s)
{
   TPMS_SCHEME_HASH_SWAP(t, s);
}
#endif

#ifdef TPM_ALG_KDF2
static inline void
TPMS_SCHEME_KDF2_SWAP(TPMS_SCHEME_KDF2 *t, TPMS_SCHEME_KDF2 *s)
{
   TPMS_SCHEME_HASH_SWAP(t, s);
}
#endif

#ifdef TPM_ALG_KDF1_SP800_108
static inline void
TPMS_SCHEME_KDF1_SP800_108_SWAP(TPMS_SCHEME_KDF1_SP800_108 *t,
                                TPMS_SCHEME_KDF1_SP800_108 *s)
{
   TPMS_SCHEME_HASH_SWAP(t, s);
}
#endif

static void
TPMU_KDF_SCHEME_SWAP(TPMU_KDF_SCHEME *t, TPMU_KDF_SCHEME *s,
                     TPMI_ALG_KDF type)
{
    switch (type) {
#ifdef TPM_ALG_MGF1
      case TPM_ALG_MGF1:
	TPMS_SCHEME_MGF1_SWAP(&t->mgf1, &s->mgf1);
	break;
#endif
#ifdef TPM_ALG_KDF1_SP800_56A
      case TPM_ALG_KDF1_SP800_56A:
	TPMS_SCHEME_KDF1_SP800_56A_SWAP(&t->kdf1_sp800_56a, &s->kdf1_sp800_56a);
	break;
#endif
#ifdef TPM_ALG_KDF2
      case TPM_ALG_KDF2:
	TPMS_SCHEME_KDF2_SWAP(&t->kdf2, &s->kdf2);
	break;
#endif
#ifdef TPM_ALG_KDF1_SP800_108
      case TPM_ALG_KDF1_SP800_108:
	TPMS_SCHEME_KDF1_SP800_108_SWAP(&t->kdf1_sp800_108, &s->kdf1_sp800_108);
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	pAssert(FALSE);
    }
}

static inline void
TPMT_KDF_SCHEME_SWAP(TPMT_KDF_SCHEME *t, TPMT_KDF_SCHEME *s,
                     bool to_native)
{
    TPMI_ALG_KDF_SWAP(&t->scheme, &s->scheme);
    TPMU_KDF_SCHEME_SWAP(&t->details, &s->details,
                         to_native ? t->scheme : s->scheme);
}

static void
TPMU_ASYM_SCHEME_SWAP(TPMU_ASYM_SCHEME *t, TPMU_ASYM_SCHEME *s,
                      TPMI_ALG_ASYM_SCHEME type)
{
    switch (type) {
#ifdef TPM_ALG_ECDH
      case TPM_ALG_ECDH:
	TPMS_KEY_SCHEME_ECDH_SWAP(&t->ecdh, &s->ecdh);
	break;
#endif
#ifdef TPM_ALG_ECMQV
      case TPM_ALG_ECMQV:
	TPMS_KEY_SCHEME_ECMQV_SWAP(&t->ecmqvh, &s->ecmqvh);
	break;
#endif
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	TPMS_SIG_SCHEME_RSASSA_SWAP(&t->rsassa, &s->rsassa);
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	TPMS_SIG_SCHEME_RSAPSS_SWAP(&t->rsapss, &s->rsapss);
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	TPMS_SIG_SCHEME_ECDSA_SWAP(&t->ecdsa, &s->ecdsa);
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	TPMS_SIG_SCHEME_ECDAA_SWAP(&t->ecdaa, &s->ecdaa);
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	TPMS_SIG_SCHEME_SM2_SWAP(&t->sm2, &s->sm2);
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	TPMS_SIG_SCHEME_ECSCHNORR_SWAP(&t->ecschnorr, &s->ecschnorr);
	break;
#endif
#ifdef TPM_ALG_RSAES
      case TPM_ALG_RSAES:
	TPMS_ENC_SCHEME_RSAES_SWAP(&t->rsaes, &s->rsaes);
	break;
#endif
#ifdef TPM_ALG_OAEP
      case TPM_ALG_OAEP:
	TPMS_ENC_SCHEME_OAEP_SWAP(&t->oaep, &s->oaep);
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	pAssert(FALSE);
    }
}

static inline void
TPMI_ALG_RSA_SCHEME_SWAP(TPMI_ALG_RSA_SCHEME *t, TPMI_ALG_RSA_SCHEME *s)
{
    TPM_ALG_ID_SWAP(t, s);
}

static inline void
TPMT_RSA_SCHEME_SWAP(TPMT_RSA_SCHEME *t, TPMT_RSA_SCHEME *s,
                     bool to_native)
{
    TPMI_ALG_RSA_SCHEME_SWAP(&t->scheme, &s->scheme);
    TPMU_ASYM_SCHEME_SWAP(&t->details, &s->details,
                          to_native ? t->scheme : s->scheme);
}

static inline void
TPMI_ALG_ECC_SCHEME_SWAP(TPMI_ALG_ECC_SCHEME *t, TPMI_ALG_ECC_SCHEME *s)
{
    TPM_ALG_ID_SWAP(t, s);
}

static inline void
TPMI_RSA_KEY_BITS_SWAP(TPMI_RSA_KEY_BITS *t, TPMI_RSA_KEY_BITS *s)
{
    TPM_KEY_BITS_SWAP(t, s);
}

static inline void
TPMS_ECC_POINT_SWAP(TPMS_ECC_POINT *t, TPMS_ECC_POINT *s)
{
    TPM2B_SWAP(&t->x.b, &s->x.b, sizeof(t->x.t.buffer));
    TPM2B_SWAP(&t->y.b, &s->y.b, sizeof(t->y.t.buffer));
}

static inline void
TPMI_ECC_CURVE_SWAP(TPMI_ECC_CURVE *t, TPMI_ECC_CURVE *s)
{
    TPM_ECC_CURVE_SWAP(t, s);
}

static inline void
TPMI_ALG_PUBLIC_SWAP(TPMI_ALG_PUBLIC *t, TPMI_ALG_PUBLIC *s)
{
    TPM_ALG_ID_SWAP(t, s);
}

static void
TPMU_PUBLIC_ID_SWAP(TPMU_PUBLIC_ID *t, TPMU_PUBLIC_ID *s,
                    TPMI_ALG_PUBLIC type)
{
    switch (type) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	TPM2B_SWAP(&t->keyedHash.b, &s->keyedHash.b, sizeof(t->keyedHash.t.buffer));
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	TPM2B_SWAP(&t->sym.b, &s->sym.b, sizeof(t->sym.t.buffer));
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	TPM2B_SWAP(&t->rsa.b, &s->rsa.b, sizeof(t->rsa.t.buffer));
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	TPMS_ECC_POINT_SWAP(&t->ecc, &s->ecc);
	break;
#endif
      default:
	pAssert(FALSE);
    }
}

static inline void
TPMT_ECC_SCHEME_SWAP(TPMT_ECC_SCHEME *t, TPMT_ECC_SCHEME *s,
                     bool to_native)
{
    TPMI_ALG_ECC_SCHEME_SWAP(&t->scheme, &s->scheme);
    TPMU_ASYM_SCHEME_SWAP(&t->details, &s->details,
                          to_native ? t->scheme : s->scheme);
}

static inline void
TPMS_KEYEDHASH_PARMS_SWAP(TPMS_KEYEDHASH_PARMS *t, TPMS_KEYEDHASH_PARMS *s,
                          bool to_native)
{
    TPMT_KEYEDHASH_SCHEME_SWAP(&t->scheme, &s->scheme, to_native);
}

static void
TPMS_RSA_PARMS_SWAP(TPMS_RSA_PARMS *t, TPMS_RSA_PARMS *s, bool to_native)
{
    TPMT_SYM_DEF_OBJECT_SWAP(&t->symmetric, &s->symmetric, to_native);
    TPMT_RSA_SCHEME_SWAP(&t->scheme, &s->scheme, to_native);
    TPMI_RSA_KEY_BITS_SWAP(&t->keyBits, &s->keyBits);
    t->exponent = htobe32(s->exponent);
}

#ifdef TPM_ALG_ECC
static void
TPMS_ECC_PARMS_SWAP(TPMS_ECC_PARMS *t, TPMS_ECC_PARMS *s, bool to_native)
{
    TPMT_SYM_DEF_OBJECT_SWAP(&t->symmetric, &s->symmetric, to_native);
    TPMT_ECC_SCHEME_SWAP(&t->scheme, &s->scheme, to_native);
    TPMI_ECC_CURVE_SWAP(&t->curveID, &s->curveID);
    TPMT_KDF_SCHEME_SWAP(&t->kdf, &s->kdf, to_native);
}
#endif

static void
TPMU_PUBLIC_PARMS_SWAP(TPMU_PUBLIC_PARMS *t, TPMU_PUBLIC_PARMS *s,
                       TPMI_ALG_PUBLIC type, bool to_native)
{
    switch (type) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
        TPMS_KEYEDHASH_PARMS_SWAP(&t->keyedHashDetail, &s->keyedHashDetail,
                                  to_native);
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	TPMS_SYMCIPHER_PARMS_SWAP(&t->symDetail, &s->symDetail, to_native);
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	TPMS_RSA_PARMS_SWAP(&t->rsaDetail, &s->rsaDetail, to_native);
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	TPMS_ECC_PARMS_SWAP(&t->eccDetail, &s->eccDetail, to_native);
	break;
#endif
      default:
	pAssert(FALSE);
    }
}

static void
TPMT_PUBLIC_SWAP(TPMT_PUBLIC *t, TPMT_PUBLIC *s, bool to_native)
{
    TPMI_ALG_PUBLIC_SWAP(&t->type, &s->type);
    TPMI_ALG_HASH_SWAP(&t->nameAlg, &s->nameAlg);
    TPMA_OBJECT_SWAP(&t->objectAttributes, &s->objectAttributes);
    TPM2B_SWAP(&t->authPolicy.b, &s->authPolicy.b, sizeof(t->authPolicy.t.buffer));
    TPMU_PUBLIC_PARMS_SWAP(&t->parameters, &s->parameters,
                           to_native ? t->type : s->type, to_native);
    TPMU_PUBLIC_ID_SWAP(&t->unique, &s->unique,
                        to_native ? t->type : s->type);
}

static void
TPMU_SENSITIVE_COMPOSITE_SWAP(TPMU_SENSITIVE_COMPOSITE *t, TPMU_SENSITIVE_COMPOSITE *s,
                              TPMI_ALG_PUBLIC type)
{
    switch (type) {
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	TPM2B_SWAP(&t->rsa.b, &s->rsa.b, sizeof(t->rsa.t.buffer));
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	TPM2B_SWAP(&t->ecc.b, &s->ecc.b, sizeof(t->ecc.t.buffer));
	break;
#endif
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	TPM2B_SWAP(&t->bits.b, &s->bits.b, sizeof(t->bits.t.buffer));
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	TPM2B_SWAP(&t->sym.b, &s->sym.b, sizeof(t->sym.t.buffer));
	break;
#endif
      default:
	pAssert(FALSE);
    }
}

static void
TPMT_SENSITIVE_SWAP(TPMT_SENSITIVE *t, TPMT_SENSITIVE *s, bool to_native)
{
    TPMI_ALG_PUBLIC_SWAP(&t->sensitiveType, &s->sensitiveType);
    TPM2B_SWAP(&t->authValue.b, &s->authValue.b,
               sizeof(t->authValue.t.buffer));
    TPM2B_SWAP(&t->seedValue.b, &s->seedValue.b,
               sizeof(t->seedValue.t.buffer));
    TPMU_SENSITIVE_COMPOSITE_SWAP(&t->sensitive, &s->sensitive,
                                  to_native ? t->sensitiveType
                                            : s->sensitiveType);
}

/************** Functions related to Global.h **********/

void
OBJECT_SWAP(OBJECT *t, OBJECT *s, bool to_native)
{
    UINT32 attributes, attributes_be;

    memcpy(&attributes, &s->attributes, sizeof(attributes));
    attributes_be = htobe32(attributes);

    memcpy(&t->attributes, &attributes_be, sizeof(t->attributes));

    TPMT_PUBLIC_SWAP(&t->publicArea, &s->publicArea, to_native);
    TPMT_SENSITIVE_SWAP(&t->sensitive, &s->sensitive, to_native);

#ifdef TPM_ALG_RSA
    privateExponent_t_SWAP(&t->privateExponent, &s->privateExponent);
#endif
    TPM2B_SWAP(&t->qualifiedName.b, &s->qualifiedName.b,
               sizeof(t->qualifiedName.t.name));
    t->evictHandle = htobe32(s->evictHandle);
    TPM2B_SWAP(&t->name.b, &s->name.b, sizeof(t->name.t.name));
}

static void
PCR_SAVE_SWAP(PCR_SAVE *t, PCR_SAVE *s)
{
#ifdef TPM_ALG_SHA1
    memcpy(&t->sha1, s->sha1, sizeof(t->sha1));
#endif
#ifdef TPM_ALG_SHA256
    memcpy(&t->sha256, s->sha256, sizeof(t->sha256));
#endif
#ifdef TPM_ALG_SHA384
    memcpy(&t->sha384, s->sha384, sizeof(t->sha384));
#endif
#ifdef TPM_ALG_SHA512
    memcpy(&t->sha512, s->sha512, sizeof(t->sha512));
#endif
#ifdef TPM_ALG_SM3_256
    memcpy(&t->sm3_256, s->sm3_256, sizeof(t->sm3_256));
#endif
    t->pcrCounter = htobe32(s->pcrCounter);
}

static void
PCR_POLICY_SWAP(PCR_POLICY *t, PCR_POLICY *s)
{
    size_t i;

#if NUM_POLICY_PCR_GROUP > 0	/* kgold added to prevent zero size array */
    for (i = 0; i < ARRAY_SIZE(t->hashAlg); i++) {
        TPMI_ALG_HASH_SWAP(&t->hashAlg[i], &s->hashAlg[i]);
    }
#endif

#if 0
    // 'a' is not being used and not initialized anywhere ...
    TPM2B_SWAP(&t->a.b, &s->a.b, sizeof(t->a.t.buffer))
#endif

#if NUM_POLICY_PCR_GROUP > 0	/* kgold added to prevent zero size array */
    for (i = 0; i < ARRAY_SIZE(t->policy); i++) {
        TPM2B_SWAP(&t->policy[i].b, &s->policy[i].b,
                   sizeof(t->policy[i].t.buffer));
    }
#endif
}

static void
TPMS_NV_PUBLIC_SWAP(TPMS_NV_PUBLIC *t, TPMS_NV_PUBLIC *s)
{
    UINT32 attributes_be;

    t->nvIndex = htobe32(s->nvIndex);
    TPM_ALG_ID_SWAP(&t->nameAlg, &s->nameAlg);

    attributes_be = htobe32(*(UINT32 *)&s->attributes);
    memcpy(&t->attributes, &attributes_be, sizeof(t->attributes));
    TPM2B_SWAP(&t->authPolicy.b, &s->authPolicy.b,
               sizeof(t->authPolicy.t.buffer));
    t->dataSize = htobe16(s->dataSize);
}

void
NV_INDEX_SWAP(NV_INDEX *t, NV_INDEX *s)
{
    TPMS_NV_PUBLIC_SWAP(&t->publicArea, &s->publicArea);
    TPM2B_SWAP(&t->authValue.b, &s->authValue.b, sizeof(t->authValue.t.buffer));
}

static void
PERSISTENT_DATA_SWAP(PERSISTENT_DATA *t, PERSISTENT_DATA *s)
{
    t->disableClear = s->disableClear;

    TPM_ALG_ID_SWAP(&t->ownerAlg, &s->ownerAlg);
    TPM_ALG_ID_SWAP(&t->endorsementAlg, &s->endorsementAlg);
    TPM_ALG_ID_SWAP(&t->lockoutAlg, &s->lockoutAlg);

    TPM2B_SWAP(&t->ownerPolicy.b, &s->ownerPolicy.b,
               sizeof(t->ownerPolicy.t.buffer));
    TPM2B_SWAP(&t->endorsementPolicy.b, &s->endorsementPolicy.b,
               sizeof(t->endorsementPolicy.t.buffer));
    TPM2B_SWAP(&t->lockoutPolicy.b, &s->lockoutPolicy.b,
               sizeof(t->lockoutPolicy.t.buffer));

    TPM2B_SWAP(&t->ownerAuth.b, &s->ownerAuth.b, sizeof(t->ownerAuth.t.buffer));
    TPM2B_SWAP(&t->endorsementAuth.b, &s->endorsementAuth.b, sizeof(t->endorsementAuth.t.buffer));
    TPM2B_SWAP(&t->lockoutAuth.b, &s->lockoutAuth.b, sizeof(t->lockoutAuth.t.buffer));

    TPM2B_SWAP(&t->EPSeed.b, &s->EPSeed.b, sizeof(t->EPSeed.t.buffer));
    TPM2B_SWAP(&t->SPSeed.b, &s->SPSeed.b, sizeof(t->SPSeed.t.buffer));
    TPM2B_SWAP(&t->PPSeed.b, &s->PPSeed.b, sizeof(t->PPSeed.t.buffer));

    TPM2B_SWAP(&t->phProof.b, &s->phProof.b, sizeof(t->phProof.t.buffer));
    TPM2B_SWAP(&t->shProof.b, &s->shProof.b, sizeof(t->shProof.t.buffer));
    TPM2B_SWAP(&t->ehProof.b, &s->ehProof.b, sizeof(t->ehProof.t.buffer));

    t->totalResetCount = htobe64(s->totalResetCount);

    t->resetCount = htobe32(s->resetCount);

#if defined NUM_POLICY_PCR_GROUP && NUM_POLICY_PCR_GROUP > 0
    PCR_POLICY_SWAP(&t->pcrPolicies, &s->pcrPolicies);
#endif

    TPML_PCR_SELECTION_SWAP(&t->pcrAllocated, &s->pcrAllocated);

    memcpy(t->ppList, s->ppList, sizeof(t->ppList));

    t->failedTries = htobe32(s->failedTries);
    t->maxTries = htobe32(s->maxTries);

    t->recoveryTime = htobe32(s->recoveryTime);
    t->lockoutRecovery = htobe32(s->lockoutRecovery);

    t->lockOutAuthEnabled = s->lockOutAuthEnabled;

    t->orderlyState = htobe16(s->orderlyState);

    memcpy(t->auditCommands, s->auditCommands, sizeof(t->auditCommands));
    TPM_ALG_ID_SWAP(&t->auditHashAlg, &s->auditHashAlg);
    t->auditCounter = htobe64(s->auditCounter);

    t->algorithmSet = htobe32(s->algorithmSet);

    t->firmwareV1 = htobe32(s->firmwareV1);
    t->firmwareV2 = htobe32(s->firmwareV2);

#ifndef CLOCK_STOPS
    t->timeEpoch = htobe32(s->timeEpoch);
#endif
}

static void
ORDERLY_DATA_SWAP(ORDERLY_DATA *t, ORDERLY_DATA *s)
{
    t->clock = htobe64(s->clock);
    t->clockSafe = s->clockSafe;

    DRBG_STATE_SWAP(&t->drbgState, &s->drbgState);

#ifdef ACCUMULATE_SELF_HEAL_TIMER
    t->selfHealTimer = htobe64(s->selfHealTimer);
    t->lockoutTimer = htobe64(s->lockoutTimer);
    t->time = htobe64(s->time);
#endif
}

static void
STATE_CLEAR_DATA_SWAP(STATE_CLEAR_DATA *t, STATE_CLEAR_DATA *s)
{
    t->shEnable = s->shEnable;
    t->ehEnable = s->ehEnable;
    t->phEnableNV = s->phEnableNV;

    TPM_ALG_ID_SWAP(&t->platformAlg, &s->platformAlg);

    TPM2B_SWAP(&t->platformPolicy.b, &s->platformPolicy.b,
               sizeof(t->platformPolicy.t.buffer));
    TPM2B_SWAP(&t->platformAuth.b, &s->platformAuth.b,
               sizeof(t->platformAuth.t.buffer));

    PCR_SAVE_SWAP(&t->pcrSave, &s->pcrSave);

    PCR_AUTHVALUE_SWAP(&t->pcrAuthValues, &s->pcrAuthValues);
}

static void
STATE_RESET_DATA_SWAP(STATE_RESET_DATA *t, STATE_RESET_DATA *s)
{
    TPM2B_SWAP(&t->nullProof.b, &s->nullProof.b, sizeof(t->nullProof.t.buffer));

    TPM2B_SWAP(&t->nullSeed.b, &s->nullSeed.b, sizeof(t->nullSeed.t.buffer));

    t->clearCount = htobe32(s->clearCount);
    t->objectContextID = htobe64(s->objectContextID);
    memcpy(t->contextArray, s->contextArray, sizeof(t->contextArray));

    t->contextCounter = htobe64(s->contextCounter);

    TPM2B_SWAP(&t->commandAuditDigest.b, &s->commandAuditDigest.b,
               sizeof(t->commandAuditDigest.t.buffer));

    t->restartCount = htobe32(s->restartCount);
    t->pcrCounter = htobe32(s->pcrCounter);

#ifdef TPM_ALG_ECC
    t->commitCounter = htobe64(s->commitCounter);
    TPM2B_SWAP(&t->commitNonce.b, &s->commitNonce.b,
               sizeof(t->commitNonce.t.buffer));
    memcpy(t->commitArray, s->commitArray, sizeof(t->commitArray));
#endif
}

/************** functions related to NV.h ********/

static void
NV_ENTRY_HEADER_SWAP(NV_ENTRY_HEADER *t, NV_ENTRY_HEADER *s)
{
    t->size = htobe32(s->size);
    t->handle = htobe32(s->handle);
}

void
TPMA_NV_SWAP(TPMA_NV *t, TPMA_NV *s)
{
    UINT32 _t = htobe32(*(UINT32 *)s);

    *(UINT32 *)t = _t;
}

void
NV_LIST_TERMINATOR_SWAP(NV_LIST_TERMINATOR *t, NV_LIST_TERMINATOR *s)
{
    t->reserved = htobe32(s->reserved);
    t->maxCount = htobe64(s->maxCount);
}

/***** functions to write structs to NVRAM ******/

void
NvWrite_NV_LIST_TERMINATOR(UINT32 nvOffset, UINT32 size, NV_LIST_TERMINATOR *s)
{
    NV_LIST_TERMINATOR t;

    NV_LIST_TERMINATOR_SWAP(&t, s);

    NvWrite(nvOffset, size, &t);
}

void
NvWrite_TPM_HANDLE(UINT32 nvOffset, UINT32 size, TPM_HANDLE *data)
{
    TPM_HANDLE t = htobe32(*data);

    NvWrite(nvOffset, size, &t);
}

void
NvWrite_UINT32(UINT32 nvOffset, UINT32 size, UINT32 *data)
{
    UINT32 t = htobe32(*data);

    NvWrite(nvOffset, size, &t);
}

void
NvRead_UINT32(UINT32 *data, UINT32 nvOffset, UINT32 size)
{
    UINT32 t;

    NvRead(&t, nvOffset, size);

    *data = be32toh(t);
}

void
NvRead_UINT64(UINT64 *data, UINT32 nvOffset, UINT32 size)
{
    UINT64 t;

    NvRead(&t, nvOffset, size);

    *data = be64toh(t);
}

void
NvWrite_PERSISTENT_DATA(UINT32 nvOffset, UINT32 size, PERSISTENT_DATA *data)
{
    PERSISTENT_DATA t;

    PERSISTENT_DATA_SWAP(&t, data);

    NvWrite(nvOffset, size, &t);
}

void
NvRead_PERSISTENT_DATA(PERSISTENT_DATA *data, UINT32 nvOffset, UINT32 size)
{
    PERSISTENT_DATA t;

    NvRead(&t, nvOffset, size);

    PERSISTENT_DATA_SWAP(data, &t);
}

void
NvWrite_ORDERLY_DATA(UINT32 nvOffset, UINT32 size, ORDERLY_DATA *data)
{
    ORDERLY_DATA t;

    ORDERLY_DATA_SWAP(&t, data);

    NvWrite(nvOffset, size, &t);
}

void
NvRead_ORDERLY_DATA(ORDERLY_DATA *data, UINT32 nvOffset, UINT32 size)
{
    ORDERLY_DATA t;

    NvRead(&t, nvOffset, size);

    ORDERLY_DATA_SWAP(data, &t);
}

void
NvWrite_STATE_CLEAR_DATA(UINT32 nvOffset, UINT32 size, STATE_CLEAR_DATA *data)
{
    STATE_CLEAR_DATA t;

    STATE_CLEAR_DATA_SWAP(&t, data);

    NvWrite(nvOffset, size, &t);
}

void
NvRead_STATE_CLEAR_DATA(STATE_CLEAR_DATA *data, UINT32 nvOffset, UINT32 size)
{
    STATE_CLEAR_DATA t;

    NvRead(&t, nvOffset, size);

    STATE_CLEAR_DATA_SWAP(data, &t);
}

void
NvWrite_STATE_RESET_DATA(UINT32 nvOffset, UINT32 size, STATE_RESET_DATA *data)
{
    STATE_RESET_DATA t;

    STATE_RESET_DATA_SWAP(&t, data);

    NvWrite(nvOffset, size, &t);
}

void
NvRead_STATE_RESET_DATA(STATE_RESET_DATA *data, UINT32 nvOffset, UINT32 size)
{
    STATE_RESET_DATA t;

    NvRead(&t, nvOffset, size);

    STATE_RESET_DATA_SWAP(data, &t);
}

void
NvRead_OBJECT_ATTRIBUTES(OBJECT_ATTRIBUTES *data, UINT32 nvOffset, UINT32 size)
{
    UINT32 t;

    assert(sizeof(*data) == 4);

    NvRead(&t, nvOffset, size);

    *(UINT32 *)data = be32toh(t);
}

void
NvRead_OBJECT(OBJECT *data, UINT32 nvOffset, UINT32 size)
{
    OBJECT t;

    NvRead(&t, nvOffset, size);

    OBJECT_SWAP(data, &t, TRUE);
}

void
NvRead_TPMA_NV(TPMA_NV *data, UINT32 nvOffset, UINT32 size)
{
    TPMA_NV t;

    assert(sizeof(*data) == 4);

    NvRead(&t, nvOffset, size);

    TPMA_NV_SWAP(data, &t);
}

void
NvWrite_NV_INDEX(UINT32 nvOffset, UINT32 size, NV_INDEX *data)
{
    NV_INDEX t;

    NV_INDEX_SWAP(&t, data);

    NvWrite(nvOffset, size, &t);
}

void
NvRead_NV_INDEX(NV_INDEX *data, UINT32 nvOffset, UINT32 size)
{
    NV_INDEX t;

    NvRead(&t, nvOffset, size);

    NV_INDEX_SWAP(data, &t);
}

void
NvRead_NV_ENTRY_HEADER(NV_ENTRY_HEADER *data, UINT32 nvOffset, UINT32 size)
{
    NV_ENTRY_HEADER t;

    NvRead(&t, nvOffset, size);

    NV_ENTRY_HEADER_SWAP(data, &t);
}

void
NvWrite_Array(UINT32 nvOffset, UINT32 size, BYTE *data)
{
    NvWrite(nvOffset, size, data);
}
