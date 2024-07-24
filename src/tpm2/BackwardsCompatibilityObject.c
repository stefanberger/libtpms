/********************************************************************************/
/*										*/
/*		Backwards compatibility stuff related to OBJECT		*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2017,2018.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
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
/********************************************************************************/

#include <assert.h>

#include "BackwardsCompatibilityObject.h"

/* The following are data structure from libtpms 0.7.x with RSA 2048 support
 * that help to resume key and hash contexts (TPM2_ContextSave/Load) from this
 * earlier version. All structures that have different sizes in 0.8 are found
 * here.
 */
typedef union {
    struct {
	UINT16                  size;
	BYTE                    buffer[2048/8];
    }            t;
    TPM2B        b;
} RSA2048_TPM2B_PUBLIC_KEY_RSA;

typedef union {
    TPM2B_DIGEST                 keyedHash;
    TPM2B_DIGEST                 sym;
    RSA2048_TPM2B_PUBLIC_KEY_RSA rsa;
    TPMS_ECC_POINT               ecc;
//    TPMS_DERIVE                derive;
} RSA2048_TPMU_PUBLIC_ID;

typedef struct {
    TPMI_ALG_PUBLIC         type;
    TPMI_ALG_HASH           nameAlg;
    TPMA_OBJECT             objectAttributes;
    TPM2B_DIGEST            authPolicy;
    TPMU_PUBLIC_PARMS       parameters;
    RSA2048_TPMU_PUBLIC_ID  unique;
} RSA2048_TPMT_PUBLIC;

MUST_BE(sizeof(RSA2048_TPMT_PUBLIC) == 356);

typedef union {
    struct {
	UINT16                  size;
	BYTE                    buffer[((2048/8)/2)*5];
    }            t;
    TPM2B        b;
} RSA2048_TPM2B_PRIVATE_KEY_RSA;

MUST_BE(sizeof(RSA2048_TPM2B_PRIVATE_KEY_RSA) == 642);

typedef union {
    struct {
	UINT16                  size;
	BYTE                    buffer[((2048/8)/2)*5];
    }            t;
    TPM2B        b;
} RSA2048_TPM2B_PRIVATE_VENDOR_SPECIFIC;

typedef union {
    RSA2048_TPM2B_PRIVATE_KEY_RSA         rsa;
    TPM2B_ECC_PARAMETER                   ecc;
    TPM2B_SENSITIVE_DATA                  bits;
    TPM2B_SYM_KEY                         sym;
    RSA2048_TPM2B_PRIVATE_VENDOR_SPECIFIC any;
} RSA2048_TPMU_SENSITIVE_COMPOSITE;

typedef struct {
    TPMI_ALG_PUBLIC                  sensitiveType;
    TPM2B_AUTH                       authValue;
    TPM2B_DIGEST                     seedValue;
    RSA2048_TPMU_SENSITIVE_COMPOSITE sensitive;
} RSA2048_TPMT_SENSITIVE;

MUST_BE(sizeof(RSA2048_TPMT_SENSITIVE) == 776);

BN_TYPE(old_prime, (2048 / 2));

typedef struct RSA2048_privateExponent
{
    bn_old_prime_t          Q;
    bn_old_prime_t          dP;
    bn_old_prime_t          dQ;
    bn_old_prime_t          qInv;
} RSA2048_privateExponent_t;

static inline void CopyFromOldPrimeT(ci_prime_t *dst,
				     const bn_old_prime_t *src)
{
    dst->allocated = src->allocated;
    dst->size = src->size;
    memcpy(dst->d, src->d, sizeof(src->d));
}

MUST_BE(sizeof(RSA2048_privateExponent_t) == 608);

typedef struct RSA2048_OBJECT
{
    // The attributes field is required to be first followed by the publicArea.
    // This allows the overlay of the object structure and a sequence structure
    OBJECT_ATTRIBUTES   attributes;         // object attributes
    RSA2048_TPMT_PUBLIC     publicArea;         // public area of an object
    RSA2048_TPMT_SENSITIVE  sensitive;          // sensitive area of an object
    RSA2048_privateExponent_t privateExponent;  // Additional field for the private
    TPM2B_NAME          qualifiedName;      // object qualified name
    TPMI_DH_OBJECT      evictHandle;        // if the object is an evict object,
    // the original handle is kept here.
    // The 'working' handle will be the
    // handle of an object slot.
    TPM2B_NAME          name;               // Name of the object name. Kept here
    // to avoid repeatedly computing it.

    // libtpms added: OBJECT lies in NVRAM; to avoid that it needs different number
    // of bytes on 32 bit and 64 bit architectures, we need to make sure it's the
    // same size; simple padding at the end works here
    UINT32             _pad;
} RSA2048_OBJECT;

MUST_BE(sizeof(RSA2048_OBJECT) == 1896);

TPMI_RH_HIERARCHY ObjectGetHierarchyFromAttributes(OBJECT* object)
{
    if(object->attributes.spsHierarchy)
	return TPM_RH_OWNER;

    if(object->attributes.epsHierarchy)
	return TPM_RH_ENDORSEMENT;

    if(object->attributes.ppsHierarchy)
	return TPM_RH_PLATFORM;

    return TPM_RH_NULL;
}

static void RSA2048_OBJECT_To_OBJECT(OBJECT* dest, const RSA2048_OBJECT* src)
{
    dest->attributes = src->attributes;
    dest->hierarchy = ObjectGetHierarchyFromAttributes(dest);

    dest->publicArea.type = src->publicArea.type;
    dest->publicArea.nameAlg = src->publicArea.nameAlg;
    dest->publicArea.objectAttributes = src->publicArea.objectAttributes;
    dest->publicArea.authPolicy = src->publicArea.authPolicy;
    dest->publicArea.parameters = src->publicArea.parameters;
    /* the unique part can be one or two TPM2B's */
    switch (dest->publicArea.type) {
    case TPM_ALG_KEYEDHASH:
	MemoryCopy2B(&dest->publicArea.unique.keyedHash.b,
		     &src->publicArea.unique.keyedHash.b,
		     sizeof(src->publicArea.unique.keyedHash.t.buffer));
	memset(&dest->privateExponent, 0, sizeof(dest->privateExponent));
	break;
    case TPM_ALG_SYMCIPHER:
	MemoryCopy2B(&dest->publicArea.unique.sym.b,
		     &src->publicArea.unique.sym.b,
		     sizeof(src->publicArea.unique.sym.t.buffer));
	memset(&dest->privateExponent, 0, sizeof(dest->privateExponent));
	break;
    case TPM_ALG_RSA:
	MemoryCopy2B(&dest->publicArea.unique.rsa.b,
		     &src->publicArea.unique.rsa.b,
		     sizeof(src->publicArea.unique.rsa.t.buffer));

	CopyFromOldPrimeT(&dest->privateExponent.Q, &src->privateExponent.Q);
	CopyFromOldPrimeT(&dest->privateExponent.dP, &src->privateExponent.dP);
	CopyFromOldPrimeT(&dest->privateExponent.dQ, &src->privateExponent.dQ);
	CopyFromOldPrimeT(&dest->privateExponent.qInv, &src->privateExponent.qInv);
	break;
    case TPM_ALG_ECC:
	MemoryCopy2B(&dest->publicArea.unique.ecc.x.b,
		     &src->publicArea.unique.ecc.x.b,
		     sizeof(src->publicArea.unique.ecc.x.t.buffer));
	MemoryCopy2B(&dest->publicArea.unique.ecc.y.b,
		     &src->publicArea.unique.ecc.y.b,
		     sizeof(src->publicArea.unique.ecc.y.t.buffer));
	memset(&dest->privateExponent, 0, sizeof(dest->privateExponent));
	break;
    }

    dest->sensitive.sensitiveType = src->sensitive.sensitiveType;
    dest->sensitive.authValue = src->sensitive.authValue;
    dest->sensitive.seedValue = src->sensitive.seedValue;
    /* The RSA2048_TPMU_SENSITIVE_COMPOSITE is always a TPM2B */
    MemoryCopy2B(&dest->sensitive.sensitive.any.b,
		 &src->sensitive.sensitive.any.b,
		 sizeof(src->sensitive.sensitive.any.t.buffer));

    dest->qualifiedName = src->qualifiedName;
    dest->evictHandle = src->evictHandle;
    dest->name = src->name;
}

// Convert an RSA2048_OBJECT that was copied into buffer using MemoryCopy
TPM_RC
RSA2048_OBJECT_Buffer_To_OBJECT(OBJECT* newObject, BYTE* buffer, INT32 size)
{
    RSA2048_OBJECT    oldObject;
    TPM_RC        rc = 0;

    // get the attributes
    MemoryCopy(newObject, buffer, sizeof(newObject->attributes));
    if (ObjectIsSequence(newObject))
	{
	    /* resuming old hash contexts is not supported */
	    rc = TPM_RC_DISABLED;
	}
    else
        {
	    if (size != sizeof(RSA2048_OBJECT))
		return TPM_RC_SIZE;
	    MemoryCopy(&oldObject, buffer, sizeof(RSA2048_OBJECT));

	    /* fill the newObject with the contents of the oldObject */
	    RSA2048_OBJECT_To_OBJECT(newObject, &oldObject);
    }

    return rc;
}

/* The following are data structure from libtpms 0.9.x with RSA 3072 support.
 */
typedef union {
    struct {
	UINT16                  size;
	BYTE                    buffer[3072/8];
    }            t;
    TPM2B        b;
} RSA3072_TPM2B_PUBLIC_KEY_RSA;

typedef union {
    TPM2B_DIGEST                 keyedHash;
    TPM2B_DIGEST                 sym;
    RSA3072_TPM2B_PUBLIC_KEY_RSA rsa;
    TPMS_ECC_POINT               ecc;
    TPMS_DERIVE                  derive;
} RSA3072_TPMU_PUBLIC_ID;
MUST_BE(sizeof(TPM2B_DIGEST) == 2 + BITS_TO_BYTES(512));
MUST_BE(sizeof(TPMS_ECC_POINT) == 2 * (2 + BITS_TO_BYTES(638)));
MUST_BE(sizeof(TPMS_DERIVE) == 2 * (2 + 32));

typedef struct {
    TPMI_ALG_PUBLIC         type;
    TPMI_ALG_HASH           nameAlg;
    TPMA_OBJECT             objectAttributes;
    TPM2B_DIGEST            authPolicy;
    TPMU_PUBLIC_PARMS       parameters;
    RSA3072_TPMU_PUBLIC_ID          unique;
} RSA3072_TPMT_PUBLIC;
MUST_BE(sizeof(RSA3072_TPMT_PUBLIC) == 484);

typedef union {
    struct {
	UINT16                  size;
	BYTE                    buffer[((3072 / 8) / 2) * 5];
    }            t;
    TPM2B        b;
} RSA3072_TPM2B_PRIVATE_KEY_RSA;
MUST_BE(sizeof(RSA3072_TPM2B_PRIVATE_KEY_RSA) == 962);

typedef union {
    struct {
	UINT16                  size;
	BYTE                    buffer[((3072 / 8) / 2) * 5];
    }            t;
    TPM2B        b;
} RSA3072_TPM2B_PRIVATE_VENDOR_SPECIFIC;

typedef union {
    RSA3072_TPM2B_PRIVATE_KEY_RSA         rsa;
    TPM2B_ECC_PARAMETER                   ecc;
    TPM2B_SENSITIVE_DATA                  bits;
    TPM2B_SYM_KEY                         sym;
    RSA3072_TPM2B_PRIVATE_VENDOR_SPECIFIC any;
} RSA3072_TPMU_SENSITIVE_COMPOSITE;
MUST_BE(sizeof(TPM2B_ECC_PARAMETER) == 2 + BITS_TO_BYTES(638) /* BN P638 */);
MUST_BE(sizeof(TPM2B_SENSITIVE_DATA) == 2 + 128);
MUST_BE(sizeof(TPM2B_SYM_KEY) == 2 + BITS_TO_BYTES(256));

typedef struct {
    TPMI_ALG_PUBLIC             sensitiveType;
    TPM2B_AUTH                  authValue;
    TPM2B_DIGEST                seedValue;
    RSA3072_TPMU_SENSITIVE_COMPOSITE    sensitive;
} RSA3072_TPMT_SENSITIVE;
MUST_BE(sizeof(TPM2B_AUTH) == 2 + BITS_TO_BYTES(512));
MUST_BE(sizeof(TPM2B_DIGEST) == 2 + BITS_TO_BYTES(512));
MUST_BE(sizeof(RSA3072_TPMT_SENSITIVE) == 1096);

BN_TYPE(rsa3072_prime, (3072 / 2));

typedef struct RSA3072_privateExponent
{
    bn_rsa3072_prime_t          Q;
    bn_rsa3072_prime_t          dP;
    bn_rsa3072_prime_t          dQ;
    bn_rsa3072_prime_t          qInv;
} RSA3072_privateExponent_t;
MUST_BE(sizeof(RSA3072_privateExponent_t) == 864);

typedef struct RSA3072_OBJECT
{
    // The attributes field is required to be first followed by the publicArea.
    // This allows the overlay of the object structure and a sequence structure
    OBJECT_ATTRIBUTES     attributes;     // object attributes
    RSA3072_TPMT_PUBLIC     publicArea;     // public area of an object
    RSA3072_TPMT_SENSITIVE  sensitive;      // sensitive area of an object
#if 1					// libtpms added begin: keep
    RSA3072_privateExponent_t privateExponent;    // Additional field for the private
#endif					// libtpms added end
    TPM2B_NAME        qualifiedName;  // object qualified name
    TPMI_DH_OBJECT    evictHandle;    // if the object is an evict object,
    // the original handle is kept here.
    // The 'working' handle will be the
    // handle of an object slot.
    TPM2B_NAME name;                  // Name of the object name. Kept here
    // to avoid repeatedly computing it.

    // libtpms added: SEED_COMPAT_LEVEL to use for deriving child keys
    SEED_COMPAT_LEVEL   seedCompatLevel;
    // libtpms added: OBJECT lies in NVRAM; to avoid that it needs different number
    // of bytes on 32 bit and 64 bit architectures, we need to make sure it's the
    // same size; simple padding at the end works here
    UINT8               _pad[3];
} RSA3072_OBJECT;
MUST_BE(sizeof(RSA3072_OBJECT) == 2600);

static inline void CopyFromRSA3072PrimeT(ci_prime_t* dst,
				       const bn_rsa3072_prime_t* src)
{
    dst->allocated = src->allocated;
    dst->size = src->size;
    memcpy(dst->d, src->d, sizeof(src->d));
}

static inline void CopyToRSA3072PrimeT(bn_rsa3072_prime_t* dst,
                                       const ci_prime_t* src)
{
    dst->allocated = src->allocated;
    dst->size = src->size;
    memcpy(dst->d, src->d, sizeof(dst->d));
}

static void RSA3072_OBJECT_To_OBJECT(OBJECT* dest, const RSA3072_OBJECT* src)
{
    dest->attributes = src->attributes;
    dest->hierarchy = ObjectGetHierarchyFromAttributes(dest);

    dest->publicArea.type = src->publicArea.type;
    dest->publicArea.nameAlg = src->publicArea.nameAlg;
    dest->publicArea.objectAttributes = src->publicArea.objectAttributes;
    dest->publicArea.authPolicy = src->publicArea.authPolicy;
    dest->publicArea.parameters = src->publicArea.parameters;
    /* the unique part can be one or two TPM2B's */
    switch (dest->publicArea.type) {
    case TPM_ALG_KEYEDHASH:
	MemoryCopy2B(&dest->publicArea.unique.keyedHash.b,
		     &src->publicArea.unique.keyedHash.b,
		     sizeof(src->publicArea.unique.keyedHash.t.buffer));
	memset(&dest->privateExponent, 0, sizeof(dest->privateExponent));
	break;
    case TPM_ALG_SYMCIPHER:
	MemoryCopy2B(&dest->publicArea.unique.sym.b,
		     &src->publicArea.unique.sym.b,
		     sizeof(src->publicArea.unique.sym.t.buffer));
	memset(&dest->privateExponent, 0, sizeof(dest->privateExponent));
	break;
    case TPM_ALG_RSA:
	MemoryCopy2B(&dest->publicArea.unique.rsa.b,
		     &src->publicArea.unique.rsa.b,
		     sizeof(src->publicArea.unique.rsa.t.buffer));

	CopyFromRSA3072PrimeT(&dest->privateExponent.Q, &src->privateExponent.Q);
	CopyFromRSA3072PrimeT(&dest->privateExponent.dP, &src->privateExponent.dP);
	CopyFromRSA3072PrimeT(&dest->privateExponent.dQ, &src->privateExponent.dQ);
	CopyFromRSA3072PrimeT(&dest->privateExponent.qInv, &src->privateExponent.qInv);
	break;
    case TPM_ALG_ECC:
	MemoryCopy2B(&dest->publicArea.unique.ecc.x.b,
		     &src->publicArea.unique.ecc.x.b,
		     sizeof(src->publicArea.unique.ecc.x.t.buffer));
	MemoryCopy2B(&dest->publicArea.unique.ecc.y.b,
		     &src->publicArea.unique.ecc.y.b,
		     sizeof(src->publicArea.unique.ecc.y.t.buffer));
	memset(&dest->privateExponent, 0, sizeof(dest->privateExponent));
	break;
    }

    dest->sensitive.sensitiveType = src->sensitive.sensitiveType;
    dest->sensitive.authValue = src->sensitive.authValue;
    dest->sensitive.seedValue = src->sensitive.seedValue;
    /* The OLD_TPMU_SENSITIVE_COMPOSITE is always a TPM2B */
    MemoryCopy2B(&dest->sensitive.sensitive.any.b,
		 &src->sensitive.sensitive.any.b,
		 sizeof(src->sensitive.sensitive.any.t.buffer));

    dest->qualifiedName = src->qualifiedName;
    dest->evictHandle = src->evictHandle;
    dest->name = src->name;
    dest->seedCompatLevel = src->seedCompatLevel;
}

/* Convert an OBJECT to the (smaller) RSA3072_OBJECT. */
static void OBJECT_To_RSA3072_OBJECT(RSA3072_OBJECT* dest, const OBJECT* src)
{
    dest->attributes = src->attributes;

    dest->publicArea.type = src->publicArea.type;
    dest->publicArea.nameAlg = src->publicArea.nameAlg;
    dest->publicArea.objectAttributes = src->publicArea.objectAttributes;
    dest->publicArea.authPolicy = src->publicArea.authPolicy;
    dest->publicArea.parameters = src->publicArea.parameters;
    /* the unique part can be one or two TPM2B's */
    switch (dest->publicArea.type) {
    case TPM_ALG_KEYEDHASH:
	MemoryCopy2B(&dest->publicArea.unique.keyedHash.b,
		     &src->publicArea.unique.keyedHash.b,
		     sizeof(dest->publicArea.unique.keyedHash.t.buffer));
	break;
    case TPM_ALG_SYMCIPHER:
	MemoryCopy2B(&dest->publicArea.unique.sym.b,
		     &src->publicArea.unique.sym.b,
		     sizeof(dest->publicArea.unique.sym.t.buffer));
	break;
    case TPM_ALG_RSA:
	MemoryCopy2B(&dest->publicArea.unique.rsa.b,
		     &src->publicArea.unique.rsa.b,
		     sizeof(dest->publicArea.unique.rsa.t.buffer));

	CopyToRSA3072PrimeT(&dest->privateExponent.Q, &src->privateExponent.Q);
	CopyToRSA3072PrimeT(&dest->privateExponent.dP, &src->privateExponent.dP);
	CopyToRSA3072PrimeT(&dest->privateExponent.dQ, &src->privateExponent.dQ);
	CopyToRSA3072PrimeT(&dest->privateExponent.qInv, &src->privateExponent.qInv);
	break;
    case TPM_ALG_ECC:
	MemoryCopy2B(&dest->publicArea.unique.ecc.x.b,
		     &src->publicArea.unique.ecc.x.b,
		     sizeof(dest->publicArea.unique.ecc.x.t.buffer));
	MemoryCopy2B(&dest->publicArea.unique.ecc.y.b,
		     &src->publicArea.unique.ecc.y.b,
		     sizeof(dest->publicArea.unique.ecc.y.t.buffer));
	break;
    }

    dest->sensitive.sensitiveType = src->sensitive.sensitiveType;
    dest->sensitive.authValue = src->sensitive.authValue;
    dest->sensitive.seedValue = src->sensitive.seedValue;
    /* The OLD_TPMU_SENSITIVE_COMPOSITE is always a TPM2B */
    MemoryCopy2B(&dest->sensitive.sensitive.any.b,
		 &src->sensitive.sensitive.any.b,
		 sizeof(dest->sensitive.sensitive.any.t.buffer));

    dest->qualifiedName = src->qualifiedName;
    dest->evictHandle = src->evictHandle;
    dest->name = src->name;
    dest->seedCompatLevel = src->seedCompatLevel;
    MemorySet(dest->_pad, 0, sizeof(dest->_pad));
}

TPM_RC
RSA3072_OBJECT_Buffer_To_OBJECT(OBJECT *object, BYTE *buffer, INT32 size)
{
    RSA3072_OBJECT rsa3072_object;

    if (size != sizeof(RSA3072_OBJECT))
	return TPM_RC_SIZE;

    MemoryCopy(&rsa3072_object, buffer, size);

    RSA3072_OBJECT_To_OBJECT(object, &rsa3072_object);

    return 0;
}

UINT32 OBJECT_To_Buffer_As_RSA3072_OBJECT(OBJECT* object, BYTE* buffer, UINT32 size)
{
    RSA3072_OBJECT rsa3072_object;
    UINT32         written = sizeof(rsa3072_object);

    OBJECT_To_RSA3072_OBJECT(&rsa3072_object, object);

    pAssert(size >= sizeof(rsa3072_object));
    MemoryCopy(buffer, &rsa3072_object, sizeof(rsa3072_object));

    return written;
}
