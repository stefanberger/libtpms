/********************************************************************************/
/*										*/
/*			 Algorithm Runtime Disablement 				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  (c) Copyright IBM Corporation, 2022						*/
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

#define _GNU_SOURCE
#include <assert.h>
#include <string.h>

#include "Tpm.h"
#include "NVMarshal.h"
#include "GpMacros.h"
#include "tpm_library_intern.h"

#define ALGO_SEPARATOR_C ','
#define ALGO_SEPARATOR_STR ","

struct KeySizes {
    BOOL enabled;
    UINT16 size;
    unsigned int stateFormatLevel; /* required stateFormatLevel to support this */
};

struct MinKeySize {
    unsigned int stateFormatLevel; /* required stateFormatLevel to support this */
};

static const struct KeySizes s_KeySizesAES[] = {
    { .enabled = AES_128, .size = 128, .stateFormatLevel = 1 },
    { .enabled = AES_192, .size = 192, .stateFormatLevel = 4 },
    { .enabled = AES_256, .size = 256, .stateFormatLevel = 1 },
    { .enabled = false  , .size = 0  , .stateFormatLevel = 0 },
};
static const struct KeySizes s_KeySizesSM4[] = {
    { .enabled = SM4_128, .size = 128, .stateFormatLevel = 0 }, // not supported
    { .enabled = false  , .size = 0  , .stateFormatLevel = 0 },
};
static const struct KeySizes s_KeySizesCamellia[] = {
    { .enabled = CAMELLIA_128, .size = 128, .stateFormatLevel = 1 },
    { .enabled = CAMELLIA_192, .size = 192, .stateFormatLevel = 4 },
    { .enabled = CAMELLIA_256, .size = 256, .stateFormatLevel = 1 },
    { .enabled = false       , .size = 0  , .stateFormatLevel = 0 },
};
static const struct KeySizes s_KeySizesTDES[] = {
    { .enabled = TDES_128, .size = 128, .stateFormatLevel = 1 },
    { .enabled = TDES_192, .size = 192, .stateFormatLevel = 1 },
    { .enabled = false   , .size = 0  , .stateFormatLevel = 0 },
};
static const struct KeySizes s_KeySizesRSA[] = {
    { .enabled = RSA_1024, .size = 1024, .stateFormatLevel = 1 },
    { .enabled = RSA_2048, .size = 2048, .stateFormatLevel = 1 },
    { .enabled = RSA_3072, .size = 3072, .stateFormatLevel = 1 },
    { .enabled = false   , .size = 0   , .stateFormatLevel = 0 },
};
static const struct KeySizes s_KeySizesECC[] = {
    { .enabled = ECC_NIST_P192, .size = 192, .stateFormatLevel = 1 },
    { .enabled = ECC_NIST_P224, .size = 224, .stateFormatLevel = 1 },
    { .enabled = ECC_NIST_P256, .size = 256, .stateFormatLevel = 1 },
    { .enabled = ECC_BN_P256  , .size = 256, .stateFormatLevel = 1 },
    { .enabled = ECC_SM2_P256 , .size = 256, .stateFormatLevel = 1 },
    { .enabled = ECC_NIST_P384, .size = 384, .stateFormatLevel = 1 },
    { .enabled = ECC_NIST_P521, .size = 521, .stateFormatLevel = 1 },
    { .enabled = ECC_BN_P638  , .size = 638, .stateFormatLevel = 1 },
    { .enabled = false        , .size = 0  , .stateFormatLevel = 0 },
};
static const struct MinKeySize s_MinKeySizeHMAC[] = {
    { .stateFormatLevel = 7 },
};

static const struct {
    const char   *name;
    struct {
	const struct KeySizes *keySizes;
	const struct MinKeySize *minKeySize;
    } u;
    BOOL          canBeDisabled;
    unsigned int  stateFormatLevel; /* required stateFormatLevel to support this */
} s_AlgorithmProperties[NUM_ENTRIES_ALGORITHM_PROPERTIES] = {
#define SYMMETRIC(ENABLED, NAME, KEYSIZES, CANDISABLE, SFL) \
    { .name = ENABLED ? NAME : NULL, .u.keySizes = KEYSIZES, .canBeDisabled = CANDISABLE, .stateFormatLevel = SFL }
#define ASYMMETRIC(ENABLED, NAME, KEYSIZES, CANDISABLE, SFL) \
    { .name = ENABLED ? NAME : NULL, .u.keySizes = KEYSIZES, .canBeDisabled = CANDISABLE, .stateFormatLevel = SFL }
#define HASH(ENABLED, NAME, CANDISABLE, SFL) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE, .stateFormatLevel = SFL }
#define HMAC(ENABLED, NAME, MINKEYSIZE, CANDISABLE, SFL) \
    { .name = ENABLED ? NAME : NULL, .u.minKeySize = MINKEYSIZE, .canBeDisabled = CANDISABLE, .stateFormatLevel = SFL }
#define SIGNING(ENABLED, NAME, CANDISABLE, SFL) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE, .stateFormatLevel = SFL }
#define ENCRYPTING(ENABLED, NAME, CANDISABLE, SFL) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE, .stateFormatLevel = SFL }
#define OTHER(ENABLED, NAME, CANDISABLE, SFL) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE, .stateFormatLevel = SFL }

    [TPM_ALG_RSA] = ASYMMETRIC(ALG_RSA, "rsa", s_KeySizesRSA, false, 1),
    [TPM_ALG_TDES] = SYMMETRIC(ALG_TDES, "tdes", s_KeySizesTDES, true, 1),
    [TPM_ALG_SHA1] = HASH(ALG_SHA1, "sha1", true, 1),
    [TPM_ALG_HMAC] = HMAC(ALG_HMAC, "hmac", s_MinKeySizeHMAC, false, 1),
    [TPM_ALG_AES] = SYMMETRIC(ALG_AES, "aes", s_KeySizesAES, false, 1), // never disable: context encryption
    [TPM_ALG_MGF1] = HASH(ALG_MGF1, "mgf1", false, 1),
    [TPM_ALG_KEYEDHASH] = HASH(ALG_KEYEDHASH, "keyedhash", false, 1),
    [TPM_ALG_XOR] = OTHER(ALG_XOR, "xor", false, 1),
    [TPM_ALG_SHA256] = HASH(ALG_SHA256, "sha256", false, 1),
    [TPM_ALG_SHA384] = HASH(ALG_SHA384, "sha384", false, 1),
    [TPM_ALG_SHA512] = HASH(ALG_SHA512, "sha512", true, 1),
    [TPM_ALG_NULL] = OTHER(true, "null", false, 1),
    [TPM_ALG_SM4] = SYMMETRIC(ALG_SM4, "sm4", s_KeySizesSM4, true, 0), // not supported
    [TPM_ALG_RSASSA] = SIGNING(ALG_RSASSA, "rsassa", true, 1),
    [TPM_ALG_RSAES] = ENCRYPTING(ALG_RSAES, "rsaes", true, 1),
    [TPM_ALG_RSAPSS] = SIGNING(ALG_RSAPSS, "rsapss", true, 1),
    [TPM_ALG_OAEP] = ENCRYPTING(ALG_OAEP, "oaep", false, 1), // never disable: CryptSecretEncrypt/Decrypt needs it
    [TPM_ALG_ECDSA] = SIGNING(ALG_ECDSA, "ecdsa", false, 1),
    [TPM_ALG_ECDH] = OTHER(ALG_ECDH, "ecdh", false, 1),
    [TPM_ALG_ECDAA] = OTHER(ALG_ECDAA, "ecdaa", true, 1),
    [TPM_ALG_SM2] = SIGNING(ALG_SM2, "sm2", true, 1),
    [TPM_ALG_ECSCHNORR] = SIGNING(ALG_ECSCHNORR, "ecschnorr", true, 1),
    [TPM_ALG_ECMQV] = OTHER(ALG_ECMQV, "ecmqv", true, 1),
    [TPM_ALG_KDF1_SP800_56A] = HASH(ALG_KDF1_SP800_56A, "kdf1-sp800-56a", false, 1),
    [TPM_ALG_KDF2] = HASH(ALG_KDF2, "kdf2", false, 1),
    [TPM_ALG_KDF1_SP800_108] = HASH(ALG_KDF1_SP800_108, "kdf1-sp800-108", false, 1),
    [TPM_ALG_ECC] = ASYMMETRIC(ALG_ECC, "ecc", s_KeySizesECC, false, 1),
    [TPM_ALG_SYMCIPHER] = OTHER(ALG_SYMCIPHER, "symcipher", false, 1),
    [TPM_ALG_CAMELLIA] = SYMMETRIC(ALG_CAMELLIA, "camellia", s_KeySizesCamellia, true, 1),
    [TPM_ALG_SHA3_256] = HASH(ALG_SHA3_256, "sha3-256", true, 0), // not supported
    [TPM_ALG_SHA3_384] = HASH(ALG_SHA3_384, "sha3-384", true, 0), // not supported
    [TPM_ALG_SHA3_512] = HASH(ALG_SHA3_512, "sha3-256", true, 0), // not supported
    [TPM_ALG_CMAC] = SIGNING(ALG_CMAC, "cmac", true, 1),
    [TPM_ALG_CTR] = ENCRYPTING(ALG_CTR, "ctr", true, 1),
    [TPM_ALG_OFB] = ENCRYPTING(ALG_OFB, "ofb", true, 1),
    [TPM_ALG_CBC] = ENCRYPTING(ALG_CBC, "cbc", true, 1),
    [TPM_ALG_CFB] = ENCRYPTING(ALG_CFB, "cfb", false, 1), // never disable: context entryption
    [TPM_ALG_ECB] = ENCRYPTING(ALG_ECB, "ecb", true, 1),
    /* all newly added algorithms must have .canBedisable=true so they can be disabled */
};

static const struct {
    const char   *name;
    BOOL          canBeDisabled;
    const char   *prefix;
} s_EccShortcuts[] = {
#define ECC_SHORTCUT(NAME, CANDISABLE, PREFIX) \
    { .name = NAME, .canBeDisabled = CANDISABLE, .prefix = PREFIX }
    [RUNTIME_ALGORITHM_ECC_NIST_BIT] = ECC_SHORTCUT("ecc-nist", true, "ecc-nist-p"),
    [RUNTIME_ALGORITHM_ECC_BN_BIT] = ECC_SHORTCUT("ecc-bn", true, "ecc-bn-p"),
};

static const struct {
    const char   *name;
    UINT16        keySize;
    BOOL          canBeDisabled;
    unsigned int  stateFormatLevel; /* required stateFormatLevel to support this */
} s_EccAlgorithmProperties[] = {
#define ECC(ENABLED, NAME, KEYSIZE, CANDISABLE, SFL) \
    { .name = ENABLED ? NAME : NULL, .keySize = KEYSIZE, .canBeDisabled = CANDISABLE, .stateFormatLevel = SFL }

    [TPM_ECC_NIST_P192] = ECC(ECC_NIST_P192, "ecc-nist-p192", 192, true, 1),
    [TPM_ECC_NIST_P224] = ECC(ECC_NIST_P224, "ecc-nist-p224", 224, true, 1),
    [TPM_ECC_NIST_P256] = ECC(ECC_NIST_P256, "ecc-nist-p256", 256, false, 1),
    [TPM_ECC_NIST_P384] = ECC(ECC_NIST_P384, "ecc-nist-p384", 384, false, 1),
    [TPM_ECC_NIST_P521] = ECC(ECC_NIST_P521, "ecc-nist-p521", 521, true, 1),
    [TPM_ECC_BN_P256] = ECC(ECC_BN_P256, "ecc-bn-p256", 256, true, 1),
    [TPM_ECC_BN_P638] = ECC(ECC_BN_P638, "ecc-bn-p638", 638, true, 1),
    [TPM_ECC_SM2_P256] = ECC(ECC_SM2_P256, "ecc-sm2-p256", 256, true, 1),
};

static const TPM_ALG_ID algsWithKeySizes[] = {
    TPM_ALG_RSA,
    TPM_ALG_TDES,
    TPM_ALG_AES,
    TPM_ALG_SM4,
    TPM_ALG_CAMELLIA,
};

static unsigned int
KeySizesGetMinimum(const struct KeySizes *ks)
{
    size_t i = 0;

    while (ks[i].size) {
	if (ks[i].enabled)
	    return ks[i].size;
	i++;
    }
    return 0;
}

static void
RuntimeAlgorithmEnableAllAlgorithms(struct RuntimeAlgorithm *RuntimeAlgorithm)
{
    TPM_ECC_CURVE curveId;
    TPM_ALG_ID algId;

    MemorySet(RuntimeAlgorithm->enabledAlgorithms, 0 , sizeof(RuntimeAlgorithm->enabledAlgorithms));

    for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	/* skip over unsupported algorithms */
	if (!s_AlgorithmProperties[algId].name)
	    continue;
	SET_BIT(algId, RuntimeAlgorithm->enabledAlgorithms);
    }

    MemorySet(RuntimeAlgorithm->enabledEccCurves, 0 , sizeof(RuntimeAlgorithm->enabledEccCurves));

    for (curveId = 0; curveId < ARRAY_SIZE(s_EccAlgorithmProperties); curveId++) {
        if (!s_EccAlgorithmProperties[curveId].name)
            continue;
        SET_BIT(curveId, RuntimeAlgorithm->enabledEccCurves);
    }
}

LIB_EXPORT void
RuntimeAlgorithmInit(struct RuntimeAlgorithm *RuntimeAlgorithm)
{
    TPM_ALG_ID algId;
    size_t i;

    MemorySet(RuntimeAlgorithm->algosMinimumKeySizes, 0 , sizeof(RuntimeAlgorithm->algosMinimumKeySizes));

    for (i = 0; i < ARRAY_SIZE(algsWithKeySizes); i++) {
	algId = algsWithKeySizes[i];
	assert(algId < ARRAY_SIZE(RuntimeAlgorithm->algosMinimumKeySizes));
	assert(s_AlgorithmProperties[algId].u.keySizes != NULL);
	RuntimeAlgorithm->algosMinimumKeySizes[algId] = KeySizesGetMinimum(s_AlgorithmProperties[algId].u.keySizes);
    }
}

LIB_EXPORT void
RuntimeAlgorithmFree(struct RuntimeAlgorithm *RuntimeAlgorithm)
{
    free(RuntimeAlgorithm->algorithmProfile);
    RuntimeAlgorithm->algorithmProfile = NULL;
}

/* Set the default profile with all algorithms and all keysizes enabled */
static void
RuntimeAlgorithmSetDefault(struct RuntimeAlgorithm *RuntimeAlgorithm)
{
    RuntimeAlgorithmFree(RuntimeAlgorithm);
    RuntimeAlgorithmInit(RuntimeAlgorithm);
    RuntimeAlgorithmEnableAllAlgorithms(RuntimeAlgorithm);
}

/* Set the given profile and runtime-enable the given algorithms. A NULL pointer
 * for the profile parameter sets the default profile which enables all algorithms
 * and all key sizes without any restrictions.
 *
 * This function will adjust the stateFormatLevel to the number required for the
 * given algorithms and key sizes.
 */
LIB_EXPORT TPM_RC
RuntimeAlgorithmSetProfile(struct RuntimeAlgorithm  *RuntimeAlgorithm,
			   const char		    *newProfile,		// IN: colon-separated list of algorithm names
			   unsigned int             *stateFormatLevel,		// IN/OUT: stateFormatLevel
			   unsigned int	             maxStateFormatLevel	// IN: maximum allowed stateFormatLevel
			   )
{
    size_t toklen, cmplen, i, prefix_len, idx;
    const char *token, *comma, *prefix;
    const struct KeySizes *keysizes;
    TPM_RC retVal = TPM_RC_SUCCESS;
    unsigned long minKeySize;
    TPM_ECC_CURVE curveId;
    TPM_ALG_ID algId;
    char *endptr;
    bool found;

    /* NULL pointer for profile enables all */
    if (!newProfile) {
	RuntimeAlgorithmSetDefault(RuntimeAlgorithm);
	return TPM_RC_SUCCESS;
    }

    MemorySet(RuntimeAlgorithm->enabledAlgorithms, 0, sizeof(RuntimeAlgorithm->enabledAlgorithms));
    MemorySet(RuntimeAlgorithm->enabledEccCurves, 0 , sizeof(RuntimeAlgorithm->enabledEccCurves));
    MemorySet(RuntimeAlgorithm->enabledEccShortcuts, 0, sizeof(RuntimeAlgorithm->enabledEccShortcuts));

    token = newProfile;
    while (1) {
	comma = strchr(token, ALGO_SEPARATOR_C);
	if (comma)
	    toklen = (size_t)(comma - token);
	else
	    toklen = strlen(token);

	found = false;
	for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	    /* skip over unsupported algorithms */
	    if (!s_AlgorithmProperties[algId].name)
		continue;
	    cmplen = MAX(strlen(s_AlgorithmProperties[algId].name), toklen);
	    if (!strncmp(token, s_AlgorithmProperties[algId].name, cmplen)) {
		if (s_AlgorithmProperties[algId].stateFormatLevel > maxStateFormatLevel) {
		    TPMLIB_LogTPM2Error("Requested algorithm %.*s requires StateFormatLevel %u but maximum allowed is %u.\n",
					(int)toklen, token,
					s_AlgorithmProperties[algId].stateFormatLevel,
					maxStateFormatLevel);
		    retVal = TPM_RC_VALUE;
		    goto exit;
		}
		SET_BIT(algId, RuntimeAlgorithm->enabledAlgorithms);
		assert(s_AlgorithmProperties[algId].stateFormatLevel > 0);
		*stateFormatLevel = MAX(*stateFormatLevel,
					s_AlgorithmProperties[algId].stateFormatLevel);
		found = true;
		break;
	    } else if (s_AlgorithmProperties[algId].u.minKeySize) {
	        size_t namelen = strlen(s_AlgorithmProperties[algId].name);
	        if (strncmp(token,
	                    s_AlgorithmProperties[algId].name, /* i.e., 'hmac' */
	                    namelen) ||
	            strncmp(&token[namelen], "-min-key-size=", 14))
	            continue;
		minKeySize = strtoul(&token[namelen + 14], &endptr, 10);
		if ((*endptr != ALGO_SEPARATOR_C && *endptr != '\0')
		    || minKeySize > MAX_SYM_DATA * 8) {
		    retVal = TPM_RC_KEY_SIZE;
		    goto exit;
		}
		RuntimeAlgorithm->algosMinimumKeySizes[algId] = (UINT16)minKeySize;
		*stateFormatLevel = MAX(*stateFormatLevel,
					s_AlgorithmProperties[algId].u.minKeySize->stateFormatLevel);
		found = true;
		break;
	    } else if (s_AlgorithmProperties[algId].u.keySizes) {
		size_t algnamelen = strlen(s_AlgorithmProperties[algId].name);
		if (strncmp(token, s_AlgorithmProperties[algId].name, algnamelen) ||
		    strncmp(&token[algnamelen], "-min-size=", 10))
		    continue;
		minKeySize = strtoul(&token[algnamelen + 10], &endptr, 10);
		if ((*endptr != ALGO_SEPARATOR_C && *endptr != '\0') ||  minKeySize > 4096) {
		    retVal = TPM_RC_KEY_SIZE;
		    goto exit;
		}

		/* determine stateFormatLevel needed; skip those key sizes that exceed max. stateFormatLevel */
		keysizes = s_AlgorithmProperties[algId].u.keySizes;
		for (i = 0; keysizes[i].size != 0; i++) {
		    if (keysizes[i].enabled &&
			keysizes[i].size >= minKeySize &&
			keysizes[i].stateFormatLevel <= maxStateFormatLevel) {
			assert(keysizes[i].stateFormatLevel > 0);
			*stateFormatLevel = MAX(*stateFormatLevel,
						keysizes[i].stateFormatLevel);
		    }
		}

		RuntimeAlgorithm->algosMinimumKeySizes[algId] = (UINT16)minKeySize;
		found = true;
		break;
	    }
	}

	if (!found) {
	    bool match_one = true;

	    /* handling of ECC curves: shortcuts */
	    for (idx = 0; idx < ARRAY_SIZE(s_EccShortcuts); idx++) {
		cmplen = MAX(strlen(s_EccShortcuts[idx].name), toklen);
		if (!strncmp(token, s_EccShortcuts[idx].name, cmplen)) {
		    SET_BIT(idx, RuntimeAlgorithm->enabledEccShortcuts);
		    match_one = false;
		    prefix = s_EccShortcuts[idx].prefix;
		    prefix_len = strlen(prefix);
		    break;
		}
	    }
	    if (match_one) {
		prefix = token;
		prefix_len = toklen;
	    }
	    for (curveId = 0; curveId < ARRAY_SIZE(s_EccAlgorithmProperties); curveId++) {
		if (!s_EccAlgorithmProperties[curveId].name)
		    continue;

		if (match_one)
		    cmplen = MAX(strlen(s_EccAlgorithmProperties[curveId].name), toklen);
		else
		    cmplen = prefix_len;

		if (!strncmp(prefix, s_EccAlgorithmProperties[curveId].name, cmplen)) {
		    if (s_EccAlgorithmProperties[curveId].stateFormatLevel > maxStateFormatLevel) {
			/* specific match that is not allowed causes error, otherwise skip */
			if (match_one) {
			    TPMLIB_LogTPM2Error("Requested curve %s requires StateFormatLevel %u but maximum allowed is %u.\n",
						s_EccAlgorithmProperties[curveId].name,
						s_EccAlgorithmProperties[curveId].stateFormatLevel,
						maxStateFormatLevel);
			    retVal = TPM_RC_VALUE;
			    goto exit;
			}
			continue;
		    }
		    *stateFormatLevel = MAX(*stateFormatLevel,
					    s_EccAlgorithmProperties[curveId].stateFormatLevel);
		    SET_BIT(curveId, RuntimeAlgorithm->enabledEccCurves);
		    found = true;
		}
	    }
	}

	if (!found) {
	    TPMLIB_LogTPM2Error("Requested algorithm specifier %.*s is not supported.\n",
				(int)toklen, token);
	    retVal = TPM_RC_VALUE;
	    goto exit;
	}

	if (!comma)
	    break;
	token = &comma[1];
    }

    /* reconcile with what can be disabled per code instrumentation */
    for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	/* skip over unsupported algorithms */
	if (!s_AlgorithmProperties[algId].name)
	    continue;
	if (!s_AlgorithmProperties[algId].canBeDisabled &&
	    !TEST_BIT(algId, RuntimeAlgorithm->enabledAlgorithms)) {
	    TPMLIB_LogTPM2Error("Algorithm %s must be enabled.\n",
				s_AlgorithmProperties[algId].name);
	    retVal = TPM_RC_VALUE;
	    goto exit;
	}
    }
    for (curveId = 0; curveId < ARRAY_SIZE(s_EccAlgorithmProperties); curveId++) {
	if (!s_EccAlgorithmProperties[curveId].name)
	    continue;
	if (!s_EccAlgorithmProperties[curveId].canBeDisabled &&
	    !TEST_BIT(curveId, RuntimeAlgorithm->enabledEccCurves)) {
	    TPMLIB_LogTPM2Error("Elliptic curve %s must be enabled.\n",
				s_EccAlgorithmProperties[curveId].name);
	    retVal = TPM_RC_VALUE;
	    goto exit;
	}
	/* disable curves that can be disabled and not meet min. keysize */
        if (RuntimeAlgorithm->algosMinimumKeySizes[TPM_ALG_ECC] >
               s_EccAlgorithmProperties[curveId].keySize &&
            s_EccAlgorithmProperties[curveId].canBeDisabled)
            CLEAR_BIT(curveId, RuntimeAlgorithm->enabledEccCurves);
    }

    /* some consistency checks */
    /* Do not allow aes-min-size > 128 while RSA=2048 otherwise standard EK certs cannot be created anymore */
    if (RuntimeAlgorithm->algosMinimumKeySizes[TPM_ALG_AES] > 128 &&
	RuntimeAlgorithm->algosMinimumKeySizes[TPM_ALG_RSA] == 2048) {
	TPMLIB_LogTPM2Error("AES minimum key size must be 128 when "
			    "2048 bit %s keys are used.\n",
			    "RSA");
	retVal = TPM_RC_KEY_SIZE;
	goto exit;
    }

    free(RuntimeAlgorithm->algorithmProfile);
    RuntimeAlgorithm->algorithmProfile = strdup(newProfile);
    if (!RuntimeAlgorithm->algorithmProfile)
	retVal = TPM_RC_MEMORY;

exit:
    if (retVal != TPM_RC_SUCCESS)
	RuntimeAlgorithmSetDefault(RuntimeAlgorithm);

    return retVal;
}

LIB_EXPORT TPM_RC
RuntimeAlgorithmSwitchProfile(struct RuntimeAlgorithm  *RuntimeAlgorithm,
			      const char               *newProfile,
			      unsigned int              maxStateFormatLevel,
			      char                    **oldProfile)
{
    TPM_RC retVal;
    unsigned int stateFormatLevel = 0; // ignored

    *oldProfile = RuntimeAlgorithm->algorithmProfile;
    RuntimeAlgorithm->algorithmProfile = NULL;

    retVal = RuntimeAlgorithmSetProfile(RuntimeAlgorithm, newProfile,
                                        &stateFormatLevel, maxStateFormatLevel);
    if (retVal != TPM_RC_SUCCESS) {
	RuntimeAlgorithmSetProfile(RuntimeAlgorithm, *oldProfile,
	                           &stateFormatLevel, maxStateFormatLevel);
	*oldProfile = NULL;
    }
    return retVal;
}

/* Check whether the given algorithm is runtime-enabled */
LIB_EXPORT BOOL
RuntimeAlgorithmCheckEnabled(struct RuntimeAlgorithm *RuntimeAlgorithm,
			     TPM_ALG_ID	              algId      // IN: the algorithm to check
			     )
{
    if ((algId >> 3) >= sizeof(RuntimeAlgorithm->enabledAlgorithms) ||
        !TestBit(algId, RuntimeAlgorithm->enabledAlgorithms,
                 sizeof(RuntimeAlgorithm->enabledAlgorithms)))
	return FALSE;
    return TRUE;
}

/* Check whether the given symmetric or asymmetric crypto algorithm is enabled
 * for the given keysize. The maxStateFormatLevel prevents certain key sizes
 * from being usable if these were only enabled after the algorithm was enabled.
 *
 * Example: Algorithm 'x' was enabled but keysize 192 was not enabled at this
 * point. The required stateFormatLevel for 'x' is 1. To use keysize 192
 * stateFormatLevel '4' is required but due to the profile's stateFormatLevel '1'
 * it needs to be filtered-out so that the profile doesn't need an upgrade to
 * stateFormatLevel '4'.
 */
LIB_EXPORT BOOL
RuntimeAlgorithmKeySizeCheckEnabled(struct RuntimeAlgorithm *RuntimeAlgorithm,
				    TPM_ALG_ID               algId,			// IN: the algorithm to check
				    UINT16                   keySizeInBits,		// IN: size of the key in bits
				    TPM_ECC_CURVE            curveId,			// IN: curve Id if algId == TPM_ALG_ECC
				    unsigned int             maxStateFormatLevel	// IN: maximum stateFormatLevel
				    )
{
    const struct KeySizes *keysizes;
    UINT16 minKeySize;
    size_t i;

    if (!RuntimeAlgorithmCheckEnabled(RuntimeAlgorithm, algId))
	return FALSE;

    minKeySize = RuntimeAlgorithm->algosMinimumKeySizes[algId];
    if (minKeySize > keySizeInBits)
	return FALSE;

    if (s_AlgorithmProperties[algId].u.minKeySize)
        return TRUE;

    if (algId == TPM_ALG_ECC) {
	if ((curveId >> 3) >= sizeof(RuntimeAlgorithm->enabledEccCurves) ||
	    !TestBit(curveId, RuntimeAlgorithm->enabledEccCurves,
	             sizeof(RuntimeAlgorithm->enabledEccCurves))) {
	    return FALSE;
	}
    }

    keysizes = s_AlgorithmProperties[algId].u.keySizes;
    for (i = 0; keysizes[i].size != 0; i++) {
	if (keysizes[i].size == keySizeInBits) {
	    if (keysizes[i].enabled &&
		keysizes[i].stateFormatLevel > maxStateFormatLevel) {
		return FALSE;
	    }
	    return TRUE;
	}
    }

    return TRUE;
}

static char *
RuntimeAlgorithmGetEcc(struct RuntimeAlgorithm   *RuntimeAlgorithm,
		       enum RuntimeAlgorithmType rat,
		       char                      *buffer,
		       BOOL                      *first)
{
    TPM_ECC_CURVE curveId;
    char *nbuffer = NULL;
    size_t idx;
    int n;

    for (idx = 0; idx < ARRAY_SIZE(s_EccShortcuts); idx++) {
	switch (rat) {
	case RUNTIME_ALGO_IMPLEMENTED:
	    // no filter;
	    break;
	case RUNTIME_ALGO_CAN_BE_DISABLED:
	    if (!s_EccShortcuts[idx].canBeDisabled)
		continue;
	    break;
	case RUNTIME_ALGO_ENABLED:
	    if (!TEST_BIT(idx, RuntimeAlgorithm->enabledEccShortcuts))
		continue;
	    break;
	case RUNTIME_ALGO_DISABLED:
	    if (TEST_BIT(idx, RuntimeAlgorithm->enabledEccShortcuts))
		continue;
	    break;
	default:
	    break;
	}
	n = asprintf(&nbuffer, "%s%s%s",
		     buffer,
		     *first ? "" : ALGO_SEPARATOR_STR,
		     s_EccShortcuts[idx].name);
	free(buffer);
	if (n < 0)
	    return NULL;
	buffer = nbuffer;
	*first = false;
    }

    for (curveId = 0; curveId < ARRAY_SIZE(s_EccAlgorithmProperties); curveId++) {
	if (!s_EccAlgorithmProperties[curveId].name)
	    continue;

	switch (rat) {
	case RUNTIME_ALGO_IMPLEMENTED:
	    // no filter
	    break;
	case RUNTIME_ALGO_CAN_BE_DISABLED:
	    if (!s_EccAlgorithmProperties[curveId].canBeDisabled)
	       continue;
	    break;
	case RUNTIME_ALGO_ENABLED:
	    if (!TEST_BIT(curveId, RuntimeAlgorithm->enabledEccCurves))
		continue;
	    break;
	case RUNTIME_ALGO_DISABLED:
	    if (TEST_BIT(curveId, RuntimeAlgorithm->enabledEccCurves))
		continue;
	    break;
	default:
	    break;
	}
	n = asprintf(&nbuffer, "%s%s%s",
		     buffer,
		     *first ? "" : ALGO_SEPARATOR_STR,
		     s_EccAlgorithmProperties[curveId].name);
	free(buffer);
	if (n < 0)
	    return NULL;
	buffer = nbuffer;
	*first = FALSE;
    }

    return buffer;
}

LIB_EXPORT char *
RuntimeAlgorithmPrint(struct RuntimeAlgorithm   *RuntimeAlgorithm,
		      enum RuntimeAlgorithmType rat)
{
    char *buffer, *nbuffer = NULL;
    unsigned int minKeySize;
    TPM_ALG_ID algId;
    int n;
    BOOL first = true;

    buffer = strdup("\"");
    if (!buffer)
	return NULL;

    for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	// skip over unsupported algorithms
	if (!s_AlgorithmProperties[algId].name)
	    continue;
	switch (rat) {
	case RUNTIME_ALGO_IMPLEMENTED:
	    // no filter
	    break;
	case RUNTIME_ALGO_CAN_BE_DISABLED:
	    if (!s_AlgorithmProperties[algId].canBeDisabled)
		 goto skip; // TPM_ALG_ECC: need to print more
	    break;
	case RUNTIME_ALGO_ENABLED:
	    // skip over disabled ones
	    if (!RuntimeAlgorithmCheckEnabled(RuntimeAlgorithm, algId))
		goto skip;
	    break;
	case RUNTIME_ALGO_DISABLED:
	    // skip over enabled ones
	    if (RuntimeAlgorithmCheckEnabled(RuntimeAlgorithm, algId))
		goto skip;
	    break;
	default:
	    continue;
	}
	n = asprintf(&nbuffer, "%s%s%s",
		     buffer,
		     first ? "" : ALGO_SEPARATOR_STR,
		     s_AlgorithmProperties[algId].name);
	free(buffer);
	if (n < 0)
	     return NULL;

	buffer = nbuffer;
	first = false;

	minKeySize = 0;

	switch (rat) {
	case RUNTIME_ALGO_IMPLEMENTED:
	    if (s_AlgorithmProperties[algId].u.keySizes) {
		minKeySize = KeySizesGetMinimum(s_AlgorithmProperties[algId].u.keySizes);
	    } else if (s_AlgorithmProperties[algId].u.minKeySize) {
	        /* for it to appear as 'Implemented' */
	        minKeySize = 1;
	    }
	    break;
	case RUNTIME_ALGO_ENABLED:
	    if (s_AlgorithmProperties[algId].u.keySizes ||
	        s_AlgorithmProperties[algId].u.minKeySize) {
		minKeySize = RuntimeAlgorithm->algosMinimumKeySizes[algId];
	    }
	    break;
	default:
	    break;
	}
	if (minKeySize > 0) {
	    const char *key = "";
	    if (s_AlgorithmProperties[algId].u.minKeySize)
	        key = "key-";

	    n = asprintf(&nbuffer, "%s%s%s-min-%ssize=%u",
			 buffer,
			 ALGO_SEPARATOR_STR,
			 s_AlgorithmProperties[algId].name,
			 key,
			 minKeySize);
	    free(buffer);
	    if (n < 0)
		return NULL;

	    buffer = nbuffer;
	}

skip:
	if (algId == TPM_ALG_ECC)
	    buffer = RuntimeAlgorithmGetEcc(RuntimeAlgorithm, rat, buffer, &first);
    }

    n = asprintf(&nbuffer, "%s\"", buffer);
    free(buffer);
    if (n < 0)
        return NULL;

    return nbuffer;
}

LIB_EXPORT void
RuntimeAlgorithmsFilterPCRSelection(TPML_PCR_SELECTION *pcrSelection // IN/OUT: PCRSelection to filter
				    )
{
    UINT32 i = 0;

    while (i < pcrSelection->count) {
	if (!RuntimeAlgorithmCheckEnabled(&g_RuntimeProfile.RuntimeAlgorithm,
					  pcrSelection->pcrSelections[i].hash)) {
	    pcrSelection->count--;
	    if (pcrSelection->count - 1 > i) {
		MemoryCopy(&pcrSelection->pcrSelections[i],
			   &pcrSelection->pcrSelections[i + 1],
			   sizeof(pcrSelection->pcrSelections[0]) * (pcrSelection->count - i));
	    }
	} else {
	    i++;
	}
    }
}
