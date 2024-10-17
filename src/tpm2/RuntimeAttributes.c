/********************************************************************************/
/*										*/
/*			        Runtime Attributes 				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  (c) Copyright IBM Corporation, 2023						*/
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
#include "tpm_library_intern.h"

#define ATTR_SEPARATOR_C ','
#define ATTR_SEPARATOR_STR ","

static const struct {
    const char   *name;
    unsigned int  attributeFlags;
    unsigned int  stateFormatLevel;
    /* all of them can be disabled */
} s_AttributeProperties[NUM_ENTRIES_ATTRIBUTE_PROPERTIES] = {
#define ATTRIBUTE(NAME, FLAGS, SFL) \
    { .name = NAME, .attributeFlags = FLAGS, .stateFormatLevel = SFL }
    ATTRIBUTE("no-unpadded-encryption", RUNTIME_ATTRIBUTE_NO_UNPADDED_ENCRYPTION,
	      7),
    ATTRIBUTE("no-sha1-signing", RUNTIME_ATTRIBUTE_NO_SHA1_SIGNING,
	      7),
    ATTRIBUTE("no-sha1-verification", RUNTIME_ATTRIBUTE_NO_SHA1_VERIFICATION,
	      7),
    ATTRIBUTE("no-sha1-hmac-creation", RUNTIME_ATTRIBUTE_NO_SHA1_HMAC_CREATION,
	      7),
    ATTRIBUTE("no-sha1-hmac-verification", RUNTIME_ATTRIBUTE_NO_SHA1_HMAC_VERIFICATION,
	      7),
    ATTRIBUTE("no-sha1-hmac", RUNTIME_ATTRIBUTE_NO_SHA1_HMAC_VERIFICATION |
                              RUNTIME_ATTRIBUTE_NO_SHA1_HMAC_CREATION,
	      7),
    ATTRIBUTE("fips-host", RUNTIME_ATTRIBUTE_NO_UNPADDED_ENCRYPTION |
			   RUNTIME_ATTRIBUTE_NO_SHA1_SIGNING |
			   RUNTIME_ATTRIBUTE_NO_SHA1_VERIFICATION,
	      7),
    ATTRIBUTE("drbg-continous-test", RUNTIME_ATTRIBUTE_DRBG_CONTINOUS_TEST,
	      7),
    ATTRIBUTE("pct", RUNTIME_ATTRIBUTE_PAIRWISE_CONSISTENCY_TEST,
              7),
    ATTRIBUTE("no-ecc-key-derivation", RUNTIME_ATTRIBUTE_NO_ECC_KEY_DERIVATION,
	      7),
};

LIB_EXPORT void
RuntimeAttributesFree(struct RuntimeAttributes *RuntimeAttributes)
{
    free(RuntimeAttributes->attributesProfile);
    RuntimeAttributes->attributesProfile = NULL;
}

LIB_EXPORT void
RuntimeAttributesInit(struct RuntimeAttributes *RuntimeAttributes)
{
    RuntimeAttributes->attributeFlags = 0;
    MemorySet(RuntimeAttributes->enabledAttributesPrint, 0, sizeof(RuntimeAttributes->enabledAttributesPrint));
    RuntimeAttributesFree(RuntimeAttributes);
}

LIB_EXPORT TPM_RC
RuntimeAttributesSetProfile(struct RuntimeAttributes *RuntimeAttributes,
			    const char		     *newProfile,		// IN: colon-separated list of algorithm names
			    unsigned int             *stateFormatLevel,		// IN/OUT: stateFormatLevel
			    unsigned int              maxStateFormatLevel	// IN: maximum allowed stateFormatLevel
			    )
{
    TPM_RC retVal = TPM_RC_SUCCESS;
    size_t toklen, idx, cmplen;
    const char *token, *comma;
    bool found;

    RuntimeAttributesInit(RuntimeAttributes);

    /* NULL pointer for profile or empty profiles enables nothing */
    if (!newProfile || strlen(newProfile) == 0)
	return TPM_RC_SUCCESS;

    token = newProfile;
    while (1) {
	comma = strchr(token, ATTR_SEPARATOR_C);
	if (comma)
	    toklen = (size_t)(comma - token);
	else
	    toklen = strlen(token);

	found = false;
	for (idx = 0; idx < ARRAY_SIZE(s_AttributeProperties); idx++) {
	    cmplen = MAX(strlen(s_AttributeProperties[idx].name), toklen);
	    if (!strncmp(token, s_AttributeProperties[idx].name, cmplen)) {
		if (s_AttributeProperties[idx].stateFormatLevel > maxStateFormatLevel) {
		    TPMLIB_LogTPM2Error("Requested attribute %.*s requires StateFormatLevel %u but maximum allowed is %u.\n",
					(int)toklen, token,
					s_AttributeProperties[idx].stateFormatLevel,
					maxStateFormatLevel);
		    retVal = TPM_RC_VALUE;
		    goto exit;
		}
		SET_BIT(idx, RuntimeAttributes->enabledAttributesPrint);
		RuntimeAttributes->attributeFlags |= s_AttributeProperties[idx].attributeFlags;
		assert(s_AttributeProperties[idx].stateFormatLevel > 0);
		*stateFormatLevel = MAX(*stateFormatLevel,
					s_AttributeProperties[idx].stateFormatLevel);
		found = true;
		break;
	    }
	}

	if (!found) {
	    TPMLIB_LogTPM2Error("Requested attribute %.*s is not supported.\n",
				(int)toklen, token);
	    retVal = TPM_RC_FAILURE;
	    goto exit;
	}

	if (!comma)
	    break;
	token = &comma[1];
    }

    free(RuntimeAttributes->attributesProfile);
    RuntimeAttributes->attributesProfile = strdup(newProfile);
    if (!RuntimeAttributes->attributesProfile)
	retVal = TPM_RC_MEMORY;

exit:
    if (retVal != TPM_RC_SUCCESS)
	RuntimeAttributesInit(RuntimeAttributes);

    return retVal;
}

LIB_EXPORT TPM_RC
RuntimeAttributesSwitchProfile(struct RuntimeAttributes *RuntimeAttributes,
			       const char               *newProfile,
			       unsigned int              maxStateFormatLevel,
			       char                    **oldProfile)
{
    TPM_RC retVal;
    unsigned int stateFormatLevel = 0; // ignored

    *oldProfile = RuntimeAttributes->attributesProfile;
    RuntimeAttributes->attributesProfile = NULL;

    retVal = RuntimeAttributesSetProfile(RuntimeAttributes, newProfile,
					 &stateFormatLevel, maxStateFormatLevel);
    if (retVal != TPM_RC_SUCCESS) {
	RuntimeAttributesSetProfile(RuntimeAttributes, *oldProfile,
				    &stateFormatLevel, maxStateFormatLevel);
	*oldProfile = NULL;
    }
    return retVal;
}

LIB_EXPORT char *
RuntimeAttributesGet(struct RuntimeAttributes   *RuntimeAttributes,
		     enum RuntimeAttributeType  rat)
{
    char *buffer, *nbuffer = NULL;
    bool first = true;
    size_t idx;
    int n;

    buffer = strdup("\"");
    if (!buffer)
	return NULL;

    for (idx = 0; idx < ARRAY_SIZE(s_AttributeProperties); idx++) {
	switch (rat) {
	case RUNTIME_ATTR_IMPLEMENTED:
	    // no filter
	    break;
	case RUNTIME_ATTR_CAN_BE_DISABLED:
	    // all of them can be disabled
	    break;
	case RUNTIME_ATTR_ENABLED:
	    // skip over disabled ones
	    if (!TEST_BIT(idx, RuntimeAttributes->enabledAttributesPrint))
		continue;
	    break;
	case RUNTIME_ATTR_DISABLED:
	    // skip over enabled ones
	    if (TEST_BIT(idx, RuntimeAttributes->enabledAttributesPrint))
		continue;
	    break;
	default:
	    continue;
	}
	n = asprintf(&nbuffer, "%s%s%s",
		     buffer ? buffer : "",
		     first ? "" : ATTR_SEPARATOR_STR,
		     s_AttributeProperties[idx].name);
	free(buffer);
	if (n < 0)
	     return NULL;

	buffer = nbuffer;
	first = false;
    }

    n = asprintf(&nbuffer, "%s\"", buffer);
    free(buffer);
    if (n < 0)
        return NULL;

    return nbuffer;
}

LIB_EXPORT BOOL
RuntimeAttributeCheckRequired(struct RuntimeAttributes *RuntimeAttributes,
			      unsigned int              attributeFlags)
{
    return (RuntimeAttributes->attributeFlags & attributeFlags) == attributeFlags;
}
