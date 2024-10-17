/********************************************************************************/
/*										*/
/*			       Runtime Profile 					*/
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
#include <errno.h>
#include <stdio.h>
#include <regex.h>
#include <limits.h>

#include "Tpm.h"
#include "tpm_library_intern.h"

struct RuntimeProfile g_RuntimeProfile;

const char defaultCommandsProfile[] =
    "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,"
    "0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197,0x199-0x19c";

const char defaultAlgorithmsProfile[] =
    "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,"
    "aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,"
    "null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
    "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,"
    "ecc-bn,ecc-sm2-p256,symcipher,camellia,camellia-min-size=128,cmac,"
    "ctr,ofb,cbc,cfb,ecb";

static const struct RuntimeProfileDesc {
    const char *name;
#define MAX_PROFILE_NAME_LEN  32
    const char *prefix;
    size_t prefix_len;
    const char *commandsProfile;
    const char *algorithmsProfile;
    const char *attributesProfile;
    /* StateFormatLevel drives the format the TPM's state is written in and
     * how it is read.
     * Once a version of libtpms is released this field must never change afterwards
     * so that backwards compatibility for reading the state can be maintained.
     * This basically locks the name of the profile to the stateFormatLevel.
     */
    unsigned int stateFormatLevel;
#define STATE_FORMAT_LEVEL_CURRENT 7
#define STATE_FORMAT_LEVEL_UNKNOWN 0 /* JSON didn't provide StateFormatLevel; this is only
					allowed for the 'default' profile or when user
					passed JSON via SetProfile() */
/* State Format Levels:
 *  1 : write the state in format of libtpms v0.9 : only 'null' profile may have this
 *  2 : write the state in format of libtpms v0.10: the profile will be written into the state
 *  3 : Enabled ECC_Encrypt (0x199) & ECC_Decrypt (0x19a) along with disabling COMPRESSED_LIST.
 *      PERSISTENT_DATA.ppList and PERSISTENT_DATA.auditCommands became bigger and need to
 *      be written differently.
 *  4 : Camellia-192 & AES-192 enabled
 *      Session attribute isNameHashDefined was added and existing functions TPM2_PolicyNameHash
 *      and CheckPolicyAuthSession are using it.
 *  5 : Enabled TPM2_PolicyCapability (0x19b) & TPM2_PolicyParameters (0x19c)
 *  6 : Only OBJECTs for RSA keys marshal the private exponent; hierachy field is also
 *      marshalled now
 *  7 : Attribute support was added:
 *      - no-unpadded-encryption
 *      - no-sha1-signing
 *      - no-sha1-verification
 *      - no-sha1-hmac-creation
 *      - no-sha1-hmac-verification
 *      - no-sha1-hmac
 *      - fips-host
 *      - drbg-continous-test
 *      - pct
 *      - no-ecc-key-derivation
 */
    const char *description;
#define DESCRIPTION_MAX_SIZE        250
    bool allowModifications; /* user is allowed to modify algorithms profile */
} RuntimeProfileDescs[] = {
#define PROFILE_DEFAULT_IDX	0
#define PROFILE_NULL_IDX	1
    [PROFILE_DEFAULT_IDX] = {
	 /* Once libtpms v0.10 is done, this profile will become frozen */
#define DEFAULT_PROFILE_NAME   "default-v1"
	.name = DEFAULT_PROFILE_NAME,
	.commandsProfile   = defaultCommandsProfile,
	.algorithmsProfile = defaultAlgorithmsProfile,
	.stateFormatLevel  = STATE_FORMAT_LEVEL_CURRENT, /* should always be the latest */
	.description = "This profile enables all libtpms v0.10-supported commands and "
		       "algorithms. This profile is compatible with libtpms >= v0.10.",
	.allowModifications = false,
    },
    [PROFILE_NULL_IDX] = {
	/* When state has no profile, then the 'null' profile is applied which locks the
	 * TPM 2 into a set of commands and algorithms that were enable for libtpms v0.9
	 * NEVER CHANGE ANY OF THESE FIELDS!
	 */
	.name = "null",
	.commandsProfile   = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,"
			     "0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197",
	.algorithmsProfile = "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,"
			     "aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,"
			     "null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
			     "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,"
			     "ecc-bn,ecc-sm2-p256,symcipher,camellia,camellia-min-size=128,cmac,"
			     "ctr,ofb,cbc,cfb,ecb",
	.stateFormatLevel  = 1, /* NEVER change */
	.description = "The profile enables the commands and algorithms that were "
		       "enabled in libtpms v0.9. This profile is automatically used "
		       "when the state does not have a profile, for example when it was "
		       "created by libtpms v0.9 or before. This profile enables compatibility "
		       "with libtpms >= v0.9.",
	.allowModifications = false,
    }, {
	.name = "custom",
	.prefix = "custom:",
	.prefix_len = 7,
	.commandsProfile   = defaultCommandsProfile,
	.algorithmsProfile = defaultAlgorithmsProfile,
	/* no need to set attributes profile ever since user MUST provide it */
	.stateFormatLevel = 2, /* minimum is '2', algos+cmds determine higher level */
	.description = "This profile allows customization of enabled algorithms and commands. "
		       "This profile requires at least libtpms v0.10.",
	.allowModifications = true,
    }
};

LIB_EXPORT TPM_RC
RuntimeProfileInit(struct RuntimeProfile *RuntimeProfile)
{
    RuntimeAlgorithmInit(&RuntimeProfile->RuntimeAlgorithm);
    RuntimeCommandsInit(&RuntimeProfile->RuntimeCommands);
    RuntimeAttributesInit(&RuntimeProfile->RuntimeAttributes);

    RuntimeProfile->profileName = NULL;
    RuntimeProfile->runtimeProfileJSON = NULL;
    RuntimeProfile->stateFormatLevel = STATE_FORMAT_LEVEL_UNKNOWN;
    RuntimeProfile->wasNullProfile = FALSE;

    return TPM_RC_SUCCESS;
}

void
RuntimeProfileFree(struct RuntimeProfile *RuntimeProfile)
{
    RuntimeAlgorithmFree(&RuntimeProfile->RuntimeAlgorithm);
    RuntimeCommandsFree(&RuntimeProfile->RuntimeCommands);
    RuntimeAttributesFree(&RuntimeProfile->RuntimeAttributes);

    free(RuntimeProfile->profileName);
    RuntimeProfile->profileName = NULL;

    free(RuntimeProfile->runtimeProfileJSON);
    RuntimeProfile->runtimeProfileJSON = NULL;

    free(RuntimeProfile->profileDescription);
    RuntimeProfile->profileDescription = NULL;
}

static TPM_RC
RuntimeProfileSetRuntimeProfile(struct RuntimeProfile           *RuntimeProfile,
				const char                      *algorithmsProfile,
				const char                      *commandsProfile,
				const char                      *attributesProfile,
				unsigned int                    *stateFormatLevel,	// IN/OUT: required stateFormatLevel
				unsigned int                    maxStateFormatLevel	// IN: maximum allowed stateFormatLevel
				)
{
    TPM_RC retVal;

    retVal = RuntimeAttributesSetProfile(&RuntimeProfile->RuntimeAttributes, attributesProfile,
					 stateFormatLevel, maxStateFormatLevel);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    retVal = RuntimeAlgorithmSetProfile(&RuntimeProfile->RuntimeAlgorithm, algorithmsProfile,
					stateFormatLevel, maxStateFormatLevel);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    return RuntimeCommandsSetProfile(&RuntimeProfile->RuntimeCommands, commandsProfile,
				     stateFormatLevel, maxStateFormatLevel);
}

static TPM_RC
RuntimeProfileCheckJSON(const char *json)
{
#define MAP_ENTRY_REGEX "[[:space:]]*\"[^\"]+\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[[:digit:]]+)[[:space:]]*"
    const char *regex = "^\\{[[:space:]]*("MAP_ENTRY_REGEX")?(,"MAP_ENTRY_REGEX")*\\}$";
#undef MAP_ENTRY_REGEX
    TPM_RC retVal;
    regex_t r;

    if (regcomp(&r, regex, REG_EXTENDED|REG_NOSUB) != 0)
	return TPM_RC_FAILURE;

    if (regexec(&r, json, 0, NULL, 0) == REG_NOMATCH) {
	retVal = TPM_RC_NO_RESULT;
	goto exit;
    }
    retVal = TPM_RC_SUCCESS;

exit:
    regfree(&r);
    return retVal;
}

/*
 * RuntimeProfileDedupStrItems does in-place deduplication of comma-separated
 * items in a string. If an item contains '=' (rsa-min-size=) then the part
 * before the '=' is deduplicated. When deduplicating always the later item is
 * kept.
 */
static void
RuntimeProfileDedupStrItems(char *input)
{
    size_t len = strlen(input), slen;
    char *comma, *equals, *dup, *ncomma;
    char *pos = input;
    bool found;
    char exp;

    while (true) {
        comma = index(pos, ',');
        if (!comma)
            return;

        /* temporarily terminate string here */
        *comma = '\0';
        equals = index(pos, '=');
        if (equals) {
            *equals = '\0';
            exp = '=';
            slen = equals - pos;
        } else {
            exp = ',';
            slen = comma - pos;
        }

        found = false;
        ncomma = comma;
        /* search for string after the comma */
        while (true) {
            dup = strstr(ncomma + 1, pos);
            if (dup) {
                /* ensure 'dup' is a prefix of 'pos' with either ',' or '\0' before it */
                if ((dup[-1] == ',' || dup[-1] == 0) && dup[slen] == exp) {
                    memmove(pos, comma + 1, len - slen);
                    /* keep pos as-is */
                    found = true;
                    break;
                }
                /* only a prefix matched; continue search afer comma */
                ncomma = index(dup, ',');
                if (!ncomma)
                    break;
            } else {
                break;
            }
        }
        if (!found) {
            *comma = ',';
            if (equals)
               *equals = '=';
            pos = comma + 1;
        }
        len -= (slen + 1);
    }
}

static TPM_RC
RuntimeProfileGetFromJSON(const char  *json,
			  const char  *regex,
			  char       **value,
			  bool         removeDuplicates,
			  bool         allowEmptyResult)
{
    regmatch_t match[2];
    TPM_RC retVal;
    regex_t r;

    if (regcomp(&r, regex, REG_EXTENDED) != 0)
	return TPM_RC_FAILURE;

    if (regexec(&r, json, 2, match, 0) == REG_NOMATCH) {
	retVal = TPM_RC_NO_RESULT;
	goto exit;
    }

    if (match[1].rm_eo - match[1].rm_so == 0 && !allowEmptyResult) {
	retVal = TPM_RC_SIZE;
	goto exit;
    }

    *value = strndup(&json[match[1].rm_so], match[1].rm_eo - match[1].rm_so);
    if (removeDuplicates)
        RuntimeProfileDedupStrItems(*value);

    if (*value == NULL) {
	retVal= TPM_RC_MEMORY;
	goto exit;
    }
    retVal = TPM_RC_SUCCESS;

exit:
    regfree(&r);

    return retVal;
}

static TPM_RC
RuntimeProfileGetNameFromJSON(const char  *json,
			      char       **name)
{
    const char *regex = "^\\{.*[[:space:]]*\"Name\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*\\}$";
    TPM_RC retVal;
    size_t len;

    retVal = RuntimeProfileGetFromJSON(json, regex, name, false, false);
    if (!retVal) {
        len = strlen(*name);
        if (len > MAX_PROFILE_NAME_LEN)
            (*name)[MAX_PROFILE_NAME_LEN] = 0;
    }

    return retVal;
}

static TPM_RC
RuntimeProfileGetDescriptionFromJSON(const char  *json,
				     char       **description)
{
    const char *regex = "^\\{.*[[:space:]]*\"Description\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*\\}$";
    TPM_RC retVal;
    size_t len;

    retVal = RuntimeProfileGetFromJSON(json, regex, description, false, false);
    if (retVal == TPM_RC_NO_RESULT) {
	*description = NULL;
	return TPM_RC_SUCCESS;
    }
    if (retVal == TPM_RC_SUCCESS && *description != NULL) {
	len = strlen(*description);
	if (len > DESCRIPTION_MAX_SIZE)
	    (*description)[DESCRIPTION_MAX_SIZE] = 0;
    }
    return retVal;
}

static TPM_RC
GetStateFormatLevelFromJSON(const char   *json,
			    unsigned int *stateFormatLevel)
{
    const char *regex = "^\\{.*[[:space:]]*\"StateFormatLevel\"[[:space:]]*:[[:space:]]*([0-9]+).*\\}$";
    char *str = NULL;
    unsigned long v;
    TPM_RC retVal;

    retVal = RuntimeProfileGetFromJSON(json, regex, &str, false, false);
    if (retVal)
	return retVal;

    errno = 0;
    v = strtoul(str, NULL, 10);
    if (v > UINT_MAX || errno) {
	TPMLIB_LogTPM2Error("StateFormatLevel value '%s' is not a valid positive number.\n",
			    str);
	retVal = TPM_RC_VALUE;
    } else {
	*stateFormatLevel = v;
    }

    free(str);

    return retVal;
}

static TPM_RC
GetAlgorithmsProfileFromJSON(const char  *json,
			     char       **algorithmsProfile)
{
    const char *regex = "^\\{.*[[:space:]]*\"Algorithms\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*\\}$";
    TPM_RC retVal;

    retVal = RuntimeProfileGetFromJSON(json, regex, algorithmsProfile, true, false);
    if (retVal == TPM_RC_NO_RESULT) {
	*algorithmsProfile = NULL;
	retVal = 0;
    }
    return retVal;
}

static TPM_RC
GetAttributesProfileFromJSON(
			     const char  *json,
			     char       **attributesProfile
			     )
{
    const char *regex = "^\\{.*[[:space:]]*\"Attributes\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*\\}$";
    TPM_RC retVal;

    retVal = RuntimeProfileGetFromJSON(json, regex, attributesProfile, true, true);
    if (retVal == TPM_RC_NO_RESULT) {
	*attributesProfile = NULL;
	retVal = 0;
    }
    return retVal;
}

static TPM_RC
GetCommandsProfileFromJSON(const char  *json,
			   char       **commandsProfile)
{
    const char *regex = "^\\{.*[[:space:]]*\"Commands\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*\\}$";
    TPM_RC retVal;

    retVal = RuntimeProfileGetFromJSON(json, regex, commandsProfile, true, false);
    if (retVal == TPM_RC_NO_RESULT) {
	*commandsProfile = NULL;
	retVal = 0;
    }
    return retVal;
}

/* Get several parameter from the JSON profile. If jsonProfile is NULL
 * then use the null-profile.
 */
static TPM_RC
GetParametersFromJSON(const char    *jsonProfile,
		      bool           jsonProfileIsFromUser,
		      char         **profileName,
		      unsigned int  *stateFormatLevel,
		      char         **algorithmsProfile,
		      char         **commandsProfile,
		      char         **attributesProfile,
		      char         **profileDescription)
{
    TPM_RC retVal;

    if (!jsonProfile) {
	/* If no profile is given use the null-profile */
	*profileName = strdup("null");
	if (*profileName == NULL)
	    return TPM_RC_MEMORY;

	return TPM_RC_SUCCESS;
    }

    retVal = RuntimeProfileCheckJSON(jsonProfile);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    retVal = RuntimeProfileGetNameFromJSON(jsonProfile, profileName);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    if (jsonProfileIsFromUser) {
	/* StateFormatLevel may be missing */
	retVal = GetStateFormatLevelFromJSON(jsonProfile, stateFormatLevel);
	switch (retVal) {
	case TPM_RC_NO_RESULT:
	    *stateFormatLevel = STATE_FORMAT_LEVEL_UNKNOWN;
	    break;
        case TPM_RC_SUCCESS:
            break;
	default:
	    goto err_free_profilename;
	}
    } else {
	retVal = GetStateFormatLevelFromJSON(jsonProfile, stateFormatLevel);
	if (retVal != TPM_RC_SUCCESS)
	    goto err_free_profilename;
    }
    if (*stateFormatLevel > STATE_FORMAT_LEVEL_CURRENT) {
	TPMLIB_LogTPM2Error("The stateFormatLevel '%u' from the JSON exceeds the maximum supported '%u'\n",
			    *stateFormatLevel, STATE_FORMAT_LEVEL_CURRENT);
	retVal = TPM_RC_VALUE;
	goto err_free_profilename;
    }

    retVal = GetAlgorithmsProfileFromJSON(jsonProfile, algorithmsProfile);
    if (retVal != TPM_RC_SUCCESS)
	goto err_free_profilename;

    retVal = GetCommandsProfileFromJSON(jsonProfile, commandsProfile);
    if (retVal != TPM_RC_SUCCESS)
	goto err_free_algorithmsprofile;

    retVal = GetAttributesProfileFromJSON(jsonProfile, attributesProfile);
    if (retVal != TPM_RC_SUCCESS)
	goto err_free_commandsprofile;

    retVal = RuntimeProfileGetDescriptionFromJSON(jsonProfile, profileDescription);
    if (retVal != TPM_RC_SUCCESS)
	goto err_free_attributesprofile;

    return TPM_RC_SUCCESS;

err_free_attributesprofile:
    free(*attributesProfile);

err_free_commandsprofile:
    free(*commandsProfile);

err_free_algorithmsprofile:
    free(*algorithmsProfile);

err_free_profilename:
    free(*profileName);

    return retVal;
}

static TPM_RC
RuntimeProfileFormat(char          **json,
		     const char     *profileName,
		     unsigned int    stateFormatLevel,
		     const char     *algorithmsProfile,
		     const char     *commandsProfile,
		     const char     *attributesProfile,
		     const char     *profileDescription)
{
    char *ret, *nret;
    int n;

    if (!profileName)
	return TPM_RC_FAILURE;

    n = asprintf(&ret,
		 "{\"Name\":\"%s\","
		  "\"StateFormatLevel\":%d",
		  profileName, stateFormatLevel);
    if (n < 0)
	return TPM_RC_MEMORY;
    if (commandsProfile) {
	n = asprintf(&nret, "%s,\"Commands\":\"%s\"", ret, commandsProfile);
	free(ret);
	if (n < 0)
	    return TPM_RC_MEMORY;

	ret = nret;
    }
    if (algorithmsProfile) {
	n = asprintf(&nret, "%s,\"Algorithms\":\"%s\"", ret, algorithmsProfile);
	free(ret);
	if (n < 0)
	    return TPM_RC_MEMORY;

	ret = nret;
    }
    if (attributesProfile) {
	n = asprintf(&nret, "%s,\"Attributes\":\"%s\"", ret, attributesProfile);
	free(ret);
	if (n < 0)
	    return TPM_RC_MEMORY;

	ret = nret;
    }
    if (profileDescription) {
	n = asprintf(&nret, "%s,\"Description\":\"%s\"", ret, profileDescription);
	free(ret);
	if (n < 0)
	    return TPM_RC_MEMORY;

	ret = nret;
    }
    n = asprintf(&nret, "%s}", ret);
    free(ret);
    if (n < 0)
       return TPM_RC_MEMORY;

    *json = nret;

    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
RuntimeProfileFormatJSON(struct RuntimeProfile *RuntimeProfile)
{
    char *runtimeProfileJSON = NULL;
    TPM_RC retVal;

    if (!RuntimeProfile->profileName)
	return TPM_RC_FAILURE;

    retVal = RuntimeProfileFormat(&runtimeProfileJSON,
				  RuntimeProfile->profileName,
				  RuntimeProfile->stateFormatLevel,
				  RuntimeProfile->RuntimeAlgorithm.algorithmProfile,
				  RuntimeProfile->RuntimeCommands.commandsProfile,
				  RuntimeProfile->RuntimeAttributes.attributesProfile,
				  RuntimeProfile->profileDescription);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    free(RuntimeProfile->runtimeProfileJSON);
    RuntimeProfile->runtimeProfileJSON = runtimeProfileJSON;

    return TPM_RC_SUCCESS;
}

static int
RuntimeProfileNameMatch(const struct RuntimeProfileDesc *rp,
                        const char *profileName)
{
    if (!strcmp(rp->name, profileName))
        return true;
    if (rp->prefix &&
        !strncmp(rp->prefix, profileName, rp->prefix_len)) {
        return true;
    }
    return false;
}

static const struct RuntimeProfileDesc *
RuntimeProfileFindByName(const char	*profileName,
			 bool            jsonProfileIsFromUser,
			 unsigned int    stateFormatLevel,
			 const char     *commandsProfile,
			 const char     *algorithmsProfile,
			 const char     *attributesProfile,
			 const char     *profileDescription)
{
    const struct RuntimeProfileDesc *rp = NULL;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(RuntimeProfileDescs); i++) {
	if (RuntimeProfileNameMatch(&RuntimeProfileDescs[i], profileName)) {
	    rp = &RuntimeProfileDescs[i];

	    if (!rp->allowModifications) {
		/* user cannot set command or algorithms profile */
		if (jsonProfileIsFromUser &&
		    (stateFormatLevel != STATE_FORMAT_LEVEL_UNKNOWN ||
		     commandsProfile || algorithmsProfile || attributesProfile || profileDescription)) {
		    TPMLIB_LogTPM2Error("The '%s' profile does not allow any customization\n",
					rp->name);
		    return NULL;
		}
	    }
	    return rp;
	}
    }
    return NULL;
}

/*
 * Set the given RuntimeProfile to the profile in JSON format. The profile may
 * be set by the user and in this case the jsonProfileIsFromUser is set to
 * true. Otherwise, it may originate from the TPM 2's state file and in this
 * case jsonProfileIsFromUser is false.
 * If jsonProfileIsFromUser is 'true' then the the default profile will get
 * the latest StateFormatLevel version number, otherwise it will get the
 * StateFormatLevel '1' if no stateFormatLevel field is found in the JSON
 * profile.
 * @RuntimeProfile: the RuntimeProfile to assign values to
 * @jsonProfile: optional JSON-formatted profile; if NULL then null-profile
 *               will be used
 * @jsonProfileIsFromUser: whether the user provided the profile (TRUE) or it
 *                         was read from state (FALSE)
 */
LIB_EXPORT TPM_RC
RuntimeProfileSet(struct RuntimeProfile *RuntimeProfile,
		  const char	        *jsonProfile,
		  bool                   jsonProfileIsFromUser)
{
    unsigned int stateFormatLevelJSON = STATE_FORMAT_LEVEL_UNKNOWN;
    const struct RuntimeProfileDesc *rp = NULL;
    unsigned int maxStateFormatLevel;
    char *runtimeProfileJSON = NULL;
    char *profileDescription = NULL;
    char *algorithmsProfile = NULL;
    char *attributesProfile = NULL;
    char *commandsProfile = NULL;
    char *profileName = NULL;
    TPM_RC retVal;

    retVal = GetParametersFromJSON(jsonProfile, jsonProfileIsFromUser,
				   &profileName, &stateFormatLevelJSON,
				   &algorithmsProfile, &commandsProfile,
				   &attributesProfile,
				   &profileDescription);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    /* profiles read from state must also have an existing profile */
    rp = RuntimeProfileFindByName(profileName,
				  jsonProfileIsFromUser,
				  stateFormatLevelJSON,
				  commandsProfile,
				  algorithmsProfile,
				  attributesProfile,
				  profileDescription);
    if (!rp) {
	retVal = TPM_RC_VALUE;
	goto error;
    }

    retVal = TPM_RC_MEMORY;
    if (!attributesProfile && rp->attributesProfile && !rp->allowModifications) {
        /* only use default if no modications are allowed; use NULL otherwise */
	if (!(attributesProfile = strdup(rp->attributesProfile)))
	    goto error;
    }
    if (!algorithmsProfile && rp->algorithmsProfile) {
	if (!(algorithmsProfile = strdup(rp->algorithmsProfile)))
	    goto error;
    }
    if (!commandsProfile && rp->commandsProfile) {
	if (!(commandsProfile = strdup(rp->commandsProfile)))
	    goto error;
    }
    if (!profileDescription && rp->description) {
	if (!(profileDescription = strdup(rp->description)))
	    goto error;
    }

    if (jsonProfileIsFromUser || stateFormatLevelJSON == STATE_FORMAT_LEVEL_UNKNOWN) {
	if (!rp->allowModifications) {
	    /* StateFormatLevels are controlled by internal profile */
	    maxStateFormatLevel = rp->stateFormatLevel;
	    RuntimeProfile->stateFormatLevel = rp->stateFormatLevel;
	} else {
	    if (stateFormatLevelJSON != STATE_FORMAT_LEVEL_UNKNOWN) {
		if (stateFormatLevelJSON < 2) {
		    TPMLIB_LogTPM2Error("The minimum required StateFormatLevel for '%s' profile is '2'\n",
					profileName);
		    goto error;
		}
		maxStateFormatLevel = stateFormatLevelJSON;
	    } else {
		maxStateFormatLevel = ~0;
	    }
	    /* User has some control over StateFormatLevel */
	    RuntimeProfile->stateFormatLevel = stateFormatLevelJSON;
	}
    } else {
	/* JSON was from TPM 2 state */
	maxStateFormatLevel = stateFormatLevelJSON;
	RuntimeProfile->stateFormatLevel = stateFormatLevelJSON;
    }
    retVal = RuntimeProfileSetRuntimeProfile(RuntimeProfile,
					     algorithmsProfile,
					     commandsProfile,
					     attributesProfile,
					     &RuntimeProfile->stateFormatLevel,
					     maxStateFormatLevel);
    if (retVal != TPM_RC_SUCCESS)
	goto error;
    assert(maxStateFormatLevel >= RuntimeProfile->stateFormatLevel);

    retVal = RuntimeProfileFormat(&runtimeProfileJSON, profileName,
				  RuntimeProfile->stateFormatLevel, algorithmsProfile,
				  commandsProfile, attributesProfile, profileDescription);
    if (retVal != TPM_RC_SUCCESS)
	goto error;

    TPMLIB_LogPrintf("%s @ %u: runtimeProfile: %s\n", __func__, __LINE__, runtimeProfileJSON);

    free(RuntimeProfile->runtimeProfileJSON);
    RuntimeProfile->runtimeProfileJSON = runtimeProfileJSON;

    free(RuntimeProfile->RuntimeAlgorithm.algorithmProfile);
    RuntimeProfile->RuntimeAlgorithm.algorithmProfile = algorithmsProfile;

    free(RuntimeProfile->RuntimeCommands.commandsProfile);
    RuntimeProfile->RuntimeCommands.commandsProfile = commandsProfile;

    free(RuntimeProfile->RuntimeAttributes.attributesProfile);
    RuntimeProfile->RuntimeAttributes.attributesProfile = attributesProfile;

    free(RuntimeProfile->profileName);
    RuntimeProfile->profileName = profileName;

    free(RuntimeProfile->profileDescription);
    RuntimeProfile->profileDescription = profileDescription;

    /* Indicate whether the profile was mapped to the default profile due to
     * a NULL pointer read from the state.
     */
    RuntimeProfile->wasNullProfile = (jsonProfile == NULL) && (jsonProfileIsFromUser == FALSE);
    /* Another way is if the user passed in the null profile */
    if (jsonProfileIsFromUser && !strcmp("null", profileName))
	RuntimeProfile->wasNullProfile = true;

    return TPM_RC_SUCCESS;

error:
    free(profileDescription);
    free(attributesProfile);
    free(commandsProfile);
    free(algorithmsProfile);
    free(profileName);

    return retVal;
}

LIB_EXPORT const char *
RuntimeProfileGetJSON(struct RuntimeProfile *RuntimeProfile)
{
    return RuntimeProfile->runtimeProfileJSON;
}

/*
 * Test whether the given jsonProfile is valid.
 *
 * @RuntimeProfile: the RuntimeProfile to assign values to
 * @jsonProfile: optional JSON-formatted profile; if NULL then null-profile
 *               will be used
 * @jsonProfileIsFromUser: whether the user provided the profile (TRUE) or it
 *                         was read from state (FALSE)
 */
LIB_EXPORT TPM_RC
RuntimeProfileTest(struct RuntimeProfile *RuntimeProfile,
		   const char	         *jsonProfile,
		   bool                   jsonProfileIsFromUser)
{
    unsigned int stateFormatLevelJSON = STATE_FORMAT_LEVEL_UNKNOWN;
    unsigned int stateFormatLevel = STATE_FORMAT_LEVEL_UNKNOWN;
    const struct RuntimeProfileDesc *rp = NULL;
    unsigned int maxStateFormatLevel = ~0;
    char *profileDescription = NULL;
    char *algorithmsProfile = NULL;
    char *attributesProfile = NULL;
    char *commandsProfile = NULL;
    char *profileName = NULL;
    char *oldProfile = NULL;
    TPM_RC retVal;

    retVal = GetParametersFromJSON(jsonProfile, jsonProfileIsFromUser,
				   &profileName, &stateFormatLevelJSON,
				   &algorithmsProfile, &commandsProfile,
				   &attributesProfile,
				   &profileDescription);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    rp = RuntimeProfileFindByName(profileName,
				  jsonProfileIsFromUser,
				  stateFormatLevelJSON,
				  commandsProfile,
				  algorithmsProfile,
				  attributesProfile,
				  profileDescription);
    if (!rp) {
	retVal = TPM_RC_VALUE;
	goto error;
    }

    if (stateFormatLevelJSON != STATE_FORMAT_LEVEL_UNKNOWN)
	maxStateFormatLevel = stateFormatLevelJSON;

    if (attributesProfile) {
	/* Test the attributes profile if one was given */
	retVal = RuntimeAttributesSwitchProfile(&RuntimeProfile->RuntimeAttributes,
                                                attributesProfile, maxStateFormatLevel,
                                                &oldProfile);
	if (retVal == TPM_RC_SUCCESS)
	    retVal = RuntimeAttributesSetProfile(&RuntimeProfile->RuntimeAttributes,
						 oldProfile, &stateFormatLevel,
						 ~0);
    }

    if (algorithmsProfile) {
	/* Test the algorithms profile if one was given */
	retVal = RuntimeAlgorithmSwitchProfile(&RuntimeProfile->RuntimeAlgorithm,
					       algorithmsProfile, maxStateFormatLevel,
					       &oldProfile);
	if (retVal == TPM_RC_SUCCESS)
	    retVal = RuntimeAlgorithmSetProfile(&RuntimeProfile->RuntimeAlgorithm,
						oldProfile, &stateFormatLevel,
						~0);
    }

    if (commandsProfile) {
	/* Test the commands profile if one was given */
	retVal = RuntimeCommandsSwitchProfile(&RuntimeProfile->RuntimeCommands,
					      commandsProfile, maxStateFormatLevel,
					      &oldProfile);
	if (retVal == TPM_RC_SUCCESS)
	    retVal = RuntimeCommandsSetProfile(&RuntimeProfile->RuntimeCommands,
					       oldProfile, &stateFormatLevel,
					       ~0);
    }

error:
    free(profileDescription);
    free(attributesProfile);
    free(commandsProfile);
    free(algorithmsProfile);
    free(profileName);

    return retVal;
}

LIB_EXPORT BOOL
RuntimeProfileWasNullProfile(struct RuntimeProfile *RuntimeProfile)
{
    return RuntimeProfile->wasNullProfile;
}

LIB_EXPORT TPM_RC
RuntimeProfileGetByIndex(size_t  idx,
			 char    **runtimeProfileJSON)
{
    if (idx >= ARRAY_SIZE(RuntimeProfileDescs))
	return TPM_RC_VALUE;
    return RuntimeProfileFormat(runtimeProfileJSON,
				RuntimeProfileDescs[idx].name,
				RuntimeProfileDescs[idx].stateFormatLevel,
				RuntimeProfileDescs[idx].algorithmsProfile,
				RuntimeProfileDescs[idx].commandsProfile,
				RuntimeProfileDescs[idx].attributesProfile,
				RuntimeProfileDescs[idx].description);
}

/*
 * Determine the SEED_COMPAT_LEVEL that a profile can support. The
 * SEED_COMPAT_LEVEL must be available on the earliest version of libtpms
 * where the profile can run. If a profile for example can run on libtpms v0.9
 * then this function must return only this SEED_COMPAT_LEVEL that was
 * available in v0.9, which was SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX.
 * The SEED_COMPAT_LEVEL depends on the stateFormatLevel that in turn depends
 * on the libtpms version.
 */
LIB_EXPORT SEED_COMPAT_LEVEL
RuntimeProfileGetSeedCompatLevel(void)
{
    MUST_BE(SEED_COMPAT_LEVEL_LAST == 1); // force update when this changes

    switch (g_RuntimeProfile.stateFormatLevel) {
    case 1: /* profile runs on v0.9 */
	return SEED_COMPAT_LEVEL_RSA_PRIME_ADJUST_FIX;

    case 2 ... 7: /* profile runs on v0.10 */ {
	MUST_BE(STATE_FORMAT_LEVEL_CURRENT == 7); // force update when this changes
	return SEED_COMPAT_LEVEL_LAST;
    }

    default:
	FAIL(FATAL_ERROR_INTERNAL);
    }
}

LIB_EXPORT BOOL
RuntimeProfileRequiresAttributeFlags(struct RuntimeProfile *RuntimeProfile,
                                     unsigned int           attributeFlags)
{
    return RuntimeAttributeCheckRequired(&RuntimeProfile->RuntimeAttributes,
					 attributeFlags);
}
