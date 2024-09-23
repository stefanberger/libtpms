/********************************************************************************/
/*										*/
/*			 TPM 2 Commands Runtime Disablement 			*/
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

#include "Tpm.h"
#include "tpm_library_intern.h"

#if VENDOR_COMMAND_COUNT != 0
# error Vendor commands not supported
#endif

#define CMD_SEPARATOR_STR ","

/* List of supported commands sorted by command codes.
 * Commands can be disabled that are optional or recommended in automotive
 * thin profile.
 */
static const struct {
    const char *name;
    BOOL        canBeDisabled;
    UINT16      stateFormatLevel;
} s_CommandProperties[NUM_ENTRIES_COMMAND_PROPERTIES] = {
#define COMMAND(NAME, CAN_BE_DISABLED, SFL) \
    [ CcToIdx(TPM_CC_ ## NAME) ] = { .name = CC_ ## NAME ? STRINGIFY(NAME) : NULL, \
                                     .canBeDisabled = CAN_BE_DISABLED, \
                                     .stateFormatLevel = SFL }
    COMMAND(NV_UndefineSpaceSpecial, true, 1),
    COMMAND(EvictControl, false, 1),
    COMMAND(HierarchyControl, true, 1),
    COMMAND(NV_UndefineSpace, true, 1),
    COMMAND(ChangeEPS, true, 1),
    COMMAND(ChangePPS, true, 1),
    COMMAND(Clear, true, 1),
    COMMAND(ClearControl, true, 1),
    COMMAND(ClockSet, true, 1),
    COMMAND(HierarchyChangeAuth, false, 1),
    COMMAND(NV_DefineSpace, true, 1),
    COMMAND(PCR_Allocate, false, 1), // swtpm_setup needs it
    COMMAND(PCR_SetAuthPolicy, true, 1),
    COMMAND(PP_Commands, true, 1),
    COMMAND(SetPrimaryPolicy, true, 1),
    COMMAND(FieldUpgradeStart, true, 0), // not supported
    COMMAND(ClockRateAdjust, true, 1),
    COMMAND(CreatePrimary, false, 1),
    COMMAND(NV_GlobalWriteLock, true, 1),
    COMMAND(GetCommandAuditDigest, true, 1),
    COMMAND(NV_Increment, true, 1),
    COMMAND(NV_SetBits, true, 1),
    COMMAND(NV_Extend, true, 1),
    COMMAND(NV_Write, true, 1),
    COMMAND(NV_WriteLock, true, 1),
    COMMAND(DictionaryAttackLockReset, true, 1),
    COMMAND(DictionaryAttackParameters, true, 1),
    COMMAND(NV_ChangeAuth, true, 1),
    COMMAND(PCR_Event, false, 1),
    COMMAND(PCR_Reset, true, 1),
    COMMAND(SequenceComplete, true, 1),
    COMMAND(SetAlgorithmSet, true, 1),
    COMMAND(SetCommandCodeAuditStatus, true, 1),
    COMMAND(FieldUpgradeData, true, 0), // not supported
    COMMAND(IncrementalSelfTest, true, 1),
    COMMAND(SelfTest, false, 1),
    COMMAND(Startup, false, 1),
    COMMAND(Shutdown, false, 1),
    COMMAND(StirRandom, true, 1),
    COMMAND(ActivateCredential, true, 1),
    COMMAND(Certify, false, 1),
    COMMAND(PolicyNV, true, 1),
    COMMAND(CertifyCreation, true, 1),
    COMMAND(Duplicate, true, 1),
    COMMAND(GetTime, true, 1),
    COMMAND(GetSessionAuditDigest, true, 1),
    COMMAND(NV_Read, false, 1),
    COMMAND(NV_ReadLock, true, 1),
    COMMAND(ObjectChangeAuth, true, 1),
    COMMAND(PolicySecret, true, 1),
    COMMAND(Rewrap, true, 1),
    COMMAND(Create, false, 1),
    COMMAND(ECDH_ZGen, true, 1),
    COMMAND(MAC, true, 1),
    /* HMAC is same as MAC */
    COMMAND(Import, false, 1),
    COMMAND(Load, false, 1),
    COMMAND(Quote, false, 1),
    COMMAND(RSA_Decrypt, true, 1),
    COMMAND(MAC_Start, true, 1),
    /* HMAC_start is same as MAC_Start */
    COMMAND(SequenceUpdate, false, 1),
    COMMAND(Sign, true, 1),
    COMMAND(Unseal, true, 1),
    COMMAND(PolicySigned, true, 1),
    COMMAND(ContextLoad, true, 1),
    COMMAND(ContextSave, true, 1),
    COMMAND(ECDH_KeyGen, true, 1),
    COMMAND(EncryptDecrypt, true, 1),
    COMMAND(FlushContext, false, 1),
    COMMAND(LoadExternal, true, 1),
    COMMAND(MakeCredential, true, 1),
    COMMAND(NV_ReadPublic, false, 1),
    COMMAND(PolicyAuthorize, true, 1),
    COMMAND(PolicyAuthValue, true, 1),
    COMMAND(PolicyCommandCode, true, 1),
    COMMAND(PolicyCounterTimer, true, 1),
    COMMAND(PolicyCpHash, true, 1),
    COMMAND(PolicyLocality, true, 1),
    COMMAND(PolicyNameHash, true, 1),
    COMMAND(PolicyOR, true, 1),
    COMMAND(PolicyTicket, true, 1),
    COMMAND(ReadPublic, false, 1),
    COMMAND(RSA_Encrypt, true, 1),
    COMMAND(StartAuthSession, false, 1),
    COMMAND(VerifySignature, true, 1),
    COMMAND(ECC_Parameters, true, 1),
    COMMAND(FirmwareRead, true, 0),
    COMMAND(GetCapability, false, 1),
    COMMAND(GetRandom, true, 1),
    COMMAND(GetTestResult, false, 1),
    COMMAND(Hash, false, 1),
    COMMAND(PCR_Read, false, 1),
    COMMAND(PolicyPCR, true, 1),
    COMMAND(PolicyRestart, true, 1),
    COMMAND(ReadClock, true, 1),
    COMMAND(PCR_Extend, false, 1),
    COMMAND(PCR_SetAuthValue, true, 1),
    COMMAND(NV_Certify, true, 1),
    COMMAND(EventSequenceComplete, false, 1),
    COMMAND(HashSequenceStart, false, 1),
    COMMAND(PolicyPhysicalPresence, true, 1),
    COMMAND(PolicyDuplicationSelect, true, 1),
    COMMAND(PolicyGetDigest, true, 1),
    COMMAND(TestParms, true, 1),
    COMMAND(Commit, true, 1),
    COMMAND(PolicyPassword, true, 1),
    COMMAND(ZGen_2Phase, true, 1),
    COMMAND(EC_Ephemeral, true, 1),
    COMMAND(PolicyNvWritten, true, 1),
    COMMAND(PolicyTemplate, true, 1),
    COMMAND(CreateLoaded, true, 1),
    COMMAND(PolicyAuthorizeNV, true, 1),
    COMMAND(EncryptDecrypt2, true, 1),
    COMMAND(AC_GetCapability, true, 0), // not supported
    COMMAND(AC_Send, true, 0), // not supported
    COMMAND(Policy_AC_SendSelect, true, 0), // not supported
    COMMAND(CertifyX509, true, 1),
    COMMAND(ACT_SetTimeout, true, 0), // not supported
    COMMAND(ECC_Encrypt, true, 3),
    COMMAND(ECC_Decrypt, true, 3),
    COMMAND(PolicyCapability, true, 5),
    COMMAND(PolicyParameters, true, 5),
    COMMAND(NV_DefineSpace2, true, 0), // not supported
    COMMAND(NV_ReadPublic2, true, 0), // not supported
    COMMAND(SetCapability, true, 0), // not supported
    /* all new commands added here MUST have CAN_BE_DISABLE = true */
#undef COMMAND
};
MUST_BE(TPM_CC_LAST == TPM_CC_SetCapability); /* force update of above list when new commands added */

static void
RuntimeCommandsEnableAllCommands(struct RuntimeCommands *RuntimeCommands,
				 unsigned int            maxStateFormatLevel)
{
    COMMAND_INDEX commandIndex;

    assert(maxStateFormatLevel >= 1);

    MemorySet(RuntimeCommands->enabledCommands, 0 , sizeof(RuntimeCommands->enabledCommands));

    for (commandIndex = 0; commandIndex < ARRAY_SIZE(s_CommandProperties); commandIndex++) {
	/* skip over unsupported commands or those exceeding the max. stateFormatLevel */
	if (!s_CommandProperties[commandIndex].name ||
	    s_CommandProperties[commandIndex].stateFormatLevel > maxStateFormatLevel)
	    continue;
	SET_BIT(IdxToCc(commandIndex), RuntimeCommands->enabledCommands);
    }
}

LIB_EXPORT void
RuntimeCommandsInit(struct RuntimeCommands *RuntimeCommands)
{
    MemorySet(RuntimeCommands, 0, sizeof(*RuntimeCommands));
}

LIB_EXPORT void
RuntimeCommandsFree(struct RuntimeCommands *RuntimeCommands)
{
    free(RuntimeCommands->commandsProfile);
    RuntimeCommands->commandsProfile = NULL;
}

/* Set the default profile with all commands enabled */
static void
RuntimeCommandsSetDefault(struct RuntimeCommands *RuntimeCommands,
			  unsigned int            maxStateFormatLevel)
{
    RuntimeCommandsFree(RuntimeCommands);
    RuntimeCommandsInit(RuntimeCommands);
    RuntimeCommandsEnableAllCommands(RuntimeCommands, maxStateFormatLevel);
}

/* Parse a range of command codes or a single command code. The character following
 * the parse input must either ',' or NUL.
 */
static int
parseRange(const char *buffer,
	   TPM_CC *commandCodeLo, TPM_CC *commandCodeHi)
{
    char *endptr;
    unsigned long v;

    errno = 0;
    v = strtoul(buffer, &endptr, 0);
    if (errno != 0)
	return -1;
    if (v > (unsigned int)~0)
	return -1;
    *commandCodeLo = v;

    if (endptr[0] == '-') {
	v = strtoul(&endptr[1], &endptr, 0);
	if (errno != 0)
	    return -1;
	if (v > (unsigned int)~0)
	    return -1;
	*commandCodeHi = v;
    } else {
	*commandCodeHi = *commandCodeLo;
    }

    if (endptr[0] != ',' && endptr[0] != '\0')
	return -1;

    return 0;
}

/* Set the given profile and runtime-enable the given commands. A NULL pointer
 * for the profile command sets the default profile which enables all commands.
 *
 * This function will adjust the stateFormatLevel to the number required for the
 * given algorithms and key sizes.
 */
LIB_EXPORT
TPM_RC
RuntimeCommandsSetProfile(struct RuntimeCommands *RuntimeCommands,
			  const char		 *newProfile,		// IN: comma-separated list of command codes and ranges
			  unsigned int           *stateFormatLevel,	// IN/OUT: stateFormatLevel
			  unsigned int            maxStateFormatLevel	// IN: maximum stateFormatLevel
			  )
{
    TPM_CC commandCodeLo, commandCodeHi;
    TPM_RC retVal = TPM_RC_VALUE;
    const char *token, *comma;
    COMMAND_INDEX commandIndex;
    size_t toklen;

    /* NULL pointer for profile enables all */
    if (!newProfile) {
	RuntimeCommandsSetDefault(RuntimeCommands, maxStateFormatLevel);
	return TPM_RC_SUCCESS;
    }

    MemorySet(&RuntimeCommands->enabledCommands, 0, sizeof(RuntimeCommands->enabledCommands));

    token = newProfile;
    while (1) {
	/* expecting: 20 or 0x32 or 20-30 or 0x30x-0x50 */
	comma = strchr(token, ',');
	if (comma)
	    toklen = (size_t)(comma - token);
	else
	    toklen = strlen(token);

	if (parseRange(token, &commandCodeLo, &commandCodeHi) < 0) {
	    TPMLIB_LogTPM2Error("Requested command range %.*s cannot be parsed.\n",
				(int)toklen, token);
	    goto exit;
	}
	if (CcToIdx(commandCodeLo) >= ARRAY_SIZE(s_CommandProperties) ||
	    CcToIdx(commandCodeHi) >= ARRAY_SIZE(s_CommandProperties)) {
	    TPMLIB_LogTPM2Error("Requested command range %.*s is invalid.\n",
				(int)toklen, token);
	    goto exit;
	}
	for (commandIndex = CcToIdx(commandCodeLo);
	     commandIndex <= CcToIdx(commandCodeHi);
	     commandIndex++) {
	    /* must not select unsupported commands */
	    if (!s_CommandProperties[commandIndex].name) {
		TPMLIB_LogTPM2Error("Requested command code 0x%x is not implemented.\n",
				    IdxToCc(commandIndex));
		goto exit;
	    }
	    if (s_CommandProperties[commandIndex].stateFormatLevel > maxStateFormatLevel) {
	        TPMLIB_LogTPM2Error("Requested command code 0x%x requires stateFormatLevel '%u' but maximum allowed is '%u'.\n",
                                    IdxToCc(commandIndex),
                                    s_CommandProperties[commandIndex].stateFormatLevel,
                                    maxStateFormatLevel);
                goto exit;
	    }
	    SET_BIT(IdxToCc(commandIndex), RuntimeCommands->enabledCommands);
	    assert(s_CommandProperties[commandIndex].stateFormatLevel > 0);
	    *stateFormatLevel = MAX(*stateFormatLevel,
	                            s_CommandProperties[commandIndex].stateFormatLevel);
	}

	if (!comma)
	    break;
	token = &comma[1];
    }

    /* reconcile chosen commands with those required */
    for (commandIndex = 0; commandIndex < ARRAY_SIZE(s_CommandProperties); commandIndex++) {
        if (!s_CommandProperties[commandIndex].name)
            continue;
        if (!s_CommandProperties[commandIndex].canBeDisabled &&
            !TEST_BIT(IdxToCc(commandIndex), RuntimeCommands->enabledCommands)) {
            TPMLIB_LogTPM2Error("Command %s (0x%x) must be enabled.\n",
                                s_CommandProperties[commandIndex].name, IdxToCc(commandIndex));
            goto exit;
        }
    }


    retVal = TPM_RC_SUCCESS;

exit:
    if (retVal != TPM_RC_SUCCESS)
	RuntimeCommandsSetDefault(RuntimeCommands, ~0);

    return retVal;
}

/* Switch to a new profile and return the old one. In case an error
 * occurs the old profile is again activated and an error code returned.
 */
LIB_EXPORT TPM_RC
RuntimeCommandsSwitchProfile(struct RuntimeCommands   *RuntimeCommands,
			     const char               *newProfile,
			     unsigned int              maxStateFormatLevel,
			     char                    **oldProfile)
{
    TPM_RC retVal;
    unsigned int stateFormatLevel = 0; // ignored

    *oldProfile = RuntimeCommands->commandsProfile;
    RuntimeCommands->commandsProfile = NULL;

    retVal = RuntimeCommandsSetProfile(RuntimeCommands, newProfile,
				       &stateFormatLevel, maxStateFormatLevel);
    if (retVal != TPM_RC_SUCCESS) {
	RuntimeCommandsSetProfile(RuntimeCommands, *oldProfile,
				  &stateFormatLevel, maxStateFormatLevel);
	*oldProfile = NULL;
    }
    return retVal;
}

/* Check whether the given command is runtime-disabled */
LIB_EXPORT BOOL
RuntimeCommandsCheckEnabled(struct RuntimeCommands *RuntimeCommands,
			    TPM_CC	            commandCode      // IN: the commandCode to check
			    )
{
    if (CcToIdx(commandCode) >= ARRAY_SIZE(s_CommandProperties)) {
        TPMLIB_LogPrintf("IsEnabled(0x%x): out-of-range command code\n",
                         commandCode);
        return FALSE;
    }
    TPMLIB_LogPrintf("IsEnEnabled(0x%x = '%s'): %d\n",
		     commandCode,
		     s_CommandProperties[CcToIdx(commandCode)].name,
		     TEST_BIT(commandCode, RuntimeCommands->enabledCommands));
    if (!TEST_BIT(commandCode, RuntimeCommands->enabledCommands))
	return FALSE;
    return TRUE;
}

/* Get the number of enabled commands. */
LIB_EXPORT UINT32
RuntimeCommandsCountEnabled(struct RuntimeCommands *RuntimeCommands)
{
    TPM_CC commandCode;
    UINT32 count = 0;

    for (commandCode = TPM_CC_FIRST;
	 commandCode < sizeof(RuntimeCommands->enabledCommands) * 8;
	 commandCode++) {
	if (TEST_BIT(commandCode, RuntimeCommands->enabledCommands))
	    count++;
    }
    return count;
}

/* Append a command code or command code range to an optional given buffer.
 * Return a new buffer and free the given buffer.
 */
static char *
RuntimeCommandPrint(char           *buffer,
		    BOOL            first,
		    COMMAND_INDEX   commandCodeLo,
		    COMMAND_INDEX   commandCodeHi)
{
    char bufferlo[12], bufferhi[12];
    char *nbuffer = NULL;
    int n;

    snprintf(bufferlo, sizeof(bufferlo), "0x%x", commandCodeLo);
    if (commandCodeLo == commandCodeHi) {
	n = asprintf(&nbuffer, "%s%s%s",
		     buffer ? buffer : "",
		     first ? "" : CMD_SEPARATOR_STR,
		     bufferlo);
    } else {
	snprintf(bufferhi, sizeof(bufferhi), "0x%x", commandCodeHi);
	n = asprintf(&nbuffer, "%s%s%s-%s",
		     buffer ? buffer : "",
		     first ? "" : CMD_SEPARATOR_STR,
		     bufferlo, bufferhi);
    }
    free(buffer);
    if (n < 0)
	return NULL;

    return nbuffer;
}

LIB_EXPORT char *
RuntimeCommandsPrint(struct RuntimeCommands    *RuntimeCommands,
		     enum RuntimeCommandType    rct)
{
    COMMAND_INDEX commandIndex, commandCodeLo = 0, commandCodeHi = 0;
    char *buffer, *nbuffer = NULL;
    BOOL first = true, doPrint;
    int n;

    buffer = strdup("\"");
    if (!buffer)
	return NULL;

    for (commandIndex = 0; commandIndex < ARRAY_SIZE(s_CommandProperties); commandIndex++) {
	// skip over unsupported algorithms
	if (!s_CommandProperties[commandIndex].name)
	    continue;

	switch (rct) {
	case RUNTIME_CMD_IMPLEMENTED:
	    // no filter
	    doPrint = true;
	    break;
	case RUNTIME_CMD_CAN_BE_DISABLED:
	    doPrint = s_CommandProperties[commandIndex].canBeDisabled;
	    break;
	case RUNTIME_CMD_ENABLED:
	    // skip over disabled ones
	    doPrint = RuntimeCommandsCheckEnabled(RuntimeCommands, IdxToCc(commandIndex));
	    break;
	case RUNTIME_CMD_DISABLED:
	    // skip over enabled ones
	    doPrint = !RuntimeCommandsCheckEnabled(RuntimeCommands, IdxToCc(commandIndex));
	    break;
	default:
	    continue;
	}

	if (doPrint) {
	    if (commandCodeLo == 0) {
		commandCodeLo = commandCodeHi = IdxToCc(commandIndex);
		continue;
	    }
	    if (commandCodeHi + 1 == (COMMAND_INDEX)IdxToCc(commandIndex)) {
		commandCodeHi++;
		continue;
	    }
	}

	if (!doPrint && commandCodeLo == 0)
	    continue;

	buffer = RuntimeCommandPrint(buffer, first, commandCodeLo, commandCodeHi);
	if (!buffer)
	    return NULL;

	first = false;

	if (doPrint) {
	    commandCodeLo = commandCodeHi = IdxToCc(commandIndex);
	} else {
	    commandCodeLo = 0;
	}
    }

    if (commandCodeLo != 0)
	buffer = RuntimeCommandPrint(buffer, first, commandCodeLo, commandCodeHi);

    n = asprintf(&nbuffer, "%s\"", buffer);
    free(buffer);
    if (n < 0)
	return NULL;

    return nbuffer;
}
