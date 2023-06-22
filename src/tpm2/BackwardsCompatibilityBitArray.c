/********************************************************************************/
/*										*/
/*	Backwards compatibility support related to command code arrays		*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2023.						*/
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

#include "BackwardsCompatibilityBitArray.h"

/* The following array contains exactly the commands that libtpms v0.9 had enabled
 * when 'compressed lists' were used. Do not change this array anymore!
 * A bit in the PERSISTEN_DATA.auditCommands array corresponds to the index in
 * this array where the command code can be found.
 */
static const struct {
    TPM_CC cc;

#define ENTRY(CC, INDEX)  \
    [INDEX] = { .cc = CC }

} CCToCompressedListIndex[] = {
    ENTRY(TPM_CC_NV_UndefineSpaceSpecial, 0),
    ENTRY(TPM_CC_EvictControl, 1),
    ENTRY(TPM_CC_HierarchyControl, 2),
    ENTRY(TPM_CC_NV_UndefineSpace, 3),
    ENTRY(TPM_CC_ChangeEPS, 4),
    ENTRY(TPM_CC_ChangePPS, 5),
    ENTRY(TPM_CC_Clear, 6),
    ENTRY(TPM_CC_ClearControl, 7),
    ENTRY(TPM_CC_ClockSet, 8),
    ENTRY(TPM_CC_HierarchyChangeAuth, 9),
    ENTRY(TPM_CC_NV_DefineSpace, 10),
    ENTRY(TPM_CC_PCR_Allocate, 11),
    ENTRY(TPM_CC_PCR_SetAuthPolicy, 12),
    ENTRY(TPM_CC_PP_Commands, 13),
    ENTRY(TPM_CC_SetPrimaryPolicy, 14),
    /* CC_FieldUpdateStart */
    ENTRY(TPM_CC_ClockRateAdjust, 15),
    ENTRY(TPM_CC_CreatePrimary, 16),
    ENTRY(TPM_CC_NV_GlobalWriteLock, 17),
    ENTRY(TPM_CC_GetCommandAuditDigest, 18),
    ENTRY(TPM_CC_NV_Increment, 19),
    ENTRY(TPM_CC_NV_SetBits, 20),
    ENTRY(TPM_CC_NV_Extend, 21),
    ENTRY(TPM_CC_NV_Write, 22),
    ENTRY(TPM_CC_NV_WriteLock, 23),
    ENTRY(TPM_CC_DictionaryAttackLockReset, 24),
    ENTRY(TPM_CC_DictionaryAttackParameters, 25),
    ENTRY(TPM_CC_NV_ChangeAuth, 26),
    ENTRY(TPM_CC_PCR_Event, 27),
    ENTRY(TPM_CC_PCR_Reset, 28),
    ENTRY(TPM_CC_SequenceComplete, 29),
    ENTRY(TPM_CC_SetAlgorithmSet, 30),
    ENTRY(TPM_CC_SetCommandCodeAuditStatus, 31),
    /* CC_FieldUpgradeData */
    ENTRY(TPM_CC_IncrementalSelfTest, 32),
    ENTRY(TPM_CC_SelfTest, 33),
    ENTRY(TPM_CC_Startup, 34),
    ENTRY(TPM_CC_Shutdown, 35),
    ENTRY(TPM_CC_StirRandom, 36),
    ENTRY(TPM_CC_ActivateCredential, 37),
    ENTRY(TPM_CC_Certify, 38),
    ENTRY(TPM_CC_PolicyNV, 39),
    ENTRY(TPM_CC_CertifyCreation, 40),
    ENTRY(TPM_CC_Duplicate, 41),
    ENTRY(TPM_CC_GetTime, 42),
    ENTRY(TPM_CC_GetSessionAuditDigest, 43),
    ENTRY(TPM_CC_NV_Read, 44),
    ENTRY(TPM_CC_NV_ReadLock, 45),
    ENTRY(TPM_CC_ObjectChangeAuth, 46),
    ENTRY(TPM_CC_PolicySecret, 47),
    ENTRY(TPM_CC_Rewrap, 48),
    ENTRY(TPM_CC_Create, 49),
    ENTRY(TPM_CC_ECDH_ZGen, 50),
    ENTRY(TPM_CC_HMAC, 51),
    ENTRY(TPM_CC_Import, 52),
    ENTRY(TPM_CC_Load, 53),
    ENTRY(TPM_CC_Quote, 54),
    ENTRY(TPM_CC_RSA_Decrypt, 55),
    ENTRY(TPM_CC_HMAC_Start, 56),
    ENTRY(TPM_CC_SequenceUpdate, 57),
    ENTRY(TPM_CC_Sign, 58),
    ENTRY(TPM_CC_Unseal, 59),
    ENTRY(TPM_CC_PolicySigned, 60),
    ENTRY(TPM_CC_ContextLoad, 61),
    ENTRY(TPM_CC_ContextSave, 62),
    ENTRY(TPM_CC_ECDH_KeyGen, 63),
    ENTRY(TPM_CC_EncryptDecrypt, 64),
    ENTRY(TPM_CC_FlushContext, 65),
    ENTRY(TPM_CC_LoadExternal, 66),
    ENTRY(TPM_CC_MakeCredential, 67),
    ENTRY(TPM_CC_NV_ReadPublic, 68),
    ENTRY(TPM_CC_PolicyAuthorize, 69),
    ENTRY(TPM_CC_PolicyAuthValue, 70),
    ENTRY(TPM_CC_PolicyCommandCode, 71),
    ENTRY(TPM_CC_PolicyCounterTimer, 72),
    ENTRY(TPM_CC_PolicyCpHash, 73),
    ENTRY(TPM_CC_PolicyLocality, 74),
    ENTRY(TPM_CC_PolicyNameHash, 75),
    ENTRY(TPM_CC_PolicyOR, 76),
    ENTRY(TPM_CC_PolicyTicket, 77),
    ENTRY(TPM_CC_ReadPublic, 78),
    ENTRY(TPM_CC_RSA_Encrypt, 79),
    ENTRY(TPM_CC_StartAuthSession, 80),
    ENTRY(TPM_CC_VerifySignature, 81),
    ENTRY(TPM_CC_ECC_Parameters, 82),
    /* CC_FirmwareRead */
    ENTRY(TPM_CC_GetCapability, 83),
    ENTRY(TPM_CC_GetRandom, 84),
    ENTRY(TPM_CC_GetTestResult, 85),
    ENTRY(TPM_CC_Hash, 86),
    ENTRY(TPM_CC_PCR_Read, 87),
    ENTRY(TPM_CC_PolicyPCR, 88),
    ENTRY(TPM_CC_PolicyRestart, 89),
    ENTRY(TPM_CC_ReadClock, 90),
    ENTRY(TPM_CC_PCR_Extend, 91),
    ENTRY(TPM_CC_PCR_SetAuthValue, 92),
    ENTRY(TPM_CC_NV_Certify, 93),
    ENTRY(TPM_CC_EventSequenceComplete, 94),
    ENTRY(TPM_CC_HashSequenceStart, 95),
    ENTRY(TPM_CC_PolicyPhysicalPresence, 96),
    ENTRY(TPM_CC_PolicyDuplicationSelect, 97),
    ENTRY(TPM_CC_PolicyGetDigest, 98),
    ENTRY(TPM_CC_TestParms, 99),
    ENTRY(TPM_CC_Commit, 100),
    ENTRY(TPM_CC_PolicyPassword, 101),
    ENTRY(TPM_CC_ZGen_2Phase, 102),
    ENTRY(TPM_CC_EC_Ephemeral, 103),
    ENTRY(TPM_CC_PolicyNvWritten, 104),
    ENTRY(TPM_CC_PolicyTemplate, 105),
    ENTRY(TPM_CC_CreateLoaded, 106),
    ENTRY(TPM_CC_PolicyAuthorizeNV, 107),
    ENTRY(TPM_CC_EncryptDecrypt2, 108),
    /* CC_AC_GetCapability -- never enable here */
    /* CC_AC_Send -- never enable here */
    /* CC_Policy_AC_SendSelect */
    ENTRY(TPM_CC_CertifyX509, 109),
    /* CC_ACT_SetTimeout -- never enable here */
    /* CC_ECC_Encrypt -- never enable here */
    /* CC_ECC_Decrypt -- never enable here */
    /* never add new commands */
};

/* Convert from a bit array from the time when COMPRESSED_LIST was YES
 * to an array where the indices do NOT correspond to a COMPRESSED_LIST.
 */
TPM_RC
ConvertFromCompressedBitArray(BYTE         *inAuditCommands,
			      size_t        inAuditCommandsLen,
			      BYTE         *outAuditCommands,
			      size_t        outAuditCommandsLen)
{
    size_t max_bit = MIN(inAuditCommandsLen * 8, ARRAY_SIZE(CCToCompressedListIndex));
    size_t bit = 0;

    MemorySet(outAuditCommands, 0, outAuditCommandsLen);

    while (bit < max_bit) {
	BYTE bits = inAuditCommands[bit >> 3];
	BYTE mask = 1;
	size_t lbit = bit;

	while (bits != 0 && lbit < max_bit) {
	    if ((bits & mask) != 0) {
		TPM_CC cc = CCToCompressedListIndex[lbit].cc;
		COMMAND_INDEX idx = cc - TPM_CC_NV_UndefineSpaceSpecial;

		assert(idx != UNIMPLEMENTED_COMMAND_INDEX);

		SetBit(idx, outAuditCommands, outAuditCommandsLen);
		bits ^= mask; /* unset bit */
	    }
	    mask <<= 1;
	    lbit++;
	}
	bit += 8;
    }

    return TPM_RC_SUCCESS;
}

static size_t FindCCInCompressedListIndexArray(TPM_CC cc)
{
    size_t e_index = ARRAY_SIZE(CCToCompressedListIndex) - 1;
    size_t s_index = 0;

    while (true) {
        size_t index = (e_index + s_index) >> 1;

        if (cc == CCToCompressedListIndex[index].cc) {
            return index;
        }
        if (e_index == s_index) {
            break;
        }
        if (cc < CCToCompressedListIndex[index].cc) {
            e_index = index;
        } else {
            if (s_index != index)
                s_index = index;
            else
                s_index++;
        }
    }
    /* entry must have been found */
    pAssert(false);
}

/* Convert to a bit array from the time when COMPRESSED_LIST was YES
 * from an array where the indices do NOT correspond to a COMPRESSED_LIST.
 */
TPM_RC
ConvertToCompressedBitArray(BYTE         *inAuditCommands,
			    size_t        inAuditCommandsLen,
			    BYTE         *outAuditCommands,
			    size_t        outAuditCommandsLen)
{
    size_t max_idx = inAuditCommandsLen * 8;
    size_t idx = 0;

    MemorySet(outAuditCommands, 0, outAuditCommandsLen);

    while (idx < max_idx) {
	BYTE bits = inAuditCommands[idx >> 3];
	BYTE mask = 1;
	size_t lidx = idx;

	/* handle bits set in one byte in the loop */
	while (bits != 0 && lidx < max_idx) {
	    if ((bits & mask) != 0) {
		TPM_CC cc = lidx + TPM_CC_NV_UndefineSpaceSpecial;
		size_t bit = FindCCInCompressedListIndexArray(cc);

		SetBit(bit, outAuditCommands, outAuditCommandsLen);
		bits ^= mask; /* unset bit */
	    }
	    mask <<= 1;
	    lidx++;
	}
	idx += 8;
    }

    return TPM_RC_SUCCESS;
}
