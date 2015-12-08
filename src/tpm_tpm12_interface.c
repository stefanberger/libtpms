/********************************************************************************/
/*										*/
/*			LibTPM TPM 1.2 call interface functions				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015.						*/
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

#include <config.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "tpm12/tpm_debug.h"
#include "tpm_error.h"
#include "tpm12/tpm_init.h"
#include "tpm_library_intern.h"
#include "tpm12/tpm_process.h"
#include "tpm12/tpm_startup.h"

TPM_RESULT TPM12_MainInit(void)
{
    return TPM_MainInit();
}

void TPM12_Terminate(void)
{
    TPM_Global_Delete(tpm_instances[0]);
    free(tpm_instances[0]);
    tpm_instances[0] = NULL;
}

TPM_RESULT TPM12_Process(unsigned char **respbuffer, uint32_t *resp_size,
                         uint32_t *respbufsize,
		         unsigned char *command, uint32_t command_size)
{
    *resp_size = 0;
    return TPM_ProcessA(respbuffer, resp_size, respbufsize,
                        command, command_size);
}

TPM_RESULT TPM12_VolatileAllStore(unsigned char **buffer,
                                  uint32_t *buflen)
{
    TPM_RESULT rc;
    TPM_STORE_BUFFER tsb;
    TPM_Sbuffer_Init(&tsb);
    uint32_t total;

#ifdef TPM_DEBUG
    assert(tpm_instances[0] != NULL);
#endif

    rc = TPM_VolatileAll_Store(&tsb, tpm_instances[0]);

    if (rc == TPM_SUCCESS) {
        /* caller now owns the buffer and needs to free it */
        TPM_Sbuffer_GetAll(&tsb, buffer, buflen, &total);
    } else {
        TPM_Sbuffer_Delete(&tsb);
        *buflen = 0;
        *buffer = NULL;
    }

    return rc;
}

TPM_RESULT TPM12_GetTPMProperty(enum TPMLIB_TPMProperty prop,
                                int *result)
{
    switch (prop) {
    case  TPMPROP_TPM_RSA_KEY_LENGTH_MAX:
        *result = TPM_RSA_KEY_LENGTH_MAX;
        break;

    case  TPMPROP_TPM_KEY_HANDLES:
        *result = TPM_KEY_HANDLES;
        break;

    case  TPMPROP_TPM_OWNER_EVICT_KEY_HANDLES:
        *result = TPM_OWNER_EVICT_KEY_HANDLES;
        break;

    case  TPMPROP_TPM_MIN_AUTH_SESSIONS:
        *result = TPM_MIN_AUTH_SESSIONS;
        break;

    case  TPMPROP_TPM_MIN_TRANS_SESSIONS:
        *result = TPM_MIN_TRANS_SESSIONS;
        break;

    case  TPMPROP_TPM_MIN_DAA_SESSIONS:
        *result = TPM_MIN_DAA_SESSIONS;
        break;

    case  TPMPROP_TPM_MIN_SESSION_LIST:
        *result = TPM_MIN_SESSION_LIST;
        break;

    case  TPMPROP_TPM_MIN_COUNTERS:
        *result = TPM_MIN_COUNTERS;
        break;

    case  TPMPROP_TPM_NUM_FAMILY_TABLE_ENTRY_MIN:
        *result = TPM_NUM_FAMILY_TABLE_ENTRY_MIN;
        break;

    case  TPMPROP_TPM_NUM_DELEGATE_TABLE_ENTRY_MIN:
        *result = TPM_NUM_DELEGATE_TABLE_ENTRY_MIN;
        break;

    case  TPMPROP_TPM_SPACE_SAFETY_MARGIN:
        *result = TPM_SPACE_SAFETY_MARGIN;
        break;

    case  TPMPROP_TPM_MAX_NV_SPACE:
        /* fill up 20 kb.; this provides some safety margin (currently
           >4Kb) for possible future expansion of this blob */
        *result = ROUNDUP(TPM_MAX_NV_SPACE, 20 * 1024);
        break;

    case  TPMPROP_TPM_MAX_SAVESTATE_SPACE:
        *result = TPM_MAX_SAVESTATE_SPACE;
        break;

    case  TPMPROP_TPM_MAX_VOLATILESTATE_SPACE:
        *result = TPM_MAX_VOLATILESTATE_SPACE;
        break;

    default:
        return TPM_FAIL;
    }

    return TPM_SUCCESS;
}

const struct tpm_interface TPM12Interface = {
    .MainInit = TPM12_MainInit,
    .Terminate = TPM12_Terminate,
    .Process = TPM12_Process,
    .VolatileAllStore = TPM12_VolatileAllStore,
    .GetTPMProperty = TPM12_GetTPMProperty,
    .TpmEstablishedGet = TPM12_IO_TpmEstablished_Get,
    .HashStart = TPM12_IO_Hash_Start,
    .HashData = TPM12_IO_Hash_Data,
    .HashEnd = TPM12_IO_Hash_End,
};
