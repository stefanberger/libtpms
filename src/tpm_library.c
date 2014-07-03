/********************************************************************************/
/*										*/
/*			LibTPM interface functions				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpm_library.c 4615 2011-08-30 15:35:24Z stefanb $		*/
/*										*/
/* (c) Copyright IBM Corporation 2010.						*/
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef USE_FREEBL_CRYPTO_LIBRARY
# include <plbase64.h>
#endif

#ifdef USE_OPENSSL_CRYPTO_LIBRARY
# include <openssl/bio.h>
# include <openssl/evp.h>
#endif

#include "tpm_debug.h"
#include "tpm_error.h"
#include "tpm_init.h"
#include "tpm_library.h"
#include "tpm_library_intern.h"
#include "tpm_key.h"
#include "tpm_memory.h"
#include "tpm_process.h"
#include "tpm_startup.h"

#define ROUNDUP(VAL, SIZE) \
  ( ( (VAL) + (SIZE) - 1 ) / (SIZE) ) * (SIZE)



static const struct tags_and_indices {
    const char    *starttag;
    const char    *endtag;
} tags_and_indices[] = {
  [TPMLIB_BLOB_TYPE_INITSTATE] =
    {
      .starttag = TPMLIB_INITSTATE_START_TAG,
      .endtag   = TPMLIB_INITSTATE_END_TAG,
    },
};



uint32_t TPMLIB_GetVersion(void)
{
    return TPM_LIBRARY_VERSION;
}

TPM_RESULT TPMLIB_MainInit(void)
{
    return TPM_MainInit();
}


void TPMLIB_Terminate(void)
{
    TPM_Global_Delete(tpm_instances[0]);
    free(tpm_instances[0]);
    tpm_instances[0] = NULL;
}


/*
 * Send a command to the TPM. The command buffer must hold a well formatted
 * TPM command and the command_size indicate the size of the command.
 * The respbuffer parameter may be provided by the user and grow if
 * the respbufsize size indicator is determined to be too small for the
 * response. In that case a new buffer will be allocated and the size of that
 * buffer returned in the respbufsize parameter. resp_size describes the
 * size of the actual response within the respbuffer.
 */
TPM_RESULT TPMLIB_Process(unsigned char **respbuffer, uint32_t *resp_size,
                          uint32_t *respbufsize,
		          unsigned char *command, uint32_t command_size)
{
    *resp_size = 0;
    return TPM_ProcessA(respbuffer, resp_size, respbufsize,
                        command, command_size);
}


/*
 * Get the volatile state from the TPM. This function will return the
 * buffer and the length of the buffer to the caller in case everything
 * went alright.
 */
TPM_RESULT TPMLIB_VolatileAll_Store(unsigned char **buffer,
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


/*
 * Get a property of the TPM. The functions currently only
 * return compile-time #defines but this may change in future
 * versions where we may return parameters with which the TPM
 * was created (rather than compiled).
 */
TPM_RESULT TPMLIB_GetTPMProperty(enum TPMLIB_TPMProperty prop,
                                 int *result)
{
    switch (prop) {
    case  TPMPROP_TPM_RSA_KEY_LENGTH_MAX:
        *result = TPM_RSA_KEY_LENGTH_MAX;
        break;

    case  TPMPROP_TPM_BUFFER_MAX:
        *result = TPM_BUFFER_MAX;
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

static struct libtpms_callbacks libtpms_cbs;

struct libtpms_callbacks *TPMLIB_GetCallbacks(void)
{
    return &libtpms_cbs;
}


TPM_RESULT TPMLIB_RegisterCallbacks(struct libtpms_callbacks *callbacks)
{
    int max_size = sizeof(struct libtpms_callbacks);

    /* restrict the size of the structure to what we know currently
       future versions may know more callbacks */
    if (callbacks->sizeOfStruct < max_size)
        max_size = callbacks->sizeOfStruct;

    /* clear the internal callback structure and copy the user provided
       callbacks into it */
    memset(&libtpms_cbs, 0x0, sizeof(libtpms_cbs));
    memcpy(&libtpms_cbs, callbacks, max_size);

    return TPM_SUCCESS;
}


static int is_base64ltr(char c)
{
    return ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
             c == '+' ||
             c == '/' ||
             c == '=');
}

#ifdef USE_OPENSSL_CRYPTO_LIBRARY
static unsigned char *TPMLIB_OpenSSL_Base64Decode(char *input,
                                                  unsigned int outputlen)
{
    BIO *b64, *bmem;
    unsigned char *res = NULL;
    int n;
    TPM_RESULT rc;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        return NULL;
    }

    bmem = BIO_new_mem_buf(input, strlen(input));
    if (!bmem) {
        BIO_free(b64);
        goto cleanup;
    }
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

    rc = TPM_Malloc(&res, outputlen);
    if (rc != TPM_SUCCESS) {
        goto cleanup;
    }

    n = BIO_read(bmem, res, outputlen);
    if (n <= 0) {
        TPM_Free(res);
        res = NULL;
        goto cleanup;
    }

cleanup:
    BIO_free_all(bmem);

    return res;
}
#endif

/*
 * Base64 decode the string starting at 'start' and the last
 * valid character may be a 'end'. The length of the decoded string
 * is returned in *length.
 */
static unsigned char *TPMLIB_Base64Decode(const char *start, const char *end,
                                          size_t *length)
{
    unsigned char *ret = NULL;
    char *input = NULL, *d;
    const char *s;
    char c;
    unsigned int numbase64chars = 0;

    if (end < start)
        return NULL;

    while (end > start && !is_base64ltr(*end))
        end--;

    end++;

    if (TPM_Malloc((unsigned char **)&input, end - start + 1) != TPM_SUCCESS)
        return NULL;

    /* copy from source string skipping '\n' and '\r' and using
       '=' to calculate the exact length */
    d = input;
    s = start;

    while (s < end) {
        c = *s;
        if (is_base64ltr(c)) {
            *d = c;
            d++;
            if (c != '=') {
                numbase64chars++;
            }
        } else if (c == 0) {
            break;
        }
        s++;
    }
    *d = 0;

    *length = (numbase64chars / 4) * 3;
    switch (numbase64chars % 4) {
    case 2:
    case 3:
        *length += (numbase64chars % 4) - 1;
        break;
    case 0:
        break;
    case 1:
        fprintf(stderr,"malformed base64\n");
        goto err_exit;
    break;
    }

#ifdef USE_FREEBL_CRYPTO_LIBRARY
    ret = (unsigned char *)PL_Base64Decode(input, 0, NULL);
#endif

#ifdef USE_OPENSSL_CRYPTO_LIBRARY
    ret = TPMLIB_OpenSSL_Base64Decode(input, *length);
#endif

err_exit:
    free(input);

    return ret;
}


static unsigned char *TPMLIB_GetPlaintext(const char *stream,
                                          const char *starttag,
                                          const char *endtag,
                                          size_t *length)
{
    char *start, *end;
    unsigned char *plaintext = NULL;

    start = strstr(stream, starttag);
    if (start) {
        start += strlen(starttag);
        while (isspace((int)*start))
            start++;
        end = strstr(start, endtag);
        if (end) {
            plaintext = TPMLIB_Base64Decode(start, --end, length);
        }
    }
    return plaintext;
}


TPM_RESULT TPMLIB_DecodeBlob(const char *buffer, enum TPMLIB_BlobType type,
                             unsigned char **result, size_t *result_len)
{
    TPM_RESULT res = TPM_SUCCESS;

    *result = TPMLIB_GetPlaintext(buffer,
                                  tags_and_indices[type].starttag,
                                  tags_and_indices[type].endtag,
                                  result_len);

    if (*result == NULL) {
        res = TPM_FAIL;
    }

    return res;
}

