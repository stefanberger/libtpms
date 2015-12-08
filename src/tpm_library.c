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

#include "tpm12/tpm_debug.h"
#include "tpm_error.h"
#include "tpm_library.h"
#include "tpm_library_intern.h"
#include "tpm_memory.h"

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

static const struct tpm_interface *const tpm_iface[] = {
    &TPM12Interface,
};

uint32_t TPMLIB_GetVersion(void)
{
    return TPM_LIBRARY_VERSION;
}

TPM_RESULT TPMLIB_MainInit(void)
{
    return tpm_iface[0]->MainInit();
}

void TPMLIB_Terminate(void)
{
    tpm_iface[0]->Terminate();
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
    return tpm_iface[0]->Process(respbuffer, resp_size, respbufsize,
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
    return tpm_iface[0]->VolatileAllStore(buffer, buflen);
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
    case  TPMPROP_TPM_BUFFER_MAX:
        *result = TPM_BUFFER_MAX;
        break;

    default:
        return tpm_iface[0]->GetTPMProperty(prop, result);
    }

    return TPM_SUCCESS;
}

TPM_RESULT TPM_IO_Hash_Start(void)
{
    return tpm_iface[0]->HashStart();
}

TPM_RESULT TPM_IO_Hash_Data(const unsigned char *data, uint32_t data_length)
{
    return tpm_iface[0]->HashData(data, data_length);
}

TPM_RESULT TPM_IO_Hash_End(void)
{
    return tpm_iface[0]->HashEnd();
}

TPM_RESULT TPM_IO_TpmEstablished_Get(TPM_BOOL *tpmEstablished)
{
    return tpm_iface[0]->TpmEstablishedGet(tpmEstablished);
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
