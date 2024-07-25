/********************************************************************************/
/*										*/
/*			  Marshalling and unmarshalling of state		*/
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

#ifndef NVMARSHAL_H
#define NVMARSHAL_H

#include <stdbool.h>

#include "Tpm.h"
#include "TpmTypes.h"
#include "RuntimeProfile_fp.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

// Maximum size of buffer ANY_OBJECT_Marshal() will require to marshal an OBJECT
// This is not an exact number but gives a 'safe' buffer size
#define MAX_MARSHALLED_OBJECT_SIZE \
    (sizeof(OBJECT) + 32 /* marshalling headers */)

UINT16 VolatileState_Marshal(BYTE **buffer, INT32 *size,
                             struct RuntimeProfile *RuntimeProfile);
TPM_RC VolatileState_Unmarshal(BYTE **buffer, INT32 *size);

UINT32 PERSISTENT_ALL_Marshal(BYTE **buffer, INT32 *size);
TPM_RC PERSISTENT_ALL_Unmarshal(BYTE **buffer, INT32 *size);

void NVShadowRestore(void);

UINT16 ANY_OBJECT_Marshal(OBJECT *data, BYTE **buffer, INT32 *size,
                          struct RuntimeProfile *RuntimeProfile);
TPM_RC ANY_OBJECT_Unmarshal(OBJECT *data, BYTE **buffer, INT32 *size, BOOL verbose);

#endif /* NVMARSHAL_H */

