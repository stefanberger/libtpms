/********************************************************************************/
/*										*/
/*			  Marshalling and unmarshalling of state		*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2012-2015				*/
/*										*/
/********************************************************************************/

#ifndef NVMARSHAL_H
#define NVMARSHAL_H

#include <stdbool.h>

#include "Tpm.h"
#include "TpmTypes.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

UINT16 VolatileState_Marshal(BYTE **buffer, INT32 *size);
TPM_RC VolatileState_Unmarshal(BYTE **buffer, INT32 *size);

void NvWrite_ORDERLY_DATA(UINT32 nvOffset, UINT32 size, ORDERLY_DATA *data);
void NvWrite_STATE_RESET_DATA(UINT32 nvOffset, UINT32 size, STATE_RESET_DATA *data);
void NvWrite_STATE_CLEAR_DATA(UINT32 nvOffset, UINT32 size, STATE_CLEAR_DATA *data);
void NvWrite_PERSISTENT_DATA(UINT32 nvOffset, UINT32 size, PERSISTENT_DATA *data);
void NvWrite_NV_LIST_TERMINATOR(UINT32 nvOffset, UINT32 size, NV_LIST_TERMINATOR *data);
void NvWrite_UINT32(UINT32 nvOffset, UINT32 size, UINT32 *data);
void NvWrite_TPM_HANDLE(UINT32 nvOffset, UINT32 size, UINT32 *data);
void NvWrite_Array(UINT32 nvOffset, UINT32 size, BYTE *data);

void NvRead_UINT32(UINT32 *data, UINT32 nvOffset, UINT32 size);
void NvRead_UINT64(UINT64 *data, UINT32 nvOffset, UINT32 size);
void NvRead_ORDERLY_DATA(ORDERLY_DATA *data, UINT32 nvOffset, UINT32 size);
void NvRead_STATE_RESET_DATA(STATE_RESET_DATA *data, UINT32 nvOffset, UINT32 size);
void NvRead_STATE_CLEAR_DATA(STATE_CLEAR_DATA *data, UINT32 nvOffset, UINT32 size);
void NvRead_PERSISTENT_DATA(PERSISTENT_DATA *data, UINT32 nvOffset, UINT32 size);
void NvRead_OBJECT_ATTRIBUTES(OBJECT_ATTRIBUTES *data, UINT32 nvOffset, UINT32 size);
void NvRead_OBJECT(OBJECT *data, UINT32 nvOffset, UINT32 size);
void NvRead_TPMA_NV(TPMA_NV *data, UINT32 nvOffset, UINT32 size);
void NvRead_NV_INDEX(NV_INDEX *data, UINT32 nvOffset, UINT32 size);
void NvRead_NV_ENTRY_HEADER(NV_ENTRY_HEADER *data, UINT32 nvOffset, UINT32 size);

void TPMA_NV_SWAP(TPMA_NV *t, TPMA_NV *s);
void OBJECT_SWAP(OBJECT *t, OBJECT *s, bool to_native);
void NV_INDEX_SWAP(NV_INDEX *t, NV_INDEX *s);

static inline void TPM2B_SWAP(TPM2B *t, TPM2B *s, size_t bufsize)
{
    t->size = htobe16(s->size);
    memcpy(t->buffer, s->buffer, bufsize);
}


#endif /* NVMARSHAL_H */

