/********************************************************************************/
/*										*/
/*			        Runtime Profile 				*/
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

#ifndef RUNTIME_PROFILE_H
#define RUNTIME_PROFILE_H

#include "RuntimeAlgorithm_fp.h"
#include "RuntimeCommands_fp.h"
#include "RuntimeAttributes_fp.h"

struct RuntimeProfile {
    struct RuntimeAlgorithm RuntimeAlgorithm;
    struct RuntimeCommands  RuntimeCommands;
    struct RuntimeAttributes RuntimeAttributes;
    char *profileName;		    /* name of profile */
    char *runtimeProfileJSON;	    /* JSON description */
    unsigned int stateFormatLevel;  /* how the state is to be written */
    BOOL wasNullProfile;            /* whether this profile was originally due to a NULL profile */
    char *profileDescription;       /* description */
};

extern struct RuntimeProfile g_RuntimeProfile;

TPM_RC
RuntimeProfileInit(struct RuntimeProfile *RuntimeProfile);

void
RuntimeProfileFree(struct RuntimeProfile *RuntimeProfile);

TPM_RC
RuntimeProfileSet(struct RuntimeProfile *RuntimeProfile,
		  const char            *jsonProfile,
		  bool                   jsonProfileFromUser);

TPM_RC
RuntimeProfileTest(struct RuntimeProfile *RuntimeProfile,
		   const char            *jsonProfile,
		   bool                   jsonProfileFromUser);

BOOL
RuntimeProfileWasNullProfile(struct RuntimeProfile *RuntimeProfile);

TPM_RC
RuntimeProfileFormatJSON(struct RuntimeProfile *RuntimeProfile);

const char *
RuntimeProfileGetJSON(struct RuntimeProfile *RuntimeProfile);

TPM_RC
RuntimeProfileGetByIndex(size_t  idx,
			 char    **runtimeProfileJSON);

SEED_COMPAT_LEVEL RuntimeProfileGetSeedCompatLevel(void);

BOOL
RuntimeProfileRequiresAttributeFlags(struct RuntimeProfile *RuntimeProfile,
                                     unsigned int           attributeFlags);

#endif /* RUNTIME_PROFILE_H */
