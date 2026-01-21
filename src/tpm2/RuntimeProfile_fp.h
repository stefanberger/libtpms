// SPDX-License-Identifier: BSD-2-Clause

//  (c) Copyright IBM Corporation, 2022

#ifndef RUNTIME_PROFILE_H
#define RUNTIME_PROFILE_H

#include <stdbool.h>

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
