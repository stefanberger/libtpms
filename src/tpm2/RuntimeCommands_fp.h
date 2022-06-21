/********************************************************************************/
/*										*/
/*			 TPM 2 Commands Runtime Disablement			*/
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

#ifndef RUNTIME_COMMANDS_H
#define RUNTIME_COMMANDS_H

#include "Tpm.h"

#define CC_OFFSET    TPM_CC_FIRST

#define CcToIdx(COC) (size_t)(COC - CC_OFFSET)
#define IdxToCc(IDX) (TPM_CC)(IDX + CC_OFFSET)

#define NUM_ENTRIES_COMMAND_PROPERTIES  (CcToIdx(TPM_CC_LAST) + 1)

struct RuntimeCommands {
    unsigned char enabledCommands[(IdxToCc(NUM_ENTRIES_COMMAND_PROPERTIES) + 7) / 8];
    char *commandsProfile;
};

void
RuntimeCommandsInit(struct RuntimeCommands *RuntimeCommands);

void
RuntimeCommandsFree(struct RuntimeCommands *RuntimeCommands);

TPM_RC
RuntimeCommandsSetProfile(struct RuntimeCommands *RuntimeCommands,
			  const char             *newProfile,
			  unsigned int           *stateFormatLevel,
			  unsigned int		 maxStateFormatLevel);

TPM_RC
RuntimeCommandsSwitchProfile(struct RuntimeCommands   *RuntimeCommands,
			     const char               *newProfile,
			     unsigned int              maxStateFormatLevel,
			     char                    **oldProfile
			     );

BOOL
RuntimeCommandsCheckEnabled(struct RuntimeCommands *RuntimeCommands,
			    TPM_CC		    cc      // IN: the command code to check
			    );

LIB_EXPORT UINT32
RuntimeCommandsCountEnabled(struct RuntimeCommands *RuntimeCommands);

enum RuntimeCommandType {
    RUNTIME_CMD_IMPLEMENTED,
    RUNTIME_CMD_ENABLED,
    RUNTIME_CMD_DISABLED,
    RUNTIME_CMD_CAN_BE_DISABLED,

    RUNTIME_CMD_NUM, /* keep last */
};

char *
RuntimeCommandsPrint(struct RuntimeCommands    *RuntimeCommands,
		     enum RuntimeCommandType   rct);

#endif /* RUNTIME_COMMANDS_H */
