// SPDX-License-Identifier: BSD-2-Clause

//  (c) Copyright IBM Corporation, 2022

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
