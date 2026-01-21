// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation, 2022

#ifndef RUNTIME_ALGORITHM_H
#define RUNTIME_ALGORITHM_H

#define NUM_ENTRIES_ALGORITHM_PROPERTIES	(size_t)(TPM_ALG_LAST + 1)
#define NUM_ENTRIES_ECC_ALGO_PROPERTIES         (size_t)(TPM_ECC_SM2_P256 + 1)

struct RuntimeAlgorithm {
    /* array holding minimum key sizes for algorithms in algsWithKeySizes */
    UINT16 algosMinimumKeySizes[NUM_ENTRIES_ALGORITHM_PROPERTIES];
    ALGORITHM_VECTOR enabledAlgorithms;
    unsigned char enabledEccShortcuts[1];
#define RUNTIME_ALGORITHM_ECC_NIST_BIT      0
#define RUNTIME_ALGORITHM_ECC_BN_BIT        1
    unsigned char enabledEccCurves[(NUM_ENTRIES_ECC_ALGO_PROPERTIES + 7) / 8];
    char *algorithmProfile;
};

void
RuntimeAlgorithmInit(struct RuntimeAlgorithm *RuntimeAlgorithm);

void
RuntimeAlgorithmFree(struct RuntimeAlgorithm *RuntimeAlgorithm);

TPM_RC
RuntimeAlgorithmSetProfile(struct RuntimeAlgorithm *RuntimeAlgorithm,
			   const char              *newProfile,
			   unsigned int            *stateFormatLevel,
			   unsigned int		   maxstateFormatLevel);

TPM_RC
RuntimeAlgorithmSwitchProfile(struct RuntimeAlgorithm  *RuntimeAlgorithm,
			      const char               *newProfile,
			      unsigned int              maxStateFormatLevel,
			      char                    **oldProfile);

BOOL
RuntimeAlgorithmCheckEnabled(struct RuntimeAlgorithm *RuntimeAlgorithm,
			     TPM_ALG_ID		      algId      // IN: the algorithm to check
			     );

BOOL
RuntimeAlgorithmKeySizeCheckEnabled(struct RuntimeAlgorithm *RuntimeAlgorithm,
				    TPM_ALG_ID               algId,			// IN: the algorithm to check
				    UINT16                   keySizeInBits,		// IN: size of the key in bits
				    TPM_ECC_CURVE	     curveId,			// IN: curveId if algId == TPM_ALG_ECC
				    unsigned int             maxStateFormatLevel	// IN: maximum stateFormatLevel
				    );

enum RuntimeAlgorithmType {
    RUNTIME_ALGO_IMPLEMENTED,
    RUNTIME_ALGO_ENABLED,
    RUNTIME_ALGO_DISABLED,
    RUNTIME_ALGO_CAN_BE_DISABLED,

    RUNTIME_ALGO_NUM, /* keep last */
};

char *
RuntimeAlgorithmPrint(struct RuntimeAlgorithm   *RuntimeAlgorithm,
		      enum RuntimeAlgorithmType rat);

void
RuntimeAlgorithmsFilterPCRSelection(TPML_PCR_SELECTION *pcrSelection // IN/OUT: PCRSelection to filter
				    );

#endif /* RUNTIME_ALGORITHM_H */
