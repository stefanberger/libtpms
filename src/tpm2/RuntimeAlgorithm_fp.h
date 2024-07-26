/********************************************************************************/
/*										*/
/*			 Algorithm Runtime Disablement 				*/
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
