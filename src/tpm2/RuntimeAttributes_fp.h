/********************************************************************************/
/*										*/
/*			        Runtime Attributes 				*/
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

#ifndef RUNTIME_ATTRIBUTES_H
#define RUNTIME_ATTRIBUTES_H

#define NUM_ENTRIES_ATTRIBUTE_PROPERTIES          10

#define RUNTIME_ATTRIBUTE_NO_UNPADDED_ENCRYPTION  (1 << 0)
#define RUNTIME_ATTRIBUTE_NO_SHA1_SIGNING         (1 << 1)
#define RUNTIME_ATTRIBUTE_NO_SHA1_VERIFICATION    (1 << 2)
#define RUNTIME_ATTRIBUTE_NO_SHA1_HMAC_CREATION   (1 << 3)
#define RUNTIME_ATTRIBUTE_NO_SHA1_HMAC_VERIFICATION (1 << 4)
#define RUNTIME_ATTRIBUTE_DRBG_CONTINOUS_TEST       (1 << 5)
#define RUNTIME_ATTRIBUTE_PAIRWISE_CONSISTENCY_TEST (1 << 6)
#define RUNTIME_ATTRIBUTE_NO_ECC_KEY_DERIVATION     (1 << 7)

struct RuntimeAttributes {
    /* */
    unsigned int attributeFlags;
    unsigned char enabledAttributesPrint[(NUM_ENTRIES_ATTRIBUTE_PROPERTIES + 7) / 8];
    char *attributesProfile;
};

void
RuntimeAttributesInit(struct RuntimeAttributes *RuntimeAttributes);

void
RuntimeAttributesFree(struct RuntimeAttributes *RuntimeAttributes);

LIB_EXPORT TPM_RC
RuntimeAttributesSetProfile(struct RuntimeAttributes *RuntimeAttributes,
			    const char		     *newProfile,		// IN: colon-separated list of algorithm names
			    unsigned int             *stateFormatLevel,		// IN/OUT: stateFormatLevel
			    unsigned int	      maxStateFormatLevel	// IN: maximum allowed stateFormatLevel
			    );

TPM_RC
RuntimeAttributesSwitchProfile(struct RuntimeAttributes *RuntimeAttributes,
			       const char               *newProfile,
			       unsigned int              maxStateFormatLevel,
			       char                    **oldProfile);

enum RuntimeAttributeType {
    RUNTIME_ATTR_IMPLEMENTED,
    RUNTIME_ATTR_ENABLED,
    RUNTIME_ATTR_DISABLED,
    RUNTIME_ATTR_CAN_BE_DISABLED,

    RUNTIME_ATTR_NUM, /* keep last */
};

char *
RuntimeAttributesGet(struct RuntimeAttributes   *RuntimeAttribute,
		     enum RuntimeAttributeType   rat);

BOOL
RuntimeAttributeCheckRequired(struct RuntimeAttributes *RuntimeAttributes,
			      unsigned int              attributeFlags);

#endif
