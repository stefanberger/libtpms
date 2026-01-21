// SPDX-License-Identifier: BSD-2-Clause

//  (c) Copyright IBM Corporation, 2022

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
