#include <assert.h>
#include <stdlib.h>

#include "Tpm.h"

/* from Global.h */
extern BYTE s_indexOrderlyRam[RAM_INDEX_SPACE];

int main(void)
{
    /* ensure that the NVRAM offset of NV_USER_DYNAMIC is at the expected
       location so that there's enough memory for re-constructing NVRAM
       indices etc. into the NVRAM */
#define NV_INDEX_RAM_DATA_EXP_OFFSET 5120
    if (NV_INDEX_RAM_DATA != NV_INDEX_RAM_DATA_EXP_OFFSET) {
        /* If this ever changes due to growth of the preceding data
         * structure, we need to adjust the total NVRAM memory size
         * for the architecture where this changed (or have all
         * architectures use the same offset.
         */
        fprintf(stderr,
                "NV_INDEX_RAM_DATA not at expected offset %u but at %u\n",
                 NV_INDEX_RAM_DATA_EXP_OFFSET, (unsigned int)NV_INDEX_RAM_DATA);
        return EXIT_FAILURE;
    }

#define NV_USER_DYNAMIC_EXP_OFFSET (5120 + 512)
    if (NV_USER_DYNAMIC != NV_USER_DYNAMIC_EXP_OFFSET) {
        fprintf(stderr,
                "NV_USER_DYNAMIC not at expected offset %u but at %u\n",
                NV_USER_DYNAMIC_EXP_OFFSET, (unsigned int)NV_USER_DYNAMIC);
        return EXIT_FAILURE;
    }

#if defined(__x86_64__)
    /* Leave this check on x86_64 for 'notification' when sizeof(OBJECT) increases */
#if RSA_16384
# error Unsupported RSA key size
#elif RSA_4096
# define OBJECT_EXP_SIZE 3312
#elif RSA_3072
# define OBJECT_EXP_SIZE 2608
#elif RSA_2048
# define OBJECT_EXP_SIZE 1896
#endif
    if (sizeof(OBJECT) != OBJECT_EXP_SIZE) {
        fprintf(stderr, "sizeof(OBJECT) does not have expected size of %u bytes"
                        "but %zu bytes\n", OBJECT_EXP_SIZE, sizeof(OBJECT));
        fprintf(stderr, "sizeof(TPMT_PUBLIC) is now %zu bytes;"
                        "was 356/484/612 bytes for 2048/3072/4096 bit RSA keys\n",
                        sizeof(TPMT_PUBLIC));
        fprintf(stderr, "sizeof(TPMT_SENSITIVE) is now %zu bytes;"
                        "was 776/1096/1416 bytes for 2048/3072/4096 bit RSA keys\n",
                        sizeof(TPMT_SENSITIVE));
        fprintf(stderr, "sizeof(privateExponent_t) is now %zu bytes;"
                        "was 608/864/1120 bytes for 2048/3072/4096 bit RSA keys\n",
                        sizeof(privateExponent_t));
        return EXIT_FAILURE;
    }
#endif /* __x86_64__ */

    /*
     * NV_INDEX structure is (still) directly copied into NVRAM memory using
     * memcpy. sizeof(NV_INDEX) MUST have the same size on all architectures.
     */
MUST_BE(offsetof(TPMS_NV_PUBLIC, nameAlg)    == 4);
MUST_BE(offsetof(TPMS_NV_PUBLIC, attributes) == 4 + 4);
MUST_BE(offsetof(TPMS_NV_PUBLIC, authPolicy) == 4 + 4 + 4);
MUST_BE(offsetof(TPMS_NV_PUBLIC, dataSize)   == 4 + 4 + 4 + 66);
MUST_BE(sizeof(TPMS_NV_PUBLIC) == 80);
MUST_BE(sizeof(TPM2B_AUTH) == 2 + BITS_TO_BYTES(512));
MUST_BE(offsetof(NV_INDEX, authValue) == 80);
MUST_BE(sizeof(NV_INDEX) == 148);

    return EXIT_SUCCESS;
}
