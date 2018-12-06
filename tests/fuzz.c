#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <libtpms/tpm_types.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    unsigned char *rbuffer = NULL;
    uint32_t rlength;
    uint32_t rtotal = 0;
    TPM_RESULT res;
    unsigned char startup[] = {
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00
    };

    res = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    assert(res == TPM_SUCCESS);

    res = TPMLIB_MainInit();
    if (res != TPM_SUCCESS)
        fprintf(stderr, "Error: TPMLIB_MainInit() failed\n");

    res = TPMLIB_Process(&rbuffer, &rlength, &rtotal, startup, sizeof(startup));
    if (res != TPM_SUCCESS)
        fprintf(stderr, "Error: TPMLIB_Process(Startup) failed\n");

    res = TPMLIB_Process(&rbuffer, &rlength, &rtotal, (unsigned char*)data, size);
    if (res != TPM_SUCCESS)
        fprintf(stderr, "Error: TPMLIB_Process(fuzz-command) failed\n")


    TPMLIB_Terminate();
    TPM_Free(rbuffer);

    return 0;
}
