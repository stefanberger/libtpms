#if USE_OPENSSL_FUNCTIONS_SSKDF

#include "Tpm.h"
#include "Helpers_fp.h"

int main(void)
{
    UINT16 gen1, gen2;
    TPM2B_LABEL key = {
	.t.size = 0x20,
	.t.buffer = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	             0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
    };
    TPM2B_LABEL label = {
	.t.size = 5,
	.t.buffer = "label",
    };
    TPM2B_LABEL contextU = {
	.t.size = 6,
	.t.buffer = "test12",
    };
    TPM2B_LABEL contextV = {
	.t.size = 7,
	.t.buffer = "test123",
    };
    BYTE keyStream1[256] = {0, }, keyStream2[256] = {0, };
    UINT32 counter1, counter2;
    const TPM_ALG_ID hashAlgs[] = {
        TPM_ALG_SHA1,
        TPM_ALG_SHA256,
        TPM_ALG_SHA384,
        TPM_ALG_SHA512
    };
    UINT32 sizeInBits;
    UINT16 blocks;
    size_t i;

    for (sizeInBits = 0; sizeInBits < 8 * sizeof(keyStream1); sizeInBits += 8) {
	for (i = 0; i < ARRAY_SIZE(hashAlgs); i++) {
	    counter1 = 0;
	    memset(keyStream1, 0, sizeof(keyStream1));
	    gen1 = CryptKDFa(hashAlgs[i], &key.b, &label.b,
			     &contextU.b, &contextV.b, sizeInBits, keyStream1,
			     &counter1, blocks);

	    counter2 = 0;
	    memset(keyStream2, 0, sizeof(keyStream2));
	    gen2 = OSSLCryptKDFa(hashAlgs[i], &key.b, &label.b,
				 &contextU.b, &contextV.b, sizeInBits, keyStream2,
				 &counter2, blocks);

	    if (gen1 != gen2 || memcmp(keyStream1, keyStream2, gen1)) {
		fprintf(stderr, "results are not equal: gen1: %d  gen2: %d  hash: %d sizeInBits: %d\n",
			gen1, gen2, hashAlgs[i], sizeInBits);
		fprintf(stderr, "%02x %02x %02x ... %02x\n",
			keyStream1[0], keyStream1[1], keyStream1[2], keyStream1[gen1 - 1]);
		fprintf(stderr, "%02x %02x %02x ... %02x\n",
			keyStream2[0], keyStream2[1], keyStream2[2], keyStream2[gen2 - 1]);
		return 1;
	    }
	    fprintf(stdout, "Success with hash %d, sizeInBits %d\n",
		    hashAlgs[i], sizeInBits);
	}
    }
}

#else

int main(void)
{
    return 0;
}

#endif
