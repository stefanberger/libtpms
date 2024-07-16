#if USE_OPENSSL_FUNCTIONS_SSKDF

#include "Tpm.h"
#include "Helpers_fp.h"

int main(void)
{
    UINT16 gen1, gen2;
    TPM2B_LABEL Z = {
	.t.size = 6,
	.t.buffer = {1, 2, 3, 4, 5, 6},
    };
    TPM2B_LABEL label = {
	.t.size = 5,
	.t.buffer = "label",
    };
    TPM2B_LABEL partyUInfo = {
	.t.size = 6,
	.t.buffer = "test12",
    };
    TPM2B_LABEL partyVInfo = {
	.t.size = 7,
	.t.buffer = "test123",
    };
    TPM2B_LABEL info = {
	.t.size = 8,
	.t.buffer = "label123",
    };
    BYTE keyStream1[128] = {0, }, keyStream2[128] = {0, };
    UINT32 sizeInBits = 8 * sizeof(keyStream2);
    TPM_ALG_ID hashAlgs[] = { TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512 };
    size_t i, o;

    for (o = 0; o < 8; o++) {
	for (i = 0; i < ARRAY_SIZE(hashAlgs); i++) {
	    gen1 = ReferenceCryptKDFe(hashAlgs[i], &Z.b, &label.b,
				      &partyUInfo.b, &partyVInfo.b, sizeInBits - o, keyStream1);

	    gen2 = OSSLCryptKDFe(hashAlgs[i], &Z.b, &label.b,
				 &partyUInfo.b, &partyVInfo.b, sizeInBits - o, keyStream2);

	    if (gen1 != gen2 || memcmp(keyStream1, keyStream2, gen1)) {
		fprintf(stderr, "results are not equal: gen1: %d  gen2: %d  o: %d\n", gen1, gen2, o);
		fprintf(stderr, "%02x %02x %02x .. %02x\n",
		        keyStream1[0], keyStream1[1], keyStream1[2], keyStream1[gen1 - 1]);
		fprintf(stderr, "%02x %02x %02x .. %02x\n",
		        keyStream2[0], keyStream2[1], keyStream2[2], keyStream2[gen2 - 1]);
		return 1;
	    }
	}
    }
}

#else

int main(void)
{
    return 0;
}

#endif
