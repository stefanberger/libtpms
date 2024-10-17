/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>

static const char * const null_profile =
    "{\"ActiveProfile\":{"
        "\"Name\":\"null\","
        "\"StateFormatLevel\":1,"
        "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                       "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                       "0x17a-0x193,0x197\","
        "\"Algorithms\":\"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,"
                        "sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                        "xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,"
                        "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                        "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                        "ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"
                        "camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb\","
        "\"Description\":\"The profile enables the commands and algorithms that "
                          "were enabled in libtpms v0.9. This profile is "
                          "automatically used when the state does not have a "
                          "profile, for example when it was created by libtpms "
                          "v0.9 or before. This profile enables compatibility with "
                          "libtpms >= v0.9.\""
    "}}";

struct transfer {
    uint8_t *cmd;
    uint8_t *rsp;
};

static const struct {
    const char            *profile;
    bool                   exp_fail;
    const char            *exp_profile;
    const struct transfer *tx;
} testcases[] = {
    {
        .profile = NULL,
        .exp_fail = false,
        .exp_profile = null_profile,
    }, {
        // StateFormatLevel not allowed to be passed
        .profile = "{\"Name\":\"default-v1\",\"StateFormatLevel\":2}",
        .exp_fail = true,
    }, {
        .profile = "{\"Name\":\"null\"}",
        .exp_fail = false,
        .exp_profile = null_profile,
    }, {
        .profile = "{\"Name\":\"default-v1\"}",
        .exp_profile =
          "{\"ActiveProfile\":{"
            "\"Name\":\"default-v1\","
            "\"StateFormatLevel\":7,"
            "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                           "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                           "0x17a-0x193,0x197,0x199-0x19c\","
            "\"Algorithms\":\"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,"
                             "sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                             "xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,"
                             "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                             "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                             "ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"
                             "camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb\","
            "\"Description\":\"This profile enables all libtpms v0.10-supported "
                              "commands and algorithms. This profile is compatible with "
                              "libtpms >= v0.10.\""
          "}}",
    }, {
        .profile = "{"
                    "\"Name\":\"custom\","
                    "\"StateFormatLevel\":2,"
                    "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                                   "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                                   "0x17a-0x193,0x197\","
                    "\"Attributes\":\"\","
                    "\"Description\":\"test\""
                   "}",
        .exp_fail = false,
        .exp_profile =
          "{\"ActiveProfile\":{"
            "\"Name\":\"custom\","
            "\"StateFormatLevel\":2,"
            "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                           "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                           "0x17a-0x193,0x197\","
            "\"Algorithms\":\"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,"
                             "sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                             "xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,"
                             "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                             "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                             "ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"
                             "camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb\","
            "\"Attributes\":\"\","
            "\"Description\":\"test\""
          "}}",
    }, {
        .profile = "{"
                    "\"Name\":\"custom\","
                    "\"StateFormatLevel\":2,"
                    "\"Commands\":\"0x120,0x129,0x12b,0x131,0x13c,0x143-0x145,"
                                   "0x148,0x14e,0x153,0x156-0x158,0x15c,"
                                   "0x165,0x169,0x173,0x176,0x17a,0x17c-0x17e,"
                                   "0x182,0x185-0x186\","
                    "\"Algorithms\":\"rsa,rsa-min-size=2048,"
                                     "hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                                     "xor,sha256,sha384,null,rsassa,rsaes,rsapss,"
                                     "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                                     "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                                     "ecc-nist,symcipher,"
                                     "cfb\","
                    "\"Description\":\"Small profile\""
                   "}",
        .exp_fail = false,
        .exp_profile =
          "{\"ActiveProfile\":{"
            "\"Name\":\"custom\","
            "\"StateFormatLevel\":2,"
            "\"Commands\":\"0x120,0x129,0x12b,0x131,0x13c,0x143-0x145,"
                           "0x148,0x14e,0x153,0x156-0x158,0x15c,"
                           "0x165,0x169,0x173,0x176,0x17a,0x17c-0x17e,"
                           "0x182,0x185-0x186\","
            "\"Algorithms\":\"rsa,rsa-min-size=2048,"
                             "hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                             "xor,sha256,sha384,null,rsassa,rsaes,rsapss,"
                             "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                             "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                             "ecc-nist,symcipher,"
                             "cfb\","
            "\"Description\":\"Small profile\""
          "}}",
        .tx = (struct transfer[]){
            {
                .cmd = (uint8_t[]){
                    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00
                },
                .rsp = (uint8_t[]){
                    0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00
                }
            }, {
                /* algorithms: tssgetcapability -v -cap 0 */
                .cmd = (uint8_t[]){
                    0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7a, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
                },
                .rsp = (uint8_t[]){
                    0x80, 0x01, 0x00, 0x00, 0x00, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x05, 0x00, 0x00, 0x01, 0x04, 0x00,
                    0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x04, 0x04, 0x00, 0x08, 0x00, 0x00, 0x03,
                    0x0c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0c, 0x00,
                    0x00, 0x00, 0x04, 0x00, 0x14, 0x00, 0x00, 0x01, 0x01, 0x00, 0x15, 0x00, 0x00, 0x02, 0x01, 0x00,
                    0x16, 0x00, 0x00, 0x01, 0x01, 0x00, 0x17, 0x00, 0x00, 0x02, 0x01, 0x00, 0x18, 0x00, 0x00, 0x01,
                    0x01, 0x00, 0x19, 0x00, 0x00, 0x04, 0x01, 0x00, 0x1a, 0x00, 0x00, 0x01, 0x01, 0x00, 0x1b, 0x00,
                    0x00, 0x05, 0x01, 0x00, 0x1c, 0x00, 0x00, 0x01, 0x01, 0x00, 0x1d, 0x00, 0x00, 0x04, 0x01, 0x00,
                    0x20, 0x00, 0x00, 0x04, 0x04, 0x00, 0x21, 0x00, 0x00, 0x04, 0x04, 0x00, 0x22, 0x00, 0x00, 0x04,
                    0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x09, 0x00, 0x25, 0x00, 0x00, 0x00, 0x08, 0x00, 0x43, 0x00,
                    0x00, 0x02, 0x02
                }
            }, {
                /* commands: tssgetcapability -v -cap 2 */
                .cmd = (uint8_t[]){
                    0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7a, 0x00,
                    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
                },
                .rsp = (uint8_t[]){
                    0x80, 0x01, 0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                    0x00, 0x00, 0x1a, 0x04, 0x40, 0x01, 0x20, 0x02, 0x40, 0x01, 0x29, 0x02, 0x40, 0x01, 0x2b, 0x12,
                    0x00, 0x01, 0x31, 0x02, 0x40, 0x01, 0x3c, 0x00, 0x40, 0x01, 0x43, 0x00, 0x40, 0x01, 0x44, 0x00,
                    0x40, 0x01, 0x45, 0x04, 0x00, 0x01, 0x48, 0x04, 0x00, 0x01, 0x4e, 0x02, 0x00, 0x01, 0x53, 0x02,
                    0x00, 0x01, 0x56, 0x12, 0x00, 0x01, 0x57, 0x02, 0x00, 0x01, 0x58, 0x02, 0x00, 0x01, 0x5c, 0x00,
                    0x00, 0x01, 0x65, 0x02, 0x00, 0x01, 0x69, 0x02, 0x00, 0x01, 0x73, 0x14, 0x00, 0x01, 0x76, 0x00,
                    0x00, 0x01, 0x7a, 0x00, 0x00, 0x01, 0x7c, 0x00, 0x00, 0x01, 0x7d, 0x00, 0x00, 0x01, 0x7e, 0x02,
                    0x40, 0x01, 0x82, 0x05, 0x40, 0x01, 0x85, 0x10, 0x00, 0x01, 0x86
                }
            }, {
                /* pcrs: tssgetcapability -v -cap 5 */
                .cmd = (uint8_t[]){
                    0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7a, 0x00,
                    0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
                },
                .rsp = (uint8_t[]){
                    0x80, 0x01, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
                    0x00, 0x00, 0x02, 0x00, 0x0b, 0x03, 0xff, 0xff, 0xff, 0x00, 0x0c, 0x03, 0xff, 0xff, 0xff
                }
            }, {
                /* curves: tssgetcapability -v -cap 8 */
                .cmd = (uint8_t[]){
                    0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7a, 0x00,
                    0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
                },
                .rsp = (uint8_t[]){
                    0x80, 0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
                    0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05
                }
            }, {
                /* unsupported command: tsschangeeps -v */
                .cmd = (uint8_t[]){
                    0x80, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x01, 0x24, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00,
                    0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00
                },
                .rsp = (uint8_t[]){
                    0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x43
                }
            }, {
               // keep last
            }
        }
    }, {
        // commands 0x199-0x19a require StateFormatLevel 3
        .profile = "{"
                    "\"Name\":\"custom\","
                    "\"StateFormatLevel\":2,"
                    "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                                   "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                                   "0x17a-0x193,0x197,0x199-0x19a\","
                    "\"Description\":\"test\""
                   "}",
        .exp_fail = true,
    }, {
        .profile = "{"
                    "\"Name\":\"custom\","
                    "\"StateFormatLevel\":3,"
                    "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                                   "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                                   "0x17a-0x193,0x197,0x199-0x19a\","
                    "\"Description\":\"test\""
                   "}",
        .exp_fail = false,
        .exp_profile =
          "{\"ActiveProfile\":{"
            "\"Name\":\"custom\","
            "\"StateFormatLevel\":3,"
            "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                           "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                           "0x17a-0x193,0x197,0x199-0x19a\","
            "\"Algorithms\":\"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,"
                             "sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                             "xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,"
                             "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                             "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                             "ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"
                             "camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb\","
            "\"Description\":\"test\""
          "}}",
    }, {
        // commands 0x19b-0x19c require StateFormatLevel 5
        .profile = "{"
                    "\"Name\":\"custom\","
                    "\"StateFormatLevel\":4,"
                    "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                                   "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                                   "0x17a-0x193,0x197,0x199-0x19b\","
                    "\"Description\":\"test\""
                   "}",
        .exp_fail = true,
    }, {
        .profile = "{"
                    "\"Name\":\"custom\","
                    "\"StateFormatLevel\":0,"
                    "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                                   "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                                   "0x17a-0x193,0x197,0x19b-0x19c\","
                    "\"Description\":\"test\""
                   "}",
        .exp_fail = false,
        .exp_profile =
          "{\"ActiveProfile\":{"
            "\"Name\":\"custom\","
            "\"StateFormatLevel\":5,"
            "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                           "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                           "0x17a-0x193,0x197,0x19b-0x19c\","
            "\"Algorithms\":\"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,"
                             "sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                             "xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,"
                             "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                             "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                             "ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"
                             "camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb\","
            "\"Description\":\"test\""
          "}}",
    }, {
        // choosen StateFormatLevel 4 not require by commands but enables bugfix
        // -> stays at StateFormatLevel 4
        .profile = "{"
                    "\"Name\":\"custom\","
                    "\"StateFormatLevel\":4,"
                    "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                                   "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                                   "0x17a-0x193,0x197\","
                    "\"Description\":\"test\""
                   "}",
        .exp_fail = false,
        .exp_profile =
          "{\"ActiveProfile\":{"
            "\"Name\":\"custom\","
            "\"StateFormatLevel\":4,"
            "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                           "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                           "0x17a-0x193,0x197\","
            "\"Algorithms\":\"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,"
                             "sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                             "xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,"
                             "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                             "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                             "ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"
                             "camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb\","
            "\"Description\":\"test\""
          "}}",
    }, {
        .profile = "{"
                    "\"Name\":\"custom\","
                    "\"StateFormatLevel\":4,"
                    "\"Attributes\":\"no-unpadded-encryption\","
                    "\"Description\":\"test\""
                   "}",
        .exp_fail = true, /* StateFormatLevel 7 required */
    }, {
        .profile = "{" /* StateFormatLevel 7 is chosen */
                    "\"Name\":\"custom\","
                    "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                                   "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                                   "0x17a-0x193,0x197\","
                    "\"Attributes\":\"no-unpadded-encryption,no-sha1-signing,"
                                    "no-sha1-verification,drbg-continous-test,pct,"
                                    "no-ecc-key-derivation\","
                    "\"Description\":\"test\""
                   "}",
        .exp_fail = false,
        .exp_profile =
          "{\"ActiveProfile\":{"
            "\"Name\":\"custom\","
            "\"StateFormatLevel\":7,"
            "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                           "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                           "0x17a-0x193,0x197\","
            "\"Algorithms\":\"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,"
                             "sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                             "xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,"
                             "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                             "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                             "ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"
                             "camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb\","
            "\"Attributes\":\"no-unpadded-encryption,no-sha1-signing,"
                             "no-sha1-verification,drbg-continous-test,pct,"
                             "no-ecc-key-derivation\","
            "\"Description\":\"test\""
          "}}",
    }, {
        .profile = "{" /* StateFormatLevel 7 is chosen */
                    "\"Name\":\"custom:test\","
                    "\"Algorithms\":\"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,"
                                     "sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                                     "xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,"
                                     "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                                     "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                                     "ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"
                                     "camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb,"
                                     "hmac-min-key-size=128\","
                    "\"Description\":\"test\""
                   "}",
        .exp_fail = false,
        .exp_profile =
          "{\"ActiveProfile\":{"
            "\"Name\":\"custom:test\","
            "\"StateFormatLevel\":7,"
            "\"Commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                           "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                           "0x17a-0x193,0x197,0x199-0x19c\","
            "\"Algorithms\":\"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,"
                             "sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                             "xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,"
                             "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                             "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                             "ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"
                             "camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb,"
                             "hmac-min-key-size=128\","
            "\"Description\":\"test\""
          "}}",
    }, {
        // keep last
    }
};

int main(void)
{
    unsigned char *rbuffer = NULL;
    uint32_t rtotal = 0;
    uint32_t rlength;
    TPM_RESULT res;
    char *profile = NULL;
    int ret = 1;
    size_t i, j, n;

    for (i = 0;
         testcases[i].profile || testcases[i].exp_fail || testcases[i].exp_profile;
         i++) {
        TPMLIB_SetDebugLevel(10);

        res = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
        if (res) {
            fprintf(stderr, "TPMLIB_ChooseTPMVersion() failed: 0x%02x\n", res);
            goto exit;
        }

        res = TPMLIB_SetProfile(testcases[i].profile);
        if (testcases[i].exp_fail && !res) {
            fprintf(stderr,
                    "TPMLIB_SetProfile() did not fail as expected for testcase %zu.\n",
                    i + 1);
            goto exit;
        }
        if (res) {
            if (testcases[i].exp_fail) {
                printf("Passed test case %zu (failed as expected)\n", i + 1);
                continue;
            }
            fprintf(stderr, "TPMLIB_SetProfile() failed: 0x%02x\n", res);
            goto exit;
        }

        res = TPMLIB_MainInit();
        if (res) {
            fprintf(stderr, "TPMLIB_MainInit() failed: 0x%02x\n", res);
            goto exit;
        }

        /*
         * The stateFormatLevel will have to be adapted when the default profile
         * implements a later version of the state format.
         */
        profile = TPMLIB_GetInfo(TPMLIB_INFO_ACTIVE_PROFILE);
        if (strcmp(profile, testcases[i].exp_profile)) {
            fprintf(stderr,
                    "Active Profile is different than expected one.\n"
                    "actual   : %s\n"
                    "expected : %s\n",
                    profile, testcases[i].exp_profile);
            goto exit;
        }
        free(profile);
        profile = NULL;

        for (j = 0;
             testcases[i].tx && testcases[i].tx[j].cmd;
             j++) {
            uint32_t len;

            memcpy(&len, &testcases[i].tx[j].cmd[2], sizeof(len));

            res = TPMLIB_Process(&rbuffer, &rlength, &rtotal,
                                 testcases[i].tx[j].cmd, ntohl(len));
            if (res) {
                fprintf(stderr, "TPMLIB_Process() failed: 0x%02x\n",
                        res);
                goto exit;
            }

            memcpy(&len, &testcases[i].tx[j].rsp[2], sizeof(len));
            if (ntohl(len) != rlength || memcmp(rbuffer, testcases[i].tx[j].rsp, rlength)) {
                fprintf(stderr, "Response to command %zu is different than expected.\n",
                        j + 1);
                for (n = 0; n < rlength; n++)
                    fprintf(stderr, "%s%02x ", n == 0 ?   "actual   " : "", rbuffer[n]);
                for (n = 0; n < rlength; n++)
                    fprintf(stderr, "%s%02x ", n == 0 ? "\nexpected " : "", testcases[i].tx[j].rsp[n]);
                goto exit;
            }
            printf("  Received expected response to command %zu\n", j + 1);
        }

        TPMLIB_Terminate();
        printf("Passed test case %zu\n", i + 1);
    }

    ret = 0;

exit:
    free(profile);
    TPM_Free(rbuffer);

    return ret;
}
