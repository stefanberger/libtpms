/********************************************************************************/
/*										*/
/*			     RSA Test Vectors					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: RsaTestData.h 1259 2018-07-10 19:11:09Z kgoldman $		*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2016 - 2018				*/
/*										*/
/********************************************************************************/

//
// RSA Test Vectors

#define RSA_TEST_KEY_SIZE 256

typedef struct
{
    UINT16 size;
    BYTE   buffer[RSA_TEST_KEY_SIZE];
} TPM2B_RSA_TEST_KEY;

typedef TPM2B_RSA_TEST_KEY TPM2B_RSA_TEST_VALUE;

typedef struct
{
    UINT16 size;
    BYTE   buffer[RSA_TEST_KEY_SIZE / 2];
} TPM2B_RSA_TEST_PRIME;

const TPM2B_RSA_TEST_KEY c_rsaPublicModulus =
    {256,
     {0x91, 0x12, 0xf5, 0x07, 0x9d, 0x5f, 0x6b, 0x1c, 0x90, 0xf6, 0xcc, 0x87, 0xde,
      0x3a, 0x7a, 0x15, 0xdc, 0x54, 0x07, 0x6c, 0x26, 0x8f, 0x25, 0xef, 0x7e, 0x66,
      0xc0, 0xe3, 0x82, 0x12, 0x2f, 0xab, 0x52, 0x82, 0x1e, 0x85, 0xbc, 0x53, 0xba,
      0x2b, 0x01, 0xad, 0x01, 0xc7, 0x8d, 0x46, 0x4f, 0x7d, 0xdd, 0x7e, 0xdc, 0xb0,
      0xad, 0xf6, 0x0c, 0xa1, 0x62, 0x92, 0x97, 0x8a, 0x3e, 0x6f, 0x7e, 0x3e, 0xf6,
      0x9a, 0xcc, 0xf9, 0xa9, 0x86, 0x77, 0xb6, 0x85, 0x43, 0x42, 0x04, 0x13, 0x65,
      0xe2, 0xad, 0x36, 0xc9, 0xbf, 0xc1, 0x97, 0x84, 0x6f, 0xee, 0x7c, 0xda, 0x58,
      0xd2, 0xae, 0x07, 0x00, 0xaf, 0xc5, 0x5f, 0x4d, 0x3a, 0x98, 0xb0, 0xed, 0x27,
      0x7c, 0xc2, 0xce, 0x26, 0x5d, 0x87, 0xe1, 0xe3, 0xa9, 0x69, 0x88, 0x4f, 0x8c,
      0x08, 0x31, 0x18, 0xae, 0x93, 0x16, 0xe3, 0x74, 0xde, 0xd3, 0xf6, 0x16, 0xaf,
      0xa3, 0xac, 0x37, 0x91, 0x8d, 0x10, 0xc6, 0x6b, 0x64, 0x14, 0x3a, 0xd9, 0xfc,
      0xe4, 0xa0, 0xf2, 0xd1, 0x01, 0x37, 0x4f, 0x4a, 0xeb, 0xe5, 0xec, 0x98, 0xc5,
      0xd9, 0x4b, 0x30, 0xd2, 0x80, 0x2a, 0x5a, 0x18, 0x5a, 0x7d, 0xd4, 0x3d, 0xb7,
      0x62, 0x98, 0xce, 0x6d, 0xa2, 0x02, 0x6e, 0x45, 0xaa, 0x95, 0x73, 0xe0, 0xaa,
      0x75, 0x57, 0xb1, 0x3d, 0x1b, 0x05, 0x75, 0x23, 0x6b, 0x20, 0x69, 0x9e, 0x14,
      0xb0, 0x7f, 0xac, 0xae, 0xd2, 0xc7, 0x48, 0x3b, 0xe4, 0x56, 0x11, 0x34, 0x1e,
      0x05, 0x1a, 0x30, 0x20, 0xef, 0x68, 0x93, 0x6b, 0x9d, 0x7e, 0xdd, 0xba, 0x96,
      0x50, 0xcc, 0x1c, 0x81, 0xb4, 0x59, 0xb9, 0x74, 0x36, 0xd9, 0x97, 0xdc, 0x8f,
      0x17, 0x82, 0x72, 0xb3, 0x59, 0xf6, 0x23, 0xfa, 0x84, 0xf7, 0x6d, 0xf2, 0x05,
      0xff, 0xf1, 0xb9, 0xcc, 0xe9, 0xa2, 0x82, 0x01, 0xfb}};

const TPM2B_RSA_TEST_PRIME c_rsaPrivatePrime =
    {RSA_TEST_KEY_SIZE / 2,
     {0xb7, 0xa0, 0x90, 0xc7, 0x92, 0x09, 0xde, 0x71, 0x03, 0x37, 0x4a, 0xb5, 0x2f,
      0xda, 0x61, 0xb8, 0x09, 0x1b, 0xba, 0x99, 0x70, 0x45, 0xc1, 0x0b, 0x15, 0x12,
      0x71, 0x8a, 0xb3, 0x2a, 0x4d, 0x5a, 0x41, 0x9b, 0x73, 0x89, 0x80, 0x0a, 0x8f,
      0x18, 0x4c, 0x8b, 0xa2, 0x5b, 0xda, 0xbd, 0x43, 0xbe, 0xdc, 0x76, 0x4d, 0x71,
      0x0f, 0xb9, 0xfc, 0x7a, 0x09, 0xfe, 0x4f, 0xac, 0x63, 0xd9, 0x2e, 0x50, 0x3a,
      0xa1, 0x37, 0xc6, 0xf2, 0xa1, 0x89, 0x12, 0xe7, 0x72, 0x64, 0x2b, 0xba, 0xc1,
      0x1f, 0xca, 0x9d, 0xb7, 0xaa, 0x3a, 0xa9, 0xd3, 0xa6, 0x6f, 0x73, 0x02, 0xbb,
      0x85, 0x5d, 0x9a, 0xb9, 0x5c, 0x08, 0x83, 0x22, 0x20, 0x49, 0x91, 0x5f, 0x4b,
      0x86, 0xbc, 0x3f, 0x76, 0x43, 0x08, 0x97, 0xbf, 0x82, 0x55, 0x36, 0x2d, 0x8b,
      0x6e, 0x9e, 0xfb, 0xc1, 0x67, 0x6a, 0x43, 0xa2, 0x46, 0x81, 0x71}};

const BYTE c_RsaTestValue[RSA_TEST_KEY_SIZE] =
    {0x2a, 0x24, 0x3a, 0xbb, 0x50, 0x1d, 0xd4, 0x2a, 0xf9, 0x18, 0x32, 0x34, 0xa2,
     0x0f, 0xea, 0x5c, 0x91, 0x77, 0xe9, 0xe1, 0x09, 0x83, 0xdc, 0x5f, 0x71, 0x64,
     0x5b, 0xeb, 0x57, 0x79, 0xa0, 0x41, 0xc9, 0xe4, 0x5a, 0x0b, 0xf4, 0x9f, 0xdb,
     0x84, 0x04, 0xa6, 0x48, 0x24, 0xf6, 0x3f, 0x66, 0x1f, 0xa8, 0x04, 0x5c, 0xf0,
     0x7a, 0x6b, 0x4a, 0x9c, 0x7e, 0x21, 0xb6, 0xda, 0x6b, 0x65, 0x9c, 0x3a, 0x68,
     0x50, 0x13, 0x1e, 0xa4, 0xb7, 0xca, 0xec, 0xd3, 0xcc, 0xb2, 0x9b, 0x8c, 0x87,
     0xa4, 0x6a, 0xba, 0xc2, 0x06, 0x3f, 0x40, 0x48, 0x7b, 0xa8, 0xb8, 0x2c, 0x03,
     0x14, 0x33, 0xf3, 0x1d, 0xe9, 0xbd, 0x6f, 0x54, 0x66, 0xb4, 0x69, 0x5e, 0xbc,
     0x80, 0x7c, 0xe9, 0x6a, 0x43, 0x7f, 0xb8, 0x6a, 0xa0, 0x5f, 0x5d, 0x7a, 0x20,
     0xfd, 0x7a, 0x39, 0xe1, 0xea, 0x0e, 0x94, 0x91, 0x28, 0x63, 0x7a, 0xac, 0xc9,
     0xa5, 0x3a, 0x6d, 0x31, 0x7b, 0x7c, 0x54, 0x56, 0x99, 0x56, 0xbb, 0xb7, 0xa1,
     0x2d, 0xd2, 0x5c, 0x91, 0x5f, 0x1c, 0xd3, 0x06, 0x7f, 0x34, 0x53, 0x2f, 0x4c,
     0xd1, 0x8b, 0xd2, 0x9e, 0xdc, 0xc3, 0x94, 0x0a, 0xe1, 0x0f, 0xa5, 0x15, 0x46,
     0x2a, 0x8e, 0x10, 0xc2, 0xfe, 0xb7, 0x5e, 0x2d, 0x0d, 0xd1, 0x25, 0xfc, 0xe4,
     0xf7, 0x02, 0x19, 0xfe, 0xb6, 0xe4, 0x95, 0x9c, 0x17, 0x4a, 0x9b, 0xdb, 0xab,
     0xc7, 0x79, 0xe3, 0x5e, 0x40, 0xd0, 0x56, 0x6d, 0x25, 0x0a, 0x72, 0x65, 0x80,
     0x92, 0x9a, 0xa8, 0x07, 0x70, 0x32, 0x14, 0xfb, 0xfe, 0x08, 0xeb, 0x13, 0xb4,
     0x07, 0x68, 0xb4, 0x58, 0x39, 0xbe, 0x8e, 0x78, 0x3a, 0x59, 0x3f, 0x9c, 0x4c,
     0xe9, 0xa8, 0x64, 0x68, 0xf7, 0xb9, 0x6e, 0x20, 0xf5, 0xcb, 0xca, 0x47, 0xf2,
     0x17, 0xaa, 0x8b, 0xbc, 0x13, 0x14, 0x84, 0xf6, 0xab};

const TPM2B_RSA_TEST_VALUE c_RsaepKvt =
    {RSA_TEST_KEY_SIZE,
     {0x73, 0xbd, 0x65, 0x49, 0xda, 0x7b, 0xb8, 0x50, 0x9e, 0x87, 0xf0, 0x0a, 0x8a,
      0x9a, 0x07, 0xb6, 0x00, 0x82, 0x10, 0x14, 0x60, 0xd8, 0x01, 0xfc, 0xc5, 0x18,
      0xea, 0x49, 0x5f, 0x13, 0xcf, 0x65, 0x66, 0x30, 0x6c, 0x60, 0x3f, 0x24, 0x3c,
      0xfb, 0xe2, 0x31, 0x16, 0x99, 0x7e, 0x31, 0x98, 0xab, 0x93, 0xb8, 0x07, 0x53,
      0xcc, 0xdb, 0x7f, 0x44, 0xd9, 0xee, 0x5d, 0xe8, 0x5f, 0x97, 0x5f, 0xe8, 0x1f,
      0x88, 0x52, 0x24, 0x7b, 0xac, 0x62, 0x95, 0xb7, 0x7d, 0xf5, 0xf8, 0x9f, 0x5a,
      0xa8, 0x24, 0x9a, 0x76, 0x71, 0x2a, 0x35, 0x2a, 0xa1, 0x08, 0xbb, 0x95, 0xe3,
      0x64, 0xdc, 0xdb, 0xc2, 0x33, 0xa9, 0x5f, 0xbe, 0x4c, 0xc4, 0xcc, 0x28, 0xc9,
      0x25, 0xff, 0xee, 0x17, 0x15, 0x9a, 0x50, 0x90, 0x0e, 0x15, 0xb4, 0xea, 0x6a,
      0x09, 0xe6, 0xff, 0xa4, 0xee, 0xc7, 0x7e, 0xce, 0xa9, 0x73, 0xe4, 0xa0, 0x56,
      0xbd, 0x53, 0x2a, 0xe4, 0xc0, 0x2b, 0xa8, 0x9b, 0x09, 0x30, 0x72, 0x62, 0x0f,
      0xf9, 0xf6, 0xa1, 0x52, 0xd2, 0x8a, 0x37, 0xee, 0xa5, 0xc8, 0x47, 0xe1, 0x99,
      0x21, 0x47, 0xeb, 0xdd, 0x37, 0xaa, 0xe4, 0xbd, 0x55, 0x46, 0x5a, 0x5a, 0x5d,
      0xfb, 0x7b, 0xfc, 0xff, 0xbf, 0x26, 0x71, 0xf6, 0x1e, 0xad, 0xbc, 0xbf, 0x33,
      0xca, 0xe1, 0x92, 0x8f, 0x2a, 0x89, 0x6c, 0x45, 0x24, 0xd1, 0xa6, 0x52, 0x56,
      0x24, 0x5e, 0x90, 0x47, 0xe5, 0xcb, 0x12, 0xb0, 0x32, 0xf9, 0xa6, 0xbb, 0xea,
      0x37, 0xa9, 0xbd, 0xef, 0x23, 0xef, 0x63, 0x07, 0x6c, 0xc4, 0x4e, 0x64, 0x3c,
      0xc6, 0x11, 0x84, 0x7d, 0x65, 0xd6, 0x5d, 0x7a, 0x17, 0x58, 0xa5, 0xf7, 0x74,
      0x3b, 0x42, 0xe3, 0xd2, 0xda, 0x5f, 0x6f, 0xe0, 0x1e, 0x4b, 0xcf, 0x46, 0xe2,
      0xdf, 0x3e, 0x41, 0x8e, 0x0e, 0xb0, 0x3f, 0x8b, 0x65}};

#define OAEP_TEST_LABEL "OAEP Test Value"

#if ALG_SHA1_VALUE == DEFAULT_TEST_HASH

const TPM2B_RSA_TEST_VALUE c_OaepKvt =
    {RSA_TEST_KEY_SIZE,
     {0x32, 0x68, 0x84, 0x0b, 0x9c, 0xc9, 0x25, 0x26, 0xd9, 0xc0, 0xd0, 0xb1, 0xde,
      0x60, 0x55, 0xae, 0x33, 0xe5, 0xcf, 0x6c, 0x85, 0xbe, 0x0d, 0x71, 0x11, 0xe1,
      0x45, 0x60, 0xbb, 0x42, 0x3d, 0xf3, 0xb1, 0x18, 0x84, 0x7b, 0xc6, 0x5d, 0xce,
      0x1d, 0x5f, 0x9a, 0x97, 0xcf, 0xb1, 0x97, 0x9a, 0x85, 0x7c, 0xa7, 0xa1, 0x63,
      0x23, 0xb6, 0x74, 0x0f, 0x1a, 0xee, 0x29, 0x51, 0xeb, 0x50, 0x8f, 0x3c, 0x8e,
      0x4e, 0x31, 0x38, 0xdc, 0x11, 0xfc, 0x9a, 0x4e, 0xaf, 0x93, 0xc9, 0x7f, 0x6e,
      0x35, 0xf3, 0xc9, 0xe4, 0x89, 0x14, 0x53, 0xe2, 0xc2, 0x1a, 0xf7, 0x6b, 0x9b,
      0xf0, 0x7a, 0xa4, 0x69, 0x52, 0xe0, 0x24, 0x8f, 0xea, 0x31, 0xa7, 0x5c, 0x43,
      0xb0, 0x65, 0xc9, 0xfe, 0xba, 0xfe, 0x80, 0x9e, 0xa5, 0xc0, 0xf5, 0x8d, 0xce,
      0x41, 0xf9, 0x83, 0x0d, 0x8e, 0x0f, 0xef, 0x3d, 0x1f, 0x6a, 0xcc, 0x8a, 0x3d,
      0x3b, 0xdf, 0x22, 0x38, 0xd7, 0x34, 0x58, 0x7b, 0x55, 0xc9, 0xf6, 0xbc, 0x7c,
      0x4c, 0x3f, 0xd7, 0xde, 0x4e, 0x30, 0xa9, 0x69, 0xf3, 0x5f, 0x56, 0x8f, 0xc2,
      0xe7, 0x75, 0x79, 0xb8, 0xa5, 0xc8, 0x0d, 0xc0, 0xcd, 0xb6, 0xc9, 0x63, 0xad,
      0x7c, 0xe4, 0x8f, 0x39, 0x60, 0x4d, 0x7d, 0xdb, 0x34, 0x49, 0x2a, 0x47, 0xde,
      0xc0, 0x42, 0x4a, 0x19, 0x94, 0x2e, 0x50, 0x21, 0x03, 0x47, 0xff, 0x73, 0xb3,
      0xb7, 0x89, 0xcc, 0x7b, 0x2c, 0xeb, 0x03, 0xa7, 0x9a, 0x06, 0xfd, 0xed, 0x19,
      0xbb, 0x82, 0xa0, 0x13, 0xe9, 0xfa, 0xac, 0x06, 0x5f, 0xc5, 0xa9, 0x2b, 0xda,
      0x88, 0x23, 0xa2, 0x5d, 0xc2, 0x7f, 0xda, 0xc8, 0x5a, 0x94, 0x31, 0xc1, 0x21,
      0xd7, 0x1e, 0x6b, 0xd7, 0x89, 0xb1, 0x93, 0x80, 0xab, 0xd1, 0x37, 0xf2, 0x6f,
      0x50, 0xcd, 0x2a, 0xea, 0xb1, 0xc4, 0xcd, 0xcb, 0xb5}};

const TPM2B_RSA_TEST_VALUE c_RsaesKvt =
    {RSA_TEST_KEY_SIZE,
     {0x29, 0xa4, 0x2f, 0xbb, 0x8a, 0x14, 0x05, 0x1e, 0x3c, 0x72, 0x76, 0x77, 0x38,
      0xe7, 0x73, 0xe3, 0x6e, 0x24, 0x4b, 0x38, 0xd2, 0x1a, 0xcf, 0x23, 0x58, 0x78,
      0x36, 0x82, 0x23, 0x6e, 0x6b, 0xef, 0x2c, 0x3d, 0xf2, 0xe8, 0xd6, 0xc6, 0x87,
      0x8e, 0x78, 0x9b, 0x27, 0x39, 0xc0, 0xd6, 0xef, 0x4d, 0x0b, 0xfc, 0x51, 0x27,
      0x18, 0xf3, 0x51, 0x5e, 0x4d, 0x96, 0x3a, 0xe2, 0x15, 0xe2, 0x7e, 0x42, 0xf4,
      0x16, 0xd5, 0xc6, 0x52, 0x5d, 0x17, 0x44, 0x76, 0x09, 0x7a, 0xcf, 0xe3, 0x30,
      0xe3, 0x84, 0xf6, 0x6f, 0x3a, 0x33, 0xfb, 0x32, 0x0d, 0x1d, 0xe7, 0x7c, 0x80,
      0x82, 0x4f, 0xed, 0xda, 0x87, 0x11, 0x9c, 0xc3, 0x7e, 0x85, 0xbd, 0x18, 0x58,
      0x08, 0x2b, 0x23, 0x37, 0xe7, 0x9d, 0xd0, 0xd1, 0x79, 0xe2, 0x05, 0xbd, 0xf5,
      0x4f, 0x0e, 0x0f, 0xdb, 0x4a, 0x74, 0xeb, 0x09, 0x01, 0xb3, 0xca, 0xbd, 0xa6,
      0x7b, 0x09, 0xb1, 0x13, 0x77, 0x30, 0x4d, 0x87, 0x41, 0x06, 0x57, 0x2e, 0x5f,
      0x36, 0x6e, 0xfc, 0x35, 0x69, 0xfe, 0x0a, 0x24, 0x6c, 0x98, 0x8c, 0xda, 0x97,
      0xf4, 0xfb, 0xc7, 0x83, 0x2d, 0x3e, 0x7d, 0xc0, 0x5c, 0x34, 0xfd, 0x11, 0x2a,
      0x12, 0xa7, 0xae, 0x4a, 0xde, 0xc8, 0x4e, 0xcf, 0xf4, 0x85, 0x63, 0x77, 0xc6,
      0x33, 0x34, 0xe0, 0x27, 0xe4, 0x9e, 0x91, 0x0b, 0x4b, 0x85, 0xf0, 0xb0, 0x79,
      0xaa, 0x7c, 0xc6, 0xff, 0x3b, 0xbc, 0x04, 0x73, 0xb8, 0x95, 0xd7, 0x31, 0x54,
      0x3b, 0x56, 0xec, 0x52, 0x15, 0xd7, 0x3e, 0x62, 0xf5, 0x82, 0x99, 0x3e, 0x2a,
      0xc0, 0x4b, 0x2e, 0x06, 0x57, 0x6d, 0x3f, 0x3e, 0x77, 0x1f, 0x2b, 0x2d, 0xc5,
      0xb9, 0x3b, 0x68, 0x56, 0x73, 0x70, 0x32, 0x6b, 0x6b, 0x65, 0x25, 0x76, 0x45,
      0x6c, 0x45, 0xf1, 0x6c, 0x59, 0xfc, 0x94, 0xa7, 0x15}};

const TPM2B_RSA_TEST_VALUE c_RsapssKvt =
    {RSA_TEST_KEY_SIZE,
     {0x01, 0xfe, 0xd5, 0x83, 0x0b, 0x15, 0xba, 0x90, 0x2c, 0xdf, 0xf7, 0x26, 0xb7,
      0x8f, 0xb1, 0xd7, 0x0b, 0xfd, 0x83, 0xf9, 0x95, 0xd5, 0xd7, 0xb5, 0xc5, 0xc5,
      0x4a, 0xde, 0xd5, 0xe6, 0x20, 0x78, 0xca, 0x73, 0x77, 0x3d, 0x61, 0x36, 0x48,
      0xae, 0x3e, 0x8f, 0xee, 0x43, 0x29, 0x96, 0xdf, 0x3f, 0x1c, 0x97, 0x5a, 0xbe,
      0xe5, 0xa2, 0x7e, 0x5b, 0xd0, 0xc0, 0x29, 0x39, 0x83, 0x81, 0x77, 0x24, 0x43,
      0xdb, 0x3c, 0x64, 0x4d, 0xf0, 0x23, 0xe4, 0xae, 0x0f, 0x78, 0x31, 0x8c, 0xda,
      0x0c, 0xec, 0xf1, 0xdf, 0x09, 0xf2, 0x14, 0x6a, 0x4d, 0xaf, 0x36, 0x81, 0x6e,
      0xbd, 0xbe, 0x36, 0x79, 0x88, 0x98, 0xb6, 0x6f, 0x5a, 0xad, 0xcf, 0x7c, 0xee,
      0xe0, 0xdd, 0x00, 0xbe, 0x59, 0x97, 0x88, 0x00, 0x34, 0xc0, 0x8b, 0x48, 0x42,
      0x05, 0x04, 0x5a, 0xb7, 0x85, 0x38, 0xa0, 0x35, 0xd7, 0x3b, 0x51, 0xb8, 0x7b,
      0x81, 0x83, 0xee, 0xff, 0x76, 0x6f, 0x50, 0x39, 0x4d, 0xab, 0x89, 0x63, 0x07,
      0x6d, 0xf5, 0xe5, 0x01, 0x10, 0x56, 0xfe, 0x93, 0x06, 0x8f, 0xd3, 0xc9, 0x41,
      0xab, 0xc9, 0xdf, 0x6e, 0x59, 0xa8, 0xc3, 0x1d, 0xbf, 0x96, 0x4a, 0x59, 0x80,
      0x3c, 0x90, 0x3a, 0x59, 0x56, 0x4c, 0x6d, 0x44, 0x6d, 0xeb, 0xdc, 0x73, 0xcd,
      0xc1, 0xec, 0xb8, 0x41, 0xbf, 0x89, 0x8c, 0x03, 0x69, 0x4c, 0xaf, 0x3f, 0xc1,
      0xc5, 0xc7, 0xe7, 0x7d, 0xa7, 0x83, 0x39, 0x70, 0xa2, 0x6b, 0x83, 0xbc, 0xbe,
      0xf5, 0xbf, 0x1c, 0xee, 0x6e, 0xa3, 0x22, 0x1e, 0x25, 0x2f, 0x16, 0x68, 0x69,
      0x5a, 0x1d, 0xfa, 0x2c, 0x3a, 0x0f, 0x67, 0xe1, 0x77, 0x12, 0xe8, 0x3d, 0xba,
      0xaa, 0xef, 0x96, 0x9c, 0x1f, 0x64, 0x32, 0xf4, 0xa7, 0xb3, 0x3f, 0x7d, 0x61,
      0xbb, 0x9a, 0x27, 0xad, 0xfb, 0x2f, 0x33, 0xc4, 0x70}};

const TPM2B_RSA_TEST_VALUE c_RsassaKvt =
    {RSA_TEST_KEY_SIZE,
     {0x67, 0x4e, 0xdd, 0xc2, 0xd2, 0x6d, 0xe0, 0x03, 0xc4, 0xc2, 0x41, 0xd3, 0xd4,
      0x61, 0x30, 0xd0, 0xe1, 0x68, 0x31, 0x4a, 0xda, 0xd9, 0xc2, 0x5d, 0xaa, 0xa2,
      0x7b, 0xfb, 0x44, 0x02, 0xf5, 0xd6, 0xd8, 0x2e, 0xcd, 0x13, 0x36, 0xc9, 0x4b,
      0xdb, 0x1a, 0x4b, 0x66, 0x1b, 0x4f, 0x9c, 0xb7, 0x17, 0xac, 0x53, 0x37, 0x4f,
      0x21, 0xbd, 0x0c, 0x66, 0xac, 0x06, 0x65, 0x52, 0x9f, 0x04, 0xf6, 0xa5, 0x22,
      0x5b, 0xf7, 0xe6, 0x0d, 0x3c, 0x9f, 0x41, 0x19, 0x09, 0x88, 0x7c, 0x41, 0x4c,
      0x2f, 0x9c, 0x8b, 0x3c, 0xdd, 0x7c, 0x28, 0x78, 0x24, 0xd2, 0x09, 0xa6, 0x5b,
      0xf7, 0x3c, 0x88, 0x7e, 0x73, 0x5a, 0x2d, 0x36, 0x02, 0x4f, 0x65, 0xb0, 0xcb,
      0xc8, 0xdc, 0xac, 0xa2, 0xda, 0x8b, 0x84, 0x91, 0x71, 0xe4, 0x30, 0x8b, 0xb6,
      0x12, 0xf2, 0xf0, 0xd0, 0xa0, 0x38, 0xcf, 0x75, 0xb7, 0x20, 0xcb, 0x35, 0x51,
      0x52, 0x6b, 0xc4, 0xf4, 0x21, 0x95, 0xc2, 0xf7, 0x9a, 0x13, 0xc1, 0x1a, 0x7b,
      0x8f, 0x77, 0xda, 0x19, 0x48, 0xbb, 0x6d, 0x14, 0x5d, 0xba, 0x65, 0xb4, 0x9e,
      0x43, 0x42, 0x58, 0x98, 0x0b, 0x91, 0x46, 0xd8, 0x4c, 0xf3, 0x4c, 0xaf, 0x2e,
      0x02, 0xa6, 0xb2, 0x49, 0x12, 0x62, 0x43, 0x4e, 0xa8, 0xac, 0xbf, 0xfd, 0xfa,
      0x37, 0x24, 0xea, 0x69, 0x1c, 0xf5, 0xae, 0xfa, 0x08, 0x82, 0x30, 0xc3, 0xc0,
      0xf8, 0x9a, 0x89, 0x33, 0xe1, 0x40, 0x6d, 0x18, 0x5c, 0x7b, 0x90, 0x48, 0xbf,
      0x37, 0xdb, 0xea, 0xfb, 0x0e, 0xd4, 0x2e, 0x11, 0xfa, 0xa9, 0x86, 0xff, 0x00,
      0x0b, 0x7b, 0xca, 0x09, 0x64, 0x6a, 0x8f, 0x0c, 0x0e, 0x09, 0x14, 0x36, 0x4a,
      0x74, 0x31, 0x18, 0x5b, 0x18, 0xeb, 0xea, 0x83, 0xc3, 0x66, 0x68, 0xa6, 0x7d,
      0x43, 0x06, 0x0f, 0x99, 0x60, 0xce, 0x65, 0x08, 0xf6}};

#endif  // SHA1

#if ALG_SHA256_VALUE == DEFAULT_TEST_HASH

const TPM2B_RSA_TEST_VALUE c_OaepKvt =
    {RSA_TEST_KEY_SIZE,
     {0x33, 0x20, 0x6e, 0x21, 0xc3, 0xf6, 0xcd, 0xf8, 0xd7, 0x5d, 0x9f, 0xe9, 0x05,
      0x14, 0x8c, 0x7c, 0xbb, 0x69, 0x24, 0x9e, 0x52, 0x8f, 0xaf, 0x84, 0x73, 0x21,
      0x2c, 0x85, 0xa5, 0x30, 0x4d, 0xb6, 0xb8, 0xfa, 0x15, 0x9b, 0xc7, 0x8f, 0xc9,
      0x7a, 0x72, 0x4b, 0x85, 0xa4, 0x1c, 0xc5, 0xd8, 0xe4, 0x92, 0xb3, 0xec, 0xd9,
      0xa8, 0xca, 0x5e, 0x74, 0x73, 0x89, 0x7f, 0xb4, 0xac, 0x7e, 0x68, 0x12, 0xb2,
      0x53, 0x27, 0x4b, 0xbf, 0xd0, 0x71, 0x69, 0x46, 0x9f, 0xef, 0xf4, 0x70, 0x60,
      0xf8, 0xd7, 0xae, 0xc7, 0x5a, 0x27, 0x38, 0x25, 0x2d, 0x25, 0xab, 0x96, 0x56,
      0x66, 0x3a, 0x23, 0x40, 0xa8, 0xdb, 0xbc, 0x86, 0xe8, 0xf3, 0xd2, 0x58, 0x0b,
      0x44, 0xfc, 0x94, 0x1e, 0xb7, 0x5d, 0xb4, 0x57, 0xb5, 0xf3, 0x56, 0xee, 0x9b,
      0xcf, 0x97, 0x91, 0x29, 0x36, 0xe3, 0x06, 0x13, 0xa2, 0xea, 0xd6, 0xd6, 0x0b,
      0x86, 0x0b, 0x1a, 0x27, 0xe6, 0x22, 0xc4, 0x7b, 0xff, 0xde, 0x0f, 0xbf, 0x79,
      0xc8, 0x1b, 0xed, 0xf1, 0x27, 0x62, 0xb5, 0x8b, 0xf9, 0xd9, 0x76, 0x90, 0xf6,
      0xcc, 0x83, 0x0f, 0xce, 0xce, 0x2e, 0x63, 0x7a, 0x9b, 0xf4, 0x48, 0x5b, 0xd7,
      0x81, 0x2c, 0x3a, 0xdb, 0x59, 0x0d, 0x4d, 0x9e, 0x46, 0xe9, 0x9e, 0x92, 0x22,
      0x27, 0x1c, 0xb0, 0x67, 0x8a, 0xe6, 0x8a, 0x16, 0x8a, 0xdf, 0x95, 0x76, 0x24,
      0x82, 0xad, 0xf1, 0xbc, 0x97, 0xbf, 0xd3, 0x5e, 0x6e, 0x14, 0x0c, 0x5b, 0x25,
      0xfe, 0x58, 0xfa, 0x64, 0xe5, 0x14, 0x46, 0xb7, 0x58, 0xc6, 0x3f, 0x7f, 0x42,
      0xd2, 0x8e, 0x45, 0x13, 0x41, 0x85, 0x12, 0x2e, 0x96, 0x19, 0xd0, 0x5e, 0x7d,
      0x34, 0x06, 0x32, 0x2b, 0xc8, 0xd9, 0x0d, 0x6c, 0x06, 0x36, 0xa0, 0xff, 0x47,
      0x57, 0x2c, 0x25, 0xbc, 0x8a, 0xa5, 0xe2, 0xc7, 0xe3}};

const TPM2B_RSA_TEST_VALUE c_RsaesKvt =
    {RSA_TEST_KEY_SIZE,
     {0x39, 0xfc, 0x10, 0x5d, 0xf4, 0x45, 0x3d, 0x94, 0x53, 0x06, 0x89, 0x24, 0xe7,
      0xe8, 0xfd, 0x03, 0xac, 0xfd, 0xbd, 0xb2, 0x28, 0xd3, 0x4a, 0x52, 0xc5, 0xd4,
      0xdb, 0x17, 0xd4, 0x24, 0x05, 0xc4, 0xeb, 0x6a, 0xce, 0x1d, 0xbb, 0x37, 0xcb,
      0x09, 0xd8, 0x6c, 0x83, 0x19, 0x93, 0xd4, 0xe2, 0x88, 0x88, 0x9b, 0xaf, 0x92,
      0x16, 0xc4, 0x15, 0xbd, 0x49, 0x13, 0x22, 0xb7, 0x84, 0xcf, 0x23, 0xf2, 0x6f,
      0x0c, 0x3e, 0x8f, 0xde, 0x04, 0x09, 0x31, 0x2d, 0x99, 0xdf, 0xe6, 0x74, 0x70,
      0x30, 0xde, 0x8c, 0xad, 0x32, 0x86, 0xe2, 0x7c, 0x12, 0x90, 0x21, 0xf3, 0x86,
      0xb7, 0xe2, 0x64, 0xca, 0x98, 0xcc, 0x64, 0x4b, 0xef, 0x57, 0x4f, 0x5a, 0x16,
      0x6e, 0xd7, 0x2f, 0x5b, 0xf6, 0x07, 0xad, 0x33, 0xb4, 0x8f, 0x3b, 0x3a, 0x8b,
      0xd9, 0x06, 0x2b, 0xed, 0x3c, 0x3c, 0x76, 0xf6, 0x21, 0x31, 0xe3, 0xfb, 0x2c,
      0x45, 0x61, 0x42, 0xba, 0xe0, 0xc3, 0x72, 0x63, 0xd0, 0x6b, 0x8f, 0x36, 0x26,
      0xfb, 0x9e, 0x89, 0x0e, 0x44, 0x9a, 0xc1, 0x84, 0x5e, 0x84, 0x8d, 0xb6, 0xea,
      0xf1, 0x0d, 0x66, 0xc7, 0xdb, 0x44, 0xbd, 0x19, 0x7c, 0x05, 0xbe, 0xc4, 0xab,
      0x88, 0x32, 0xbe, 0xc7, 0x63, 0x31, 0xe6, 0x38, 0xd4, 0xe5, 0xb8, 0x4b, 0xf5,
      0x0e, 0x55, 0x9a, 0x3a, 0xe6, 0x0a, 0xec, 0xee, 0xe2, 0xa8, 0x88, 0x04, 0xf2,
      0xb8, 0xaa, 0x5a, 0xd8, 0x97, 0x5d, 0xa0, 0xa8, 0x42, 0xfb, 0xd9, 0xde, 0x80,
      0xae, 0x4c, 0xb3, 0xa1, 0x90, 0x47, 0x57, 0x03, 0x10, 0x78, 0xa6, 0x8f, 0x11,
      0xba, 0x4b, 0xce, 0x2d, 0x56, 0xa4, 0xe1, 0xbd, 0xf8, 0xa0, 0xa4, 0xd5, 0x48,
      0x3c, 0x63, 0x20, 0x00, 0x38, 0xa0, 0xd1, 0xe6, 0x12, 0xe9, 0x1d, 0xd8, 0x49,
      0xe3, 0xd5, 0x24, 0xb5, 0xc5, 0x3a, 0x1f, 0xb0, 0xd4}};

const TPM2B_RSA_TEST_VALUE c_RsapssKvt =
    {RSA_TEST_KEY_SIZE,
     {0x74, 0x89, 0x29, 0x3e, 0x1b, 0xac, 0xc6, 0x85, 0xca, 0xf0, 0x63, 0x43, 0x30,
      0x7d, 0x1c, 0x9b, 0x2f, 0xbd, 0x4d, 0x69, 0x39, 0x5e, 0x85, 0xe2, 0xef, 0x86,
      0x0a, 0xc6, 0x6b, 0xa6, 0x08, 0x19, 0x6c, 0x56, 0x38, 0x24, 0x55, 0x92, 0x84,
      0x9b, 0x1b, 0x8b, 0x04, 0xcf, 0x24, 0x14, 0x24, 0x13, 0x0e, 0x8b, 0x82, 0x6f,
      0x96, 0xc8, 0x9a, 0x68, 0xfc, 0x4c, 0x02, 0xf0, 0xdc, 0xcd, 0x36, 0x25, 0x31,
      0xd5, 0x82, 0xcf, 0xc9, 0x69, 0x72, 0xf6, 0x1d, 0xab, 0x68, 0x20, 0x2e, 0x2d,
      0x19, 0x49, 0xf0, 0x2e, 0xad, 0xd2, 0xda, 0xaf, 0xff, 0xb6, 0x92, 0x83, 0x5b,
      0x8a, 0x06, 0x2d, 0x0c, 0x32, 0x11, 0x32, 0x3b, 0x77, 0x17, 0xf6, 0x50, 0xfb,
      0xf8, 0x57, 0xc9, 0xc7, 0x9b, 0x9e, 0xc6, 0xd1, 0xa9, 0x55, 0xf0, 0x22, 0x35,
      0xda, 0xca, 0x3c, 0x8e, 0xc6, 0x9a, 0xd8, 0x25, 0xc8, 0x5e, 0x93, 0x0d, 0xaa,
      0xa7, 0x06, 0xaf, 0x11, 0x29, 0x99, 0xe7, 0x7c, 0xee, 0x49, 0x82, 0x30, 0xba,
      0x2c, 0xe2, 0x40, 0x8f, 0x0a, 0xa6, 0x7b, 0x24, 0x75, 0xc5, 0xcd, 0x03, 0x12,
      0xf4, 0xb2, 0x4b, 0x3a, 0xd1, 0x91, 0x3c, 0x20, 0x0e, 0x58, 0x2b, 0x31, 0xf8,
      0x8b, 0xee, 0xbc, 0x1f, 0x95, 0x35, 0x58, 0x6a, 0x73, 0xee, 0x99, 0xb0, 0x01,
      0x42, 0x4f, 0x66, 0xc0, 0x66, 0xbb, 0x35, 0x86, 0xeb, 0xd9, 0x7b, 0x55, 0x77,
      0x2d, 0x54, 0x78, 0x19, 0x49, 0xe8, 0xcc, 0xfd, 0xb1, 0xcb, 0x49, 0xc9, 0xea,
      0x20, 0xab, 0xed, 0xb5, 0xed, 0xfe, 0xb2, 0xb5, 0xa8, 0xcf, 0x05, 0x06, 0xd5,
      0x7d, 0x2b, 0xbb, 0x0b, 0x65, 0x6b, 0x2b, 0x6d, 0x55, 0x95, 0x85, 0x44, 0x8b,
      0x12, 0x05, 0xf3, 0x4b, 0xd4, 0x8e, 0x3d, 0x68, 0x2d, 0x29, 0x9c, 0x05, 0x79,
      0xd6, 0xfc, 0x72, 0x90, 0x6a, 0xab, 0x46, 0x38, 0x81}};

const TPM2B_RSA_TEST_VALUE c_RsassaKvt =
    {RSA_TEST_KEY_SIZE,
     {0x8a, 0xb1, 0x0a, 0xb5, 0xe4, 0x02, 0xf7, 0xdd, 0x45, 0x2a, 0xcc, 0x2b, 0x6b,
      0x8c, 0x0e, 0x9a, 0x92, 0x4f, 0x9b, 0xc5, 0xe4, 0x8b, 0x82, 0xb9, 0xb0, 0xd9,
      0x87, 0x8c, 0xcb, 0xf0, 0xb0, 0x59, 0xa5, 0x92, 0x21, 0xa0, 0xa7, 0x61, 0x5c,
      0xed, 0xa8, 0x6e, 0x22, 0x29, 0x46, 0xc7, 0x86, 0x37, 0x4b, 0x1b, 0x1e, 0x94,
      0x93, 0xc8, 0x4c, 0x17, 0x7a, 0xae, 0x59, 0x91, 0xf8, 0x83, 0x84, 0xc4, 0x8c,
      0x38, 0xc2, 0x35, 0x0e, 0x7e, 0x50, 0x67, 0x76, 0xe7, 0xd3, 0xec, 0x6f, 0x0d,
      0xa0, 0x5c, 0x2f, 0x0a, 0x80, 0x28, 0xd3, 0xc5, 0x7d, 0x2d, 0x1a, 0x0b, 0x96,
      0xd6, 0xe5, 0x98, 0x05, 0x8c, 0x4d, 0xa0, 0x1f, 0x8c, 0xb6, 0xfb, 0xb1, 0xcf,
      0xe9, 0xcb, 0x38, 0x27, 0x60, 0x64, 0x17, 0xca, 0xf4, 0x8b, 0x61, 0xb7, 0x1d,
      0xb6, 0x20, 0x9d, 0x40, 0x2a, 0x1c, 0xfd, 0x55, 0x40, 0x4b, 0x95, 0x39, 0x52,
      0x18, 0x3b, 0xab, 0x44, 0xe8, 0x83, 0x4b, 0x7c, 0x47, 0xfb, 0xed, 0x06, 0x9c,
      0xcd, 0x4f, 0xba, 0x81, 0xd6, 0xb7, 0x31, 0xcf, 0x5c, 0x23, 0xf8, 0x25, 0xab,
      0x95, 0x77, 0x0a, 0x8f, 0x46, 0xef, 0xfb, 0x59, 0xb8, 0x04, 0xd7, 0x1e, 0xf5,
      0xaf, 0x6a, 0x1a, 0x26, 0x9b, 0xae, 0xf4, 0xf5, 0x7f, 0x84, 0x6f, 0x3c, 0xed,
      0xf8, 0x24, 0x0b, 0x43, 0xd1, 0xba, 0x74, 0x89, 0x4e, 0x39, 0xfe, 0xab, 0xa5,
      0x16, 0xa5, 0x28, 0xee, 0x96, 0x84, 0x3e, 0x16, 0x6d, 0x5f, 0x4e, 0x0b, 0x7d,
      0x94, 0x16, 0x1b, 0x8c, 0xf9, 0xaa, 0x9b, 0xc0, 0x49, 0x02, 0x4c, 0x3e, 0x62,
      0xff, 0xfe, 0xa2, 0x20, 0x33, 0x5e, 0xa6, 0xdd, 0xda, 0x15, 0x2d, 0xb7, 0xcd,
      0xda, 0xff, 0xb1, 0x0b, 0x45, 0x7b, 0xd3, 0xa0, 0x42, 0x29, 0xab, 0xa9, 0x73,
      0xe9, 0xa4, 0xd9, 0x8d, 0xac, 0xa1, 0x88, 0x2c, 0x2d}};

#endif  // SHA256

#if ALG_SHA384_VALUE == DEFAULT_TEST_HASH

const TPM2B_RSA_TEST_VALUE c_OaepKvt =
    {RSA_TEST_KEY_SIZE,
     {0x0f, 0x3c, 0x42, 0x4d, 0x8c, 0x91, 0x96, 0x05, 0x3c, 0xfd, 0x59, 0x3b, 0x7f,
      0x29, 0xbc, 0x03, 0x67, 0xc1, 0xff, 0x74, 0xe7, 0x09, 0xf4, 0x13, 0x45, 0xbe,
      0x13, 0x1d, 0xc9, 0x86, 0x94, 0xfe, 0xed, 0xa6, 0xe8, 0x3a, 0xcb, 0x89, 0x4d,
      0xec, 0x86, 0x63, 0x4c, 0xdb, 0xf1, 0x95, 0xee, 0xc1, 0x46, 0xc5, 0x3b, 0xd8,
      0xf8, 0xa2, 0x41, 0x6a, 0x60, 0x8b, 0x9e, 0x5e, 0x7f, 0x20, 0x16, 0xe3, 0x69,
      0xb6, 0x2d, 0x92, 0xfc, 0x60, 0xa2, 0x74, 0x88, 0xd5, 0xc7, 0xa6, 0xd1, 0xff,
      0xe3, 0x45, 0x02, 0x51, 0x39, 0xd9, 0xf3, 0x56, 0x0b, 0x91, 0x80, 0xe0, 0x6c,
      0xa8, 0xc3, 0x78, 0xef, 0x34, 0x22, 0x8c, 0xf5, 0xfb, 0x47, 0x98, 0x5d, 0x57,
      0x8e, 0x3a, 0xb9, 0xff, 0x92, 0x04, 0xc7, 0xc2, 0x6e, 0xfa, 0x14, 0xc1, 0xb9,
      0x68, 0x15, 0x5c, 0x12, 0xe8, 0xa8, 0xbe, 0xea, 0xe8, 0x8d, 0x9b, 0x48, 0x28,
      0x35, 0xdb, 0x4b, 0x52, 0xc1, 0x2d, 0x85, 0x47, 0x83, 0xd0, 0xe9, 0xae, 0x90,
      0x6e, 0x65, 0xd4, 0x34, 0x7f, 0x81, 0xce, 0x69, 0xf0, 0x96, 0x62, 0xf7, 0xec,
      0x41, 0xd5, 0xc2, 0xe3, 0x4b, 0xba, 0x9c, 0x8a, 0x02, 0xce, 0xf0, 0x5d, 0x14,
      0xf7, 0x09, 0x42, 0x8e, 0x4a, 0x27, 0xfe, 0x3e, 0x66, 0x42, 0x99, 0x03, 0xe1,
      0x69, 0xbd, 0xdb, 0x7f, 0x9b, 0x70, 0xeb, 0x4e, 0x9c, 0xac, 0x45, 0x67, 0x91,
      0x9f, 0x75, 0x10, 0xc6, 0xfc, 0x14, 0xe1, 0x28, 0xc1, 0x0e, 0xe0, 0x7e, 0xc0,
      0x5c, 0x1d, 0xee, 0xe8, 0xff, 0x45, 0x79, 0x51, 0x86, 0x08, 0xe6, 0x39, 0xac,
      0xb5, 0xfd, 0xb8, 0xf1, 0xdd, 0x2e, 0xf4, 0xb2, 0x1a, 0x69, 0x0d, 0xd9, 0x98,
      0x8e, 0xdb, 0x85, 0x61, 0x70, 0x20, 0x82, 0x91, 0x26, 0x87, 0x80, 0xc4, 0x6a,
      0xd8, 0x3b, 0x91, 0x4d, 0xd3, 0x33, 0x84, 0xad, 0xb7}};

const TPM2B_RSA_TEST_VALUE c_RsaesKvt =
    {RSA_TEST_KEY_SIZE,
     {0x44, 0xd5, 0x9f, 0xbc, 0x48, 0x03, 0x3d, 0x9f, 0x22, 0x91, 0x2a, 0xab, 0x3c,
      0x31, 0x71, 0xab, 0x86, 0x3f, 0x0f, 0x6f, 0x59, 0x5b, 0x93, 0x27, 0xbc, 0xbc,
      0xcd, 0x29, 0x38, 0x43, 0x2a, 0x3b, 0x3b, 0xd2, 0xb3, 0x45, 0x40, 0xba, 0x15,
      0xb4, 0x45, 0xe3, 0x56, 0xab, 0xff, 0xb3, 0x20, 0x26, 0x39, 0xcc, 0x48, 0xc5,
      0x5d, 0x41, 0x0d, 0x2f, 0x57, 0x7f, 0x9d, 0x16, 0x2e, 0x26, 0x57, 0xc7, 0x6b,
      0xf3, 0x36, 0x54, 0xbd, 0xb6, 0x1d, 0x46, 0x4e, 0x13, 0x50, 0xd7, 0x61, 0x9d,
      0x8d, 0x7b, 0xeb, 0x21, 0x9f, 0x79, 0xf3, 0xfd, 0xe0, 0x1b, 0xa8, 0xed, 0x6d,
      0x29, 0x33, 0x0d, 0x65, 0x94, 0x24, 0x1e, 0x62, 0x88, 0x6b, 0x2b, 0x4e, 0x39,
      0xf5, 0x80, 0x39, 0xca, 0x76, 0x95, 0xbc, 0x7c, 0x27, 0x1d, 0xdd, 0x3a, 0x11,
      0xf1, 0x3e, 0x54, 0x03, 0xb7, 0x43, 0x91, 0x99, 0x33, 0xfe, 0x9d, 0x14, 0x2c,
      0x87, 0x9a, 0x95, 0x18, 0x1f, 0x02, 0x04, 0x6a, 0xe2, 0xb7, 0x81, 0x14, 0x13,
      0x45, 0x16, 0xfb, 0xe4, 0xb7, 0x8f, 0xab, 0x2b, 0xd7, 0x60, 0x34, 0x8a, 0x55,
      0xbc, 0x01, 0x8c, 0x49, 0x02, 0x29, 0xf1, 0x9c, 0x94, 0x98, 0x44, 0xd0, 0x94,
      0xcb, 0xd4, 0x85, 0x4c, 0x3b, 0x77, 0x72, 0x99, 0xd5, 0x4b, 0xc6, 0x3b, 0xe4,
      0xd2, 0xc8, 0xe9, 0x6a, 0x23, 0x18, 0x3b, 0x3b, 0x5e, 0x32, 0xec, 0x70, 0x84,
      0x5d, 0xbb, 0x6a, 0x8f, 0x0c, 0x5f, 0x55, 0xa5, 0x30, 0x34, 0x48, 0xbb, 0xc2,
      0xdf, 0x12, 0xb9, 0x81, 0xad, 0x36, 0x3f, 0xf0, 0x24, 0x16, 0x48, 0x04, 0x4a,
      0x7f, 0xfd, 0x9f, 0x4c, 0xea, 0xfe, 0x1d, 0x83, 0xd0, 0x81, 0xad, 0x25, 0x6c,
      0x5f, 0x45, 0x36, 0x91, 0xf0, 0xd5, 0x8b, 0x53, 0x0a, 0xdf, 0xec, 0x9f, 0x04,
      0x58, 0xc4, 0x35, 0xa0, 0x78, 0x1f, 0x68, 0xe0, 0x22}};

const TPM2B_RSA_TEST_VALUE c_RsapssKvt =
    {RSA_TEST_KEY_SIZE,
     {0x3f, 0x3a, 0x82, 0x6d, 0x42, 0xe3, 0x8b, 0x4f, 0x45, 0x9c, 0xda, 0x6c, 0xbe,
      0xbe, 0xcd, 0x00, 0x98, 0xfb, 0xbe, 0x59, 0x30, 0xc6, 0x3c, 0xaa, 0xb3, 0x06,
      0x27, 0xb5, 0xda, 0xfa, 0xb2, 0xc3, 0x43, 0xb7, 0xbd, 0xe9, 0xd3, 0x23, 0xed,
      0x80, 0xce, 0x74, 0xb3, 0xb8, 0x77, 0x8d, 0xe6, 0x8d, 0x3c, 0xe5, 0xf5, 0xd7,
      0x80, 0xcf, 0x38, 0x55, 0x76, 0xd7, 0x87, 0xa8, 0xd6, 0x3a, 0xcf, 0xfd, 0xd8,
      0x91, 0x65, 0xab, 0x43, 0x66, 0x50, 0xb7, 0x9a, 0x13, 0x6b, 0x45, 0x80, 0x76,
      0x86, 0x22, 0x27, 0x72, 0xf7, 0xbb, 0x65, 0x22, 0x5c, 0x55, 0x60, 0xd8, 0x84,
      0x9f, 0xf2, 0x61, 0x52, 0xac, 0xf2, 0x4f, 0x5b, 0x7b, 0x21, 0xe1, 0xf5, 0x4b,
      0x8f, 0x01, 0xf2, 0x4b, 0xcf, 0xd3, 0xfb, 0x74, 0x5e, 0x6e, 0x96, 0xb4, 0xa8,
      0x0f, 0x01, 0x9b, 0x26, 0x54, 0x0a, 0x70, 0x55, 0x26, 0xb7, 0x0b, 0xe8, 0x01,
      0x68, 0x66, 0x0d, 0x6f, 0xb5, 0xfc, 0x66, 0xbd, 0x9e, 0x44, 0xed, 0x6a, 0x1e,
      0x3c, 0x3b, 0x61, 0x5d, 0xe8, 0xdb, 0x99, 0x5b, 0x67, 0xbf, 0x94, 0xfb, 0xe6,
      0x8c, 0x4b, 0x07, 0xcb, 0x43, 0x3a, 0x0d, 0xb1, 0x1b, 0x10, 0x66, 0x81, 0xe2,
      0x0d, 0xe7, 0xd1, 0xca, 0x85, 0xa7, 0x50, 0x82, 0x2d, 0xbf, 0xed, 0xcf, 0x43,
      0x6d, 0xdb, 0x2c, 0x7b, 0x73, 0x20, 0xfe, 0x73, 0x3f, 0x19, 0xc6, 0xdb, 0x69,
      0xb8, 0xc3, 0xd3, 0xf4, 0xe5, 0x64, 0xf8, 0x36, 0x8e, 0xd5, 0xd8, 0x09, 0x2a,
      0x5f, 0x26, 0x70, 0xa1, 0xd9, 0x5b, 0x14, 0xf8, 0x22, 0xe9, 0x9d, 0x22, 0x51,
      0xf4, 0x52, 0xc1, 0x6f, 0x53, 0xf5, 0xca, 0x0d, 0xda, 0x39, 0x8c, 0x29, 0x42,
      0xe8, 0x58, 0x89, 0xbb, 0xd1, 0x2e, 0xc5, 0xdb, 0x86, 0x8d, 0xaf, 0xec, 0x58,
      0x36, 0x8d, 0x8d, 0x57, 0x23, 0xd5, 0xdd, 0xb9, 0x24}};

const TPM2B_RSA_TEST_VALUE c_RsassaKvt =
    {RSA_TEST_KEY_SIZE,
     {0x39, 0x10, 0x58, 0x7d, 0x6d, 0xa8, 0xd5, 0x90, 0x07, 0xd6, 0x2b, 0x13, 0xe9,
      0xd8, 0x93, 0x7e, 0xf3, 0x5d, 0x71, 0xe0, 0xf0, 0x33, 0x3a, 0x4a, 0x22, 0xf3,
      0xe6, 0x95, 0xd3, 0x8e, 0x8c, 0x41, 0xe7, 0xb3, 0x13, 0xde, 0x4a, 0x45, 0xd3,
      0xd1, 0xfb, 0xb1, 0x3f, 0x9b, 0x39, 0xa5, 0x50, 0x58, 0xef, 0xb6, 0x3a, 0x43,
      0xdd, 0x54, 0xab, 0xda, 0x9d, 0x32, 0x49, 0xe4, 0x57, 0x96, 0xe5, 0x1b, 0x1d,
      0x8f, 0x33, 0x8e, 0x07, 0x67, 0x56, 0x14, 0xc1, 0x18, 0x78, 0xa2, 0x52, 0xe6,
      0x2e, 0x07, 0x81, 0xbe, 0xd8, 0xca, 0x76, 0x63, 0x68, 0xc5, 0x47, 0xa2, 0x92,
      0x5e, 0x4c, 0xfd, 0x14, 0xc7, 0x46, 0x14, 0xbe, 0xc7, 0x85, 0xef, 0xe6, 0xb8,
      0x46, 0xcb, 0x3a, 0x67, 0x66, 0x89, 0xc6, 0xee, 0x9d, 0x64, 0xf5, 0x0d, 0x09,
      0x80, 0x9a, 0x6f, 0x0e, 0xeb, 0xe4, 0xb9, 0xe9, 0xab, 0x90, 0x4f, 0xe7, 0x5a,
      0xc8, 0xca, 0xf6, 0x16, 0x0a, 0x82, 0xbd, 0xb7, 0x76, 0x59, 0x08, 0x2d, 0xd9,
      0x40, 0x5d, 0xaa, 0xa5, 0xef, 0xfb, 0xe3, 0x81, 0x2c, 0x2c, 0x5c, 0xa8, 0x16,
      0xbd, 0x63, 0x20, 0xc2, 0x4d, 0x3b, 0x51, 0xaa, 0x62, 0x1f, 0x06, 0xe5, 0xbb,
      0x78, 0x44, 0x04, 0x0c, 0x5c, 0xe1, 0x1b, 0x6b, 0x9d, 0x21, 0x10, 0xaf, 0x48,
      0x48, 0x98, 0x97, 0x77, 0xc2, 0x73, 0xb4, 0x98, 0x64, 0xcc, 0x94, 0x2c, 0x29,
      0x28, 0x45, 0x36, 0xd1, 0xc5, 0xd0, 0x2f, 0x97, 0x27, 0x92, 0x65, 0x22, 0xbb,
      0x63, 0x79, 0xea, 0xf5, 0xff, 0x77, 0x0f, 0x4b, 0x56, 0x8a, 0x9f, 0xad, 0x1a,
      0x97, 0x67, 0x39, 0x69, 0xb8, 0x4c, 0x6c, 0xc2, 0x56, 0xc5, 0x7a, 0xa8, 0x14,
      0x5a, 0x24, 0x7a, 0xa4, 0x6e, 0x55, 0xb2, 0x86, 0x1d, 0xf4, 0x62, 0x5a, 0x2d,
      0x87, 0x6d, 0xde, 0x99, 0x78, 0x2d, 0xef, 0xd7, 0xdc}};

#endif  // SHA384

#if ALG_SHA512_VALUE == DEFAULT_TEST_HASH

const TPM2B_RSA_TEST_VALUE c_OaepKvt =
    {RSA_TEST_KEY_SIZE,
     {0x48, 0x45, 0xa7, 0x70, 0xb2, 0x41, 0xb7, 0x48, 0x5e, 0x79, 0x8c, 0xdf, 0x1c,
      0xc6, 0x7e, 0xbb, 0x11, 0x80, 0x82, 0x52, 0xbf, 0x40, 0x3d, 0x90, 0x03, 0x6e,
      0x20, 0x3a, 0xb9, 0x65, 0xc8, 0x51, 0x4c, 0xbd, 0x9c, 0xa9, 0x43, 0x89, 0xd0,
      0x57, 0x0c, 0xa3, 0x69, 0x22, 0x7e, 0x82, 0x2a, 0x1c, 0x1d, 0x5a, 0x80, 0x84,
      0x81, 0xbb, 0x5e, 0x5e, 0xd0, 0xc1, 0x66, 0x9a, 0xac, 0x00, 0xba, 0x14, 0xa2,
      0xe9, 0xd0, 0x3a, 0x89, 0x5a, 0x63, 0xe2, 0xec, 0x92, 0x05, 0xf4, 0x47, 0x66,
      0x12, 0x7f, 0xdb, 0xa7, 0x3c, 0x5b, 0x67, 0xe1, 0x55, 0xca, 0x0a, 0x27, 0xbf,
      0x39, 0x89, 0x11, 0x05, 0xba, 0x9b, 0x5a, 0x9b, 0x65, 0x44, 0xad, 0x78, 0xcf,
      0x8f, 0x94, 0xf6, 0x9a, 0xb4, 0x52, 0x39, 0x0e, 0x00, 0xba, 0xbc, 0xe0, 0xbd,
      0x6f, 0x81, 0x2d, 0x76, 0x42, 0x66, 0x70, 0x07, 0x77, 0xbf, 0x09, 0x88, 0x2a,
      0x0c, 0xb1, 0x56, 0x3e, 0xee, 0xfd, 0xdc, 0xb6, 0x3c, 0x0d, 0xc5, 0xa4, 0x0d,
      0x10, 0x32, 0x80, 0x3e, 0x1e, 0xfe, 0x36, 0x8f, 0xb5, 0x42, 0xc1, 0x21, 0x7b,
      0xdf, 0xdf, 0x4a, 0xd2, 0x68, 0x0c, 0x01, 0x9f, 0x4a, 0xfd, 0xd4, 0xec, 0xf7,
      0x49, 0x06, 0xab, 0xed, 0xc6, 0xd5, 0x1b, 0x63, 0x76, 0x38, 0xc8, 0x6c, 0xc7,
      0x4f, 0xcb, 0x29, 0x8a, 0x0e, 0x6f, 0x33, 0xaf, 0x69, 0x31, 0x8e, 0xa7, 0xdd,
      0x9a, 0x36, 0xde, 0x9b, 0xf1, 0x0b, 0xfb, 0x20, 0xa0, 0x6d, 0x33, 0x31, 0xc9,
      0x9e, 0xb4, 0x2e, 0xc5, 0x40, 0x0e, 0x60, 0x71, 0x36, 0x75, 0x05, 0xf9, 0x37,
      0xe0, 0xca, 0x8e, 0x8f, 0x56, 0xe0, 0xea, 0x9b, 0xeb, 0x17, 0xf3, 0xca, 0x40,
      0xc3, 0x48, 0x01, 0xba, 0xdc, 0xc6, 0x4b, 0x2b, 0x5b, 0x7b, 0x5c, 0x81, 0xa6,
      0xbb, 0xc7, 0x43, 0xc0, 0xbe, 0xc0, 0x30, 0x7b, 0x55}};

const TPM2B_RSA_TEST_VALUE c_RsaesKvt =
    {RSA_TEST_KEY_SIZE,
     {0x74, 0x83, 0xfa, 0x52, 0x65, 0x50, 0x68, 0xd0, 0x82, 0x05, 0x72, 0x70, 0x78,
      0x1c, 0xac, 0x10, 0x23, 0xc5, 0x07, 0xf8, 0x93, 0xd2, 0xeb, 0x65, 0x87, 0xbb,
      0x47, 0xc2, 0xfb, 0x30, 0x9e, 0x61, 0x4c, 0xac, 0x04, 0x57, 0x5a, 0x7c, 0xeb,
      0x29, 0x08, 0x84, 0x86, 0x89, 0x1e, 0x8f, 0x07, 0x32, 0xa3, 0x8b, 0x70, 0xe7,
      0xa2, 0x9f, 0x9c, 0x42, 0x71, 0x3d, 0x23, 0x59, 0x82, 0x5e, 0x8a, 0xde, 0xd6,
      0xfb, 0xd8, 0xc5, 0x8b, 0xc0, 0xdb, 0x10, 0x38, 0x87, 0xd3, 0xbf, 0x04, 0xb0,
      0x66, 0xb9, 0x85, 0x81, 0x54, 0x4c, 0x69, 0xdc, 0xba, 0x78, 0xf3, 0x4a, 0xdb,
      0x25, 0xa2, 0xf2, 0x34, 0x55, 0xdd, 0xaa, 0xa5, 0xc4, 0xed, 0x55, 0x06, 0x0e,
      0x2a, 0x30, 0x77, 0xab, 0x82, 0x79, 0xf0, 0xcd, 0x9d, 0x6f, 0x09, 0xa0, 0xc8,
      0x82, 0xc9, 0xe0, 0x61, 0xda, 0x40, 0xcd, 0x17, 0x59, 0xc0, 0xef, 0x95, 0x6d,
      0xa3, 0x6d, 0x1c, 0x2b, 0xee, 0x24, 0xef, 0xd8, 0x4a, 0x55, 0x6c, 0xd6, 0x26,
      0x42, 0x32, 0x17, 0xfd, 0x6a, 0xb3, 0x4f, 0xde, 0x07, 0x2f, 0x10, 0xd4, 0xac,
      0x14, 0xea, 0x89, 0x68, 0xcc, 0xd3, 0x07, 0xb7, 0xcf, 0xba, 0x39, 0x20, 0x63,
      0x20, 0x7b, 0x44, 0x8b, 0x48, 0x60, 0x5d, 0x3a, 0x2a, 0x0a, 0xe9, 0x68, 0xab,
      0x15, 0x46, 0x27, 0x64, 0xb5, 0x82, 0x06, 0x29, 0xe7, 0x25, 0xca, 0x46, 0x48,
      0x6e, 0x2a, 0x34, 0x57, 0x4b, 0x81, 0x75, 0xae, 0xb6, 0xfd, 0x6f, 0x51, 0x5f,
      0x04, 0x59, 0xc7, 0x15, 0x1f, 0xe0, 0x68, 0xf7, 0x36, 0x2d, 0xdf, 0xc8, 0x9d,
      0x05, 0x27, 0x2d, 0x3f, 0x2b, 0x59, 0x5d, 0xcb, 0xf3, 0xc4, 0x92, 0x6e, 0x00,
      0xa8, 0x8d, 0xd0, 0x69, 0xe5, 0x59, 0xda, 0xba, 0x4f, 0x38, 0xf5, 0xa0, 0x8b,
      0xf1, 0x73, 0xe9, 0x0d, 0xee, 0x64, 0xe5, 0xa2, 0xd8}};

const TPM2B_RSA_TEST_VALUE c_RsapssKvt =
    {RSA_TEST_KEY_SIZE,
     {0x1b, 0xca, 0x8b, 0x18, 0x15, 0x3b, 0x95, 0x5b, 0x0a, 0x89, 0x10, 0x03, 0x7f,
      0x7c, 0xa0, 0xc9, 0x66, 0x57, 0x86, 0x6a, 0xc9, 0xeb, 0x82, 0x71, 0xf3, 0x8d,
      0x6f, 0xa9, 0xa4, 0x2d, 0xd0, 0x22, 0xdf, 0xe9, 0xc6, 0x71, 0x5b, 0xf4, 0x27,
      0x38, 0x5b, 0x2c, 0x8a, 0x54, 0xcc, 0x85, 0x11, 0x69, 0x6d, 0x6f, 0x42, 0xe7,
      0x22, 0xcb, 0xd6, 0xad, 0x1a, 0xc5, 0xab, 0x6a, 0xa5, 0xfc, 0xa5, 0x70, 0x72,
      0x4a, 0x62, 0x25, 0xd0, 0xa2, 0x16, 0x61, 0xab, 0xac, 0x31, 0xa0, 0x46, 0x24,
      0x4f, 0xdd, 0x9a, 0x36, 0x55, 0xb6, 0x00, 0x9e, 0x23, 0x50, 0x0d, 0x53, 0x01,
      0xb3, 0x46, 0x56, 0xb2, 0x1d, 0x33, 0x5b, 0xca, 0x41, 0x7f, 0x65, 0x7e, 0x00,
      0x5c, 0x12, 0xff, 0x0a, 0x70, 0x5d, 0x8c, 0x69, 0x4a, 0x02, 0xee, 0x72, 0x30,
      0xa7, 0x5c, 0xa4, 0xbb, 0xbe, 0x03, 0x0c, 0xe4, 0x5f, 0x33, 0xb6, 0x78, 0x91,
      0x9d, 0xd8, 0xec, 0x34, 0x03, 0x2e, 0x63, 0x32, 0xc7, 0x2a, 0x36, 0x50, 0xd5,
      0x8b, 0x0e, 0x7f, 0x54, 0x4e, 0xf4, 0x29, 0x11, 0x1b, 0xcd, 0x0f, 0x37, 0xa5,
      0xbc, 0x61, 0x83, 0x50, 0xfa, 0x18, 0x75, 0xd9, 0xfe, 0xa7, 0xe8, 0x9b, 0xc1,
      0x4f, 0x96, 0x37, 0x81, 0x71, 0xdf, 0x71, 0x8b, 0x89, 0x81, 0xf4, 0x95, 0xb5,
      0x29, 0x66, 0x41, 0x0c, 0x73, 0xd7, 0x0b, 0x21, 0xb4, 0xfb, 0xf9, 0x63, 0x2f,
      0xe9, 0x7b, 0x38, 0xaa, 0x20, 0xc3, 0x96, 0xcc, 0xb7, 0xb2, 0x24, 0xa1, 0xe0,
      0x59, 0x9c, 0x10, 0x9e, 0x5a, 0xf7, 0xe3, 0x02, 0xe6, 0x23, 0xe2, 0x44, 0x21,
      0x3f, 0x6e, 0x5e, 0x79, 0xb2, 0x93, 0x7d, 0xce, 0xed, 0xe2, 0xe1, 0xab, 0x98,
      0x07, 0xa7, 0xbd, 0xbc, 0xd8, 0xf7, 0x06, 0xeb, 0xc5, 0xa6, 0x37, 0x18, 0x11,
      0x88, 0xf7, 0x63, 0x39, 0xb9, 0x57, 0x29, 0xdc, 0x03}};

const TPM2B_RSA_TEST_VALUE c_RsassaKvt =
    {RSA_TEST_KEY_SIZE,
     {0x05, 0x55, 0x00, 0x62, 0x01, 0xc6, 0x04, 0x31, 0x55, 0x73, 0x3f, 0x2a, 0xf9,
      0xd4, 0x0f, 0xc1, 0x2b, 0xeb, 0xd8, 0xc8, 0xdb, 0xb2, 0xab, 0x6c, 0x26, 0xde,
      0x2d, 0x89, 0xc2, 0x2d, 0x36, 0x62, 0xc8, 0x22, 0x5d, 0x58, 0x03, 0xb1, 0x46,
      0x14, 0xa5, 0xd4, 0xbc, 0x25, 0x6b, 0x7f, 0x8f, 0x14, 0x7e, 0x03, 0x2f, 0x3d,
      0xb8, 0x39, 0xa5, 0x79, 0x13, 0x7e, 0x22, 0x2a, 0xb9, 0x3e, 0x8f, 0xaa, 0x01,
      0x7c, 0x03, 0x12, 0x21, 0x6c, 0x2a, 0xb4, 0x39, 0x98, 0x6d, 0xff, 0x08, 0x6c,
      0x59, 0x2d, 0xdc, 0xc6, 0xf1, 0x77, 0x62, 0x10, 0xa6, 0xcc, 0xe2, 0x71, 0x8e,
      0x97, 0x00, 0x87, 0x5b, 0x0e, 0x20, 0x00, 0x3f, 0x18, 0x63, 0x83, 0xf0, 0xe4,
      0x0a, 0x64, 0x8c, 0xe9, 0x8c, 0x91, 0xe7, 0x89, 0x04, 0x64, 0x2c, 0x8b, 0x41,
      0xc8, 0xac, 0xf6, 0x5a, 0x75, 0xe6, 0xa5, 0x76, 0x43, 0xcb, 0xa5, 0x33, 0x8b,
      0x07, 0xc9, 0x73, 0x0f, 0x45, 0xa4, 0xc3, 0xac, 0xc1, 0xc3, 0xe6, 0xe7, 0x21,
      0x66, 0x1c, 0xba, 0xbf, 0xea, 0x3e, 0x39, 0xfa, 0xb2, 0xe2, 0x8f, 0xfe, 0x9c,
      0xb4, 0x85, 0x89, 0x33, 0x2a, 0x0c, 0xc8, 0x5d, 0x58, 0xe1, 0x89, 0x12, 0xe9,
      0x4d, 0x42, 0xb3, 0x1f, 0x99, 0x0c, 0x3e, 0xd8, 0xb2, 0xeb, 0xf5, 0x88, 0xfb,
      0xe1, 0x4b, 0x8e, 0xdc, 0xd3, 0xa8, 0xda, 0xbe, 0x04, 0x45, 0xbf, 0x56, 0xc6,
      0x54, 0x70, 0x00, 0xb8, 0x66, 0x46, 0x3a, 0xa3, 0x1e, 0xb6, 0xeb, 0x1a, 0xa0,
      0x0b, 0xd3, 0x9a, 0x9a, 0x52, 0xda, 0x60, 0x69, 0xb7, 0xef, 0x93, 0x47, 0x38,
      0xab, 0x1a, 0xa0, 0x22, 0x6e, 0x76, 0x06, 0xb6, 0x74, 0xaf, 0x74, 0x8f, 0x51,
      0xc0, 0x89, 0x5a, 0x4b, 0xbe, 0x6a, 0x91, 0x18, 0x25, 0x7d, 0xa6, 0x77, 0xe6,
      0xfd, 0xc2, 0x62, 0x36, 0x07, 0xc6, 0xef, 0x79, 0xc9}};

#endif  // SHA512
