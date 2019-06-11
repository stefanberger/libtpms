/********************************************************************************/
/*										*/
/*			 Vector for testing Either Encrypt or Decrypt    	*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: SymmetricTestData.h 1476 2019-06-10 19:32:03Z kgoldman $	*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2019				*/
/*										*/
/********************************************************************************/

#ifndef SYMMETRICTESTDATA_H
#define SYMMETRICTESTDATA_H

/* 10.1.10 SymmetricTestData.h */
/* This is a vector for testing either encrypt or decrypt. The premise for decrypt is that the IV
   for decryption is the same as the IV for encryption. However, the ivOut value may be different
   for encryption and decryption. We will encrypt at least two blocks. This means that the chaining
   value will be used for each of the schemes (if any) and that implicitly checks that the chaining
   value is handled properly. */
#if AES_128
const BYTE  key_AES128 [] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
const BYTE  dataIn_AES128 [] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
const BYTE  dataOut_AES128_ECB [] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
    0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
    0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf};
const BYTE  dataOut_AES128_CBC [] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
    0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2};
const BYTE  dataOut_AES128_CFB [] = {
    0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
    0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
    0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f,
    0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b};
const BYTE  dataOut_AES128_OFB [] = {
    0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
    0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
    0x77, 0x89, 0x50, 0x8d, 0x16, 0x91, 0x8f, 0x03,
    0xf5, 0x3c, 0x52, 0xda, 0xc5, 0x4e, 0xd8, 0x25};
const BYTE  dataOut_AES128_CTR [] = {
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
    0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
    0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
    0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff};
#endif
#if AES_192
const BYTE  key_AES192 [] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
const BYTE  dataIn_AES192 [] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
const BYTE  dataOut_AES192_ECB [] = {
    0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
    0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
    0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad,
    0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef};
const BYTE  dataOut_AES192_CBC [] = {
    0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
    0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
    0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
    0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a};
const BYTE  dataOut_AES192_CFB [] = {
    0xcd, 0xc8, 0x0d, 0x6f, 0xdd, 0xf1, 0x8c, 0xab,
    0x34, 0xc2, 0x59, 0x09, 0xc9, 0x9a, 0x41, 0x74,
    0x67, 0xce, 0x7f, 0x7f, 0x81, 0x17, 0x36, 0x21,
    0x96, 0x1a, 0x2b, 0x70, 0x17, 0x1d, 0x3d, 0x7a};
const BYTE  dataOut_AES192_OFB [] = {
    0xcd, 0xc8, 0x0d, 0x6f, 0xdd, 0xf1, 0x8c, 0xab,
    0x34, 0xc2, 0x59, 0x09, 0xc9, 0x9a, 0x41, 0x74,
    0xfc, 0xc2, 0x8b, 0x8d, 0x4c, 0x63, 0x83, 0x7c,
    0x09, 0xe8, 0x17, 0x00, 0xc1, 0x10, 0x04, 0x01};
const BYTE  dataOut_AES192_CTR [] = {
    0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2,
    0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b,
    0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6, 0xfa, 0xef,
    0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94};
#endif
#if AES_256
const BYTE  key_AES256 [] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
const BYTE  dataIn_AES256 [] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
const BYTE  dataOut_AES256_ECB [] = {
    0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
    0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
    0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
    0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70};
const BYTE  dataOut_AES256_CBC [] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
    0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
    0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d};
const BYTE  dataOut_AES256_CFB [] = {
    0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b,
    0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
    0x39, 0xff, 0xed, 0x14, 0x3b, 0x28, 0xb1, 0xc8,
    0x32, 0x11, 0x3c, 0x63, 0x31, 0xe5, 0x40, 0x7b};
const BYTE  dataOut_AES256_OFB [] = {
    0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b,
    0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
    0x4f, 0xeb, 0xdc, 0x67, 0x40, 0xd2, 0x0b, 0x3a,
    0xc8, 0x8f, 0x6a, 0xd8, 0x2a, 0x4f, 0xb0, 0x8d};
const BYTE  dataOut_AES256_CTR [] = {
    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
    0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
    0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
    0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5};
#endif
// libtpms added begin
#if TDES_128
const BYTE  key_TDES128 [] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
const BYTE  dataIn_TDES128 [] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
const BYTE  dataOut_TDES128_ECB [] = {
    0xdf, 0x8f, 0x88, 0x43, 0x2f, 0xea, 0x61, 0x0c,
    0xc1, 0xfa, 0xaf, 0x1a, 0xb1, 0xc0, 0xc0, 0x37,
    0x27, 0xf2, 0xe0, 0x8e, 0xda, 0x14, 0xbe, 0x79,
    0x91, 0x95, 0xd2, 0x61, 0x2b, 0x46, 0x49, 0x4e,
    0x1b, 0x10, 0xa6, 0xcc, 0x02, 0xb6, 0x5a, 0x6c};
const BYTE  dataOut_TDES128_CBC [] = {
    0x0a, 0xdd, 0xd5, 0x8a, 0x85, 0x33, 0xda, 0x86,
    0x68, 0x8f, 0xb9, 0x05, 0xe3, 0x32, 0xe1, 0x58,
    0x82, 0x33, 0x72, 0x85, 0xbc, 0x64, 0xcd, 0xd2,
    0x25, 0xa2, 0x54, 0x5e, 0x22, 0xe0, 0xde, 0x92,
    0x80, 0x69, 0x5e, 0x61, 0x77, 0xb5, 0x94, 0x1b};
const BYTE  dataOut_TDES128_CFB [] = {
    0x9c, 0xe7, 0x8f, 0x92, 0x6d, 0x37, 0xe4, 0xaa,
    0x8e, 0x12, 0x14, 0xdc, 0xb7, 0x46, 0xc3, 0x6d,
    0x3f, 0x6f, 0x17, 0x5b, 0x97, 0x9d, 0x9e, 0x8a,
    0xb5, 0xc4, 0xcd, 0x2a, 0x7a, 0x3e, 0xad, 0xec};
const BYTE  dataOut_TDES128_OFB [] = {
    0x9c, 0xe7, 0x8f, 0x92, 0x6d, 0x37, 0xe4, 0xaa,
    0x1b, 0x85, 0x9f, 0x7f, 0x80, 0x56, 0x10, 0xbc,
    0xa4, 0xaa, 0x05, 0xd0, 0xd8, 0xf1, 0xda, 0x3e,
    0x74, 0x82, 0x69, 0xb2, 0x8f, 0xf1, 0x6d, 0xde};
const BYTE  dataOut_TDES128_CTR [] = {
    0x9e, 0xf8, 0x6f, 0x66, 0x5a, 0xa7, 0x9c, 0x91,
    0xe8, 0x07, 0xf9, 0x7a, 0x96, 0xf9, 0x6a, 0x87,
    0x19, 0x22, 0x3f, 0x9d, 0x9e, 0x92, 0xc4, 0x25,
    0x4a, 0x31, 0x6d, 0x3c, 0x35, 0xa6, 0x3a, 0x03};

const BYTE  dataInShort_TDES128 [] = {
    0x31, 0x32, 0x33, 0x34, 0x35};
// CBC and ECB need multiple of blocksize input
const BYTE  dataOutShort_TDES128_CFB[] = {
    0xc6, 0x14, 0x02, 0x44, 0x76};
const BYTE  dataOutShort_TDES128_OFB[] = {
    0xc6, 0x14, 0x02, 0x44, 0x76};
#endif
#if TDES_192
const BYTE  key_TDES192 [] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
const BYTE  dataIn_TDES192 [] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
const BYTE  dataOut_TDES192_ECB [] = {
    0x37, 0x62, 0x02, 0x5d, 0xad, 0x85, 0x03, 0xe9,
    0xff, 0x0f, 0xce, 0x66, 0x28, 0x74, 0x3f, 0x94,
    0x72, 0x42, 0xbb, 0xc5, 0x14, 0xae, 0xc6, 0x2f,
    0x61, 0xd1, 0x03, 0x9c, 0xd1, 0xf7, 0xf8, 0x29,
    0x62, 0x91, 0x03, 0x74, 0xe7, 0x05, 0xb3, 0xb6};
const BYTE  dataOut_TDES192_CBC [] = {
    0x6c, 0x30, 0xbb, 0x5e, 0xbc, 0x73, 0xb1, 0x2d,
    0x40, 0x24, 0x93, 0x65, 0xd8, 0x9a, 0x27, 0x4f,
    0xdd, 0x09, 0xfc, 0x95, 0x28, 0xa3, 0xd9, 0x46,
    0xf9, 0x15, 0x43, 0x52, 0x7a, 0x0d, 0xd6, 0x3e,
    0xd1, 0xb0, 0x10, 0x64, 0x63, 0x5e, 0xa0, 0xb5};
const BYTE  dataOut_TDES192_CFB [] = {
    0x89, 0x00, 0xbb, 0xec, 0x56, 0xdc, 0x77, 0x81,
    0x59, 0xdb, 0x1d, 0xa4, 0xe2, 0x33, 0x85, 0x2d,
    0xbf, 0xfb, 0xe3, 0xe2, 0xe0, 0x46, 0x91, 0x09,
    0x15, 0xcb, 0x41, 0x7c, 0xd5, 0x84, 0x60, 0xf1};
const BYTE  dataOut_TDES192_OFB [] = {
    0x89, 0x00, 0xbb, 0xec, 0x56, 0xdc, 0x77, 0x81,
    0xf0, 0x12, 0x4b, 0xe3, 0xc5, 0x83, 0x60, 0x45,
    0xda, 0x4d, 0xba, 0x05, 0x78, 0xa3, 0x77, 0xc8,
    0x21, 0x57, 0xcd, 0x62, 0xbb, 0x93, 0xc8, 0x4e};
const BYTE  dataOut_TDES192_CTR [] = {
    0x17, 0x4d, 0xdf, 0xde, 0x7b, 0xe0, 0x2f, 0xb7,
    0x58, 0x49, 0x76, 0xe5, 0x80, 0xbd, 0x49, 0x45,
    0x64, 0x3a, 0xe4, 0x42, 0xfe, 0x4c, 0x25, 0xd4,
    0x79, 0x74, 0xf0, 0xe6, 0x0b, 0x3d, 0x20, 0xac};

const BYTE  dataInShort_TDES192 [] = {
    0x31, 0x32, 0x33, 0x34, 0x35};
// CBC and ECB need multiple of blocksize input
const BYTE  dataOutShort_TDES192_CFB[] = {
    0xd3, 0xf3, 0x36, 0x3a, 0x4d};
const BYTE  dataOutShort_TDES192_OFB[] = {
    0xd3, 0xf3, 0x36, 0x3a, 0x4d};
#endif
// libtpms added end

#endif
