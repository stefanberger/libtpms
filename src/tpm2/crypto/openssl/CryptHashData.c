/********************************************************************************/
/*										*/
/*			Hash ALgorithm Constants     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CryptHashData.c 1370 2018-11-02 19:39:07Z kgoldman $		*/
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
/*  (c) Copyright IBM Corp. and others, 2018					*/
/*										*/
/********************************************************************************/

/* 10.2.15 CryptHashData.c */
#include "Tpm.h"
#define  SHA1_DER_SIZE       15
#define  SHA1_DER					\
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,	\
	0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14
#define  SHA256_DER_SIZE       19
#define  SHA256_DER					\
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,	\
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,	\
	0x00, 0x04, 0x20
#define  SHA384_DER_SIZE       19
#define  SHA384_DER					\
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,	\
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,	\
	0x00, 0x04, 0x30
#define  SHA512_DER_SIZE       19
#define  SHA512_DER					\
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,	\
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,	\
	0x00, 0x04, 0x40

const HASH_INFO   g_hashData[HASH_COUNT + 1] = {
#if ALG_SHA1
    {TPM_ALG_SHA1,    SHA1_DIGEST_SIZE,   SHA1_BLOCK_SIZE,
     SHA1_DER_SIZE,   {SHA1_DER}},
#endif
#if ALG_SHA256
    {TPM_ALG_SHA256,    SHA256_DIGEST_SIZE,   SHA256_BLOCK_SIZE,
     SHA256_DER_SIZE,   {SHA256_DER}},
#endif
#if ALG_SHA384
    {TPM_ALG_SHA384,    SHA384_DIGEST_SIZE,   SHA384_BLOCK_SIZE,
     SHA384_DER_SIZE,   {SHA384_DER}},
#endif
#if ALG_SHA512
    {TPM_ALG_SHA512,    SHA512_DIGEST_SIZE,   SHA512_BLOCK_SIZE,
     SHA512_DER_SIZE,   {SHA512_DER}},
#endif
#if ALG_SM3_256
    {TPM_ALG_SM3_256,    SM3_256_DIGEST_SIZE,   SM3_256_BLOCK_SIZE,
     SM3_256_DER_SIZE,   {SM3_256_DER}},
#endif
    {TPM_ALG_NULL,0,0,0,{0}}
};
