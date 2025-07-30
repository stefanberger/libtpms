/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CryptSym_fp.h 1047 2017-07-20 18:27:34Z kgoldman $		*/
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
/*  (c) Copyright IBM Corp. and others, 2016					*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Apr  2, 2019  Time: 03:18:00PM
 */

#ifndef _CRYPT_SYM_FP_H_
#define _CRYPT_SYM_FP_H_

//** Initialization and Data Access Functions
//
//*** CryptSymInit()
// This function is called to do _TPM_Init processing
BOOL CryptSymInit(void);

//*** CryptSymStartup()
// This function is called to do TPM2_Startup() processing
BOOL CryptSymStartup(void);

//*** CryptGetSymmetricBlockSize()
// This function returns the block size of the algorithm. The table of bit sizes has
// an entry for each allowed key size. The entry for a key size is 0 if the TPM does
// not implement that key size. The key size table is delimited with a negative number
// (-1). After the delimiter is a list of block sizes with each entry corresponding
// to the key bit size. For most symmetric algorithms, the block size is the same
// regardless of the key size but this arrangement allows them to be different.
//  Return Type: INT16
//   <= 0     cipher not supported
//   > 0      the cipher block size in bytes
LIB_EXPORT INT16 CryptGetSymmetricBlockSize(
    TPM_ALG_ID symmetricAlg,  // IN: the symmetric algorithm
    UINT16     keySizeInBits  // IN: the key size
);

//** Symmetric Encryption
// This function performs symmetric encryption based on the mode.
//  Return Type: TPM_RC
//      TPM_RC_SIZE         'dSize' is not a multiple of the block size for an
//                          algorithm that requires it
//      TPM_RC_FAILURE      Fatal error
LIB_EXPORT TPM_RC CryptSymmetricEncrypt(
    BYTE*       dOut,           // OUT:
    TPM_ALG_ID  algorithm,      // IN: the symmetric algorithm
    UINT16      keySizeInBits,  // IN: key size in bits
    const BYTE* key,            // IN: key buffer. The size of this buffer
                                //     in bytes is (keySizeInBits + 7) / 8
    TPM2B_IV*  ivInOut,         // IN/OUT: IV for decryption.
    TPM_ALG_ID mode,            // IN: Mode to use
    INT32      dSize,           // IN: data size (may need to be a
                                //     multiple of the blockSize)
    const BYTE* dIn             // IN: data buffer
);

//*** CryptSymmetricDecrypt()
// This function performs symmetric decryption based on the mode.
//  Return Type: TPM_RC
//      TPM_RC_FAILURE      A fatal error
//      TPM_RCS_SIZE        'dSize' is not a multiple of the block size for an
//                          algorithm that requires it
LIB_EXPORT TPM_RC CryptSymmetricDecrypt(
    BYTE*       dOut,           // OUT: decrypted data
    TPM_ALG_ID  algorithm,      // IN: the symmetric algorithm
    UINT16      keySizeInBits,  // IN: key size in bits
    const BYTE* key,            // IN: key buffer. The size of this buffer
                                //     in bytes is (keySizeInBits + 7) / 8
    TPM2B_IV*  ivInOut,         // IN/OUT: IV for decryption.
    TPM_ALG_ID mode,            // IN: Mode to use
    INT32      dSize,           // IN: data size (may need to be a
                                //     multiple of the blockSize)
    const BYTE* dIn             // IN: data buffer
);

//*** CryptSymKeyValidate()
// Validate that a provided symmetric key meets the requirements of the TPM
//  Return Type: TPM_RC
//      TPM_RC_KEY_SIZE         Key size specifiers do not match
//      TPM_RC_KEY              Key is not allowed
TPM_RC
CryptSymKeyValidate(TPMT_SYM_DEF_OBJECT* symDef, TPM2B_SYM_KEY* key);

#endif  // _CRYPT_SYM_FP_H_
