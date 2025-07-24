/********************************************************************************/
/*										*/
/*			Include Headers for Internal Routines			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CryptEccCrypt_fp.h 1594 2020-03-26 22:15:48Z kgoldman $	*/
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
/*  (c) Copyright IBM Corp. and others, 2020 - 2022				*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Feb 28, 2020  Time: 03:04:48PM
 */

#ifndef _CRYPT_ECC_CRYPT_FP_H_
#define _CRYPT_ECC_CRYPT_FP_H_

#if CC_ECC_Encrypt || CC_ECC_Encrypt

//*** CryptEccSelectScheme()
// This function is used by TPM2_ECC_Decrypt and TPM2_ECC_Encrypt.  It sets scheme
// either the input scheme or the key scheme. If they key scheme is not TPM_ALG_NULL
// then the input scheme must be TPM_ALG_NULL or the same as the key scheme. If
// not, then the function returns FALSE.
//  Return Type: BOOL
//      TRUE        'scheme' is set
//      FALSE       'scheme' is not valid (it may have been changed).
BOOL CryptEccSelectScheme(OBJECT*          key,    //IN: key containing default scheme
                          TPMT_KDF_SCHEME* scheme  // IN: a decrypt scheme
);

//*** CryptEccEncrypt()
//This function performs ECC-based data obfuscation. The only scheme that is currently
// supported is MGF1 based. See Part 1, Annex D for details.
//  Return Type: TPM_RC
//      TPM_RC_CURVE            unsupported curve
//      TPM_RC_HASH             hash not allowed
//      TPM_RC_SCHEME           'scheme' is not supported
//      TPM_RC_NO_RESULT        internal error in big number processing
LIB_EXPORT TPM_RC CryptEccEncrypt(
    OBJECT*           key,        // IN: public key of recipient
    TPMT_KDF_SCHEME*  scheme,     // IN: scheme to use.
    TPM2B_MAX_BUFFER* plainText,  // IN: the text to obfuscate
    TPMS_ECC_POINT*   c1,         // OUT: public ephemeral key
    TPM2B_MAX_BUFFER* c2,         // OUT: obfuscated text
    TPM2B_DIGEST*     c3          // OUT: digest of ephemeral key
                                  //      and plainText
);

//*** CryptEccDecrypt()
// This function performs ECC decryption and integrity check of the input data.
//  Return Type: TPM_RC
//      TPM_RC_CURVE            unsupported curve
//      TPM_RC_HASH             hash not allowed
//      TPM_RC_SCHEME           'scheme' is not supported
//      TPM_RC_NO_RESULT        internal error in big number processing
//      TPM_RC_VALUE            C3 did not match hash of recovered data
LIB_EXPORT TPM_RC CryptEccDecrypt(
    OBJECT*           key,        // IN: key used for data recovery
    TPMT_KDF_SCHEME*  scheme,     // IN: scheme to use.
    TPM2B_MAX_BUFFER* plainText,  // OUT: the recovered text
    TPMS_ECC_POINT*   c1,         // IN: public ephemeral key
    TPM2B_MAX_BUFFER* c2,         // IN: obfuscated text
    TPM2B_DIGEST*     c3          // IN: digest of ephemeral key
                                  //      and plainText
);
#endif  // CC_ECC_Encrypt || CC_ECC_Encrypt

#endif  // _CRYPT_ECC_CRYPT_FP_H_
