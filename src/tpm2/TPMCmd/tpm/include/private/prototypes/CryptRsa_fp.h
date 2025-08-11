/********************************************************************************/
/*										*/
/*		Implementation of cryptographic primitives for RSA		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2023				*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Apr  2, 2019  Time: 03:18:00PM
 */

#ifndef _CRYPT_RSA_FP_H_
#define _CRYPT_RSA_FP_H_

#if ALG_RSA

//*** CryptRsaInit()
// Function called at _TPM_Init().
BOOL CryptRsaInit(void);

//*** CryptRsaStartup()
// Function called at TPM2_Startup()
BOOL CryptRsaStartup(void);

//*** CryptRsaPssSaltSize()
// This function computes the salt size used in PSS. It is broken out so that
// the X509 code can get the same value that is used by the encoding function in this
// module.
INT16
CryptRsaPssSaltSize(INT16 hashSize, INT16 outSize);

//*** MakeDerTag()
// Construct the DER value that is used in RSASSA
//  Return Type: INT16
//   > 0        size of value
//   <= 0       no hash exists
INT16
MakeDerTag(TPM_ALG_ID hashAlg, INT16 sizeOfBuffer, BYTE* buffer);

//*** CryptRsaSelectScheme()
// This function is used by TPM2_RSA_Decrypt and TPM2_RSA_Encrypt.  It sets up
// the rules to select a scheme between input and object default.
// This function assume the RSA object is loaded.
// If a default scheme is defined in object, the default scheme should be chosen,
// otherwise, the input scheme should be chosen.
// In the case that both the object and 'scheme' are not TPM_ALG_NULL, then
// if the schemes are the same, the input scheme will be chosen.
// if the scheme are not compatible, a NULL pointer will be returned.
//
// The return pointer may point to a TPM_ALG_NULL scheme.
TPMT_RSA_DECRYPT* CryptRsaSelectScheme(
    TPMI_DH_OBJECT    rsaHandle,  // IN: handle of an RSA key
    TPMT_RSA_DECRYPT* scheme      // IN: a sign or decrypt scheme
);

//*** CryptRsaLoadPrivateExponent()
// This function is called to generate the private exponent of an RSA key.
//  Return Type: TPM_RC
//      TPM_RC_BINDING      public and private parts of 'rsaKey' are not matched
TPM_RC
CryptRsaLoadPrivateExponent(TPMT_PUBLIC* publicArea, TPMT_SENSITIVE* sensitive,
    OBJECT                  *rsaKey						// libtpms added
);

//*** CryptRsaEncrypt()
// This is the entry point for encryption using RSA. Encryption is
// use of the public exponent. The padding parameter determines what
// padding will be used.
//
// The 'cOutSize' parameter must be at least as large as the size of the key.
//
// If the padding is RSA_PAD_NONE, 'dIn' is treated as a number. It must be
// lower in value than the key modulus.
// NOTE: If dIn has fewer bytes than cOut, then we don't add low-order zeros to
//       dIn to make it the size of the RSA key for the call to RSAEP. This is
//       because the high order bytes of dIn might have a numeric value that is
//       greater than the value of the key modulus. If this had low-order zeros
//       added, it would have a numeric value larger than the modulus even though
//       it started out with a lower numeric value.
//
//  Return Type: TPM_RC
//      TPM_RC_VALUE     'cOutSize' is too small (must be the size
//                        of the modulus)
//      TPM_RC_SCHEME    'padType' is not a supported scheme
//
LIB_EXPORT TPM_RC CryptRsaEncrypt(
    TPM2B_PUBLIC_KEY_RSA* cOut,    // OUT: the encrypted data
    TPM2B*                dIn,     // IN: the data to encrypt
    OBJECT*               key,     // IN: the key used for encryption
    TPMT_RSA_DECRYPT*     scheme,  // IN: the type of padding and hash
                                   //     if needed
    const TPM2B* label,            // IN: in case it is needed
    RAND_STATE*  rand              // IN: random number generator
                                   //     state (mostly for testing)
);

//*** CryptRsaDecrypt()
// This is the entry point for decryption using RSA. Decryption is
// use of the private exponent. The 'padType' parameter determines what
// padding was used.
//
//  Return Type: TPM_RC
//      TPM_RC_SIZE        'cInSize' is not the same as the size of the public
//                          modulus of 'key'; or numeric value of the encrypted
//                          data is greater than the modulus
//      TPM_RC_VALUE       'dOutSize' is not large enough for the result
//      TPM_RC_SCHEME      'padType' is not supported
//
LIB_EXPORT TPM_RC CryptRsaDecrypt(
    TPM2B*            dOut,    // OUT: the decrypted data
    TPM2B*            cIn,     // IN: the data to decrypt
    OBJECT*           key,     // IN: the key to use for decryption
    TPMT_RSA_DECRYPT* scheme,  // IN: the padding scheme
    const TPM2B*      label    // IN: in case it is needed for the scheme
);

//*** CryptRsaSign()
// This function is used to generate an RSA signature of the type indicated in
// 'scheme'.
//
//  Return Type: TPM_RC
//      TPM_RC_SCHEME       'scheme' or 'hashAlg' are not supported
//      TPM_RC_VALUE        'hInSize' does not match 'hashAlg' (for RSASSA)
//
LIB_EXPORT TPM_RC CryptRsaSign(TPMT_SIGNATURE* sigOut,
                               OBJECT*         key,  // IN: key to use
                               TPM2B_DIGEST*   hIn,  // IN: the digest to sign
                               RAND_STATE* rand  // IN: the random number generator
                                                 //      to use (mostly for testing)
);

//*** CryptRsaValidateSignature()
// This function is used to validate an RSA signature. If the signature is valid
// TPM_RC_SUCCESS is returned. If the signature is not valid, TPM_RC_SIGNATURE is
// returned. Other return codes indicate either parameter problems or fatal errors.
//
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE    the signature does not check
//      TPM_RC_SCHEME       unsupported scheme or hash algorithm
//
LIB_EXPORT TPM_RC CryptRsaValidateSignature(
    TPMT_SIGNATURE* sig,    // IN: signature
    OBJECT*         key,    // IN: public modulus
    TPM2B_DIGEST*   digest  // IN: The digest being validated
);

//*** CryptRsaGenerateKey()
// Generate an RSA key from a provided seed
//  Return Type: TPM_RC
//      TPM_RC_CANCELED     operation was canceled
//      TPM_RC_RANGE        public exponent is not supported
//      TPM_RC_VALUE        could not find a prime using the provided parameters
LIB_EXPORT TPM_RC CryptRsaGenerateKey(
    TPMT_PUBLIC*    publicArea,
    TPMT_SENSITIVE* sensitive,
     OBJECT*        rsaKey,		// libtpms added: IN/OUT: The object structure in which the key is created.
    RAND_STATE*     rand  // IN: if not NULL, the deterministic
                          //     RNG state
);
#endif  // ALG_RSA

#endif  // _CRYPT_RSA_FP_H_
