/********************************************************************************/
/*										*/
/*			     				*/
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
/*  (c) Copyright IBM Corp. and others, 2016 -2023				*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _CRYPT_ECC_SIGNATURE_FP_H_
#define _CRYPT_ECC_SIGNATURE_FP_H_

#if ALG_ECC

//*** CryptEccSign()
// This function is the dispatch function for the various ECC-based
// signing schemes.
// There is a bit of ugliness to the parameter passing. In order to test this,
// we sometime would like to use a deterministic RNG so that we can get the same
// signatures during testing. The easiest way to do this for most schemes is to
// pass in a deterministic RNG and let it return canned values during testing.
// There is a competing need for a canned parameter to use in ECDAA. To accommodate
// both needs with minimal fuss, a special type of RAND_STATE is defined to carry
// the address of the commit value. The setup and handling of this is not very
// different for the caller than what was in previous versions of the code.
//  Return Type: TPM_RC
//      TPM_RC_SCHEME            'scheme' is not supported
LIB_EXPORT TPM_RC CryptEccSign(TPMT_SIGNATURE* signature,  // OUT: signature
			       OBJECT* signKey,  // IN: ECC key to sign the hash
			       const TPM2B_DIGEST* digest,  // IN: digest to sign
			       TPMT_ECC_SCHEME*    scheme,  // IN: signing scheme
			       RAND_STATE*         rand);

//*** CryptEccValidateSignature()
// This function validates an EcDsa or EcSchnorr signature.
// The point 'Qin' needs to have been validated to be on the curve of 'curveId'.
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE            not a valid signature
LIB_EXPORT TPM_RC CryptEccValidateSignature(
					    TPMT_SIGNATURE*     signature,  // IN: signature to be verified
					    OBJECT*             signKey,    // IN: ECC key signed the hash
					    const TPM2B_DIGEST* digest      // IN: digest that was signed
					    );

//***CryptEccCommitCompute()
// This function performs the point multiply operations required by TPM2_Commit.
//
// If 'B' or 'M' is provided, they must be on the curve defined by 'curveId'. This
// routine does not check that they are on the curve and results are unpredictable
// if they are not.
//
// It is a fatal error if 'r' is NULL. If 'B' is not NULL, then it is a
// fatal error if 'd' is NULL or if 'K' and 'L' are both NULL.
// If 'M' is not NULL, then it is a fatal error if 'E' is NULL.
//
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        if 'K', 'L' or 'E' was computed to be the point
//                              at infinity
//      TPM_RC_CANCELED         a cancel indication was asserted during this
//                              function
LIB_EXPORT TPM_RC CryptEccCommitCompute(
					TPMS_ECC_POINT*      K,        // OUT: [d]B or [r]Q
					TPMS_ECC_POINT*      L,        // OUT: [r]B
					TPMS_ECC_POINT*      E,        // OUT: [r]M
					TPM_ECC_CURVE        curveId,  // IN: the curve for the computations
					TPMS_ECC_POINT*      M,        // IN: M (optional)
					TPMS_ECC_POINT*      B,        // IN: B (optional)
					TPM2B_ECC_PARAMETER* d,        // IN: d (optional)
					TPM2B_ECC_PARAMETER* r         // IN: the computed r value (required)
					);
#endif  // ALG_ECC

#endif  // _CRYPT_ECC_SIGNATURE_FP_H_
