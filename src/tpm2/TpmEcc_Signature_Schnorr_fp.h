/********************************************************************************/
/*										*/
/*						*/
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
/*  (c) Copyright IBM Corp. and others, 2023				  	*/
/*										*/
/********************************************************************************/

#ifndef _TPMECC_SIGNATURE_SCHNORR_FP_H_
#define _TPMECC_SIGNATURE_SCHNORR_FP_H_

#if ALG_ECC && ALG_ECSCHNORR
TPM_RC TpmEcc_SignEcSchnorr(
			    Crypt_Int*            bnR,      // OUT: 'r' component of the signature
			    Crypt_Int*            bnS,      // OUT: 's' component of the signature
			    const Crypt_EccCurve* E,        // IN: the curve used in signing
			    Crypt_Int*            bnD,      // IN: the signing key
			    const TPM2B_DIGEST*   digest,   // IN: the digest to sign
			    TPM_ALG_ID            hashAlg,  // IN: signing scheme (contains a hash)
			    RAND_STATE*           rand      // IN: non-NULL when testing
			    );

//*** TpmEcc_ValidateSignatureEcSchnorr()
// This function is used to validate an EC Schnorr signature.
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE        signature not valid
TPM_RC TpmEcc_ValidateSignatureEcSchnorr(
					 Crypt_Int*            bnR,      // IN: 'r' component of the signature
					 Crypt_Int*            bnS,      // IN: 's' component of the signature
					 TPM_ALG_ID            hashAlg,  // IN: hash algorithm of the signature
					 const Crypt_EccCurve* E,        // IN: the curve used in the signature
					 //     process
					 Crypt_Point*        ecQ,        // IN: the public point of the key
					 const TPM2B_DIGEST* digest      // IN: the digest that was signed
					 );

#endif  // ALG_ECC && ALG_ECSCHNORR
#endif  // _TPMECC_SIGNATURE_SCHNORR_FP_H_
