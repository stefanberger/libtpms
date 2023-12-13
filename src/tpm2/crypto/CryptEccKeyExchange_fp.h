/********************************************************************************/
/*										*/
/*			     							*/
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
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _CRYPT_ECC_KEY_EXCHANGE_FP_H_
#define _CRYPT_ECC_KEY_EXCHANGE_FP_H_

#if CC_ZGen_2Phase == YES

//*** CryptEcc2PhaseKeyExchange()
// This function is the dispatch routine for the EC key exchange functions that use
// two ephemeral and two static keys.
//  Return Type: TPM_RC
//      TPM_RC_SCHEME             scheme is not defined
LIB_EXPORT TPM_RC CryptEcc2PhaseKeyExchange(
					    TPMS_ECC_POINT*      outZ1,    // OUT: a computed point
					    TPMS_ECC_POINT*      outZ2,    // OUT: and optional second point
					    TPM_ECC_CURVE        curveId,  // IN: the curve for the computations
					    TPM_ALG_ID           scheme,   // IN: the key exchange scheme
					    TPM2B_ECC_PARAMETER* dsA,      // IN: static private TPM key
					    TPM2B_ECC_PARAMETER* deA,      // IN: ephemeral private TPM key
					    TPMS_ECC_POINT*      QsB,      // IN: static public party B key
					    TPMS_ECC_POINT*      QeB       // IN: ephemeral public party B key
					    );
#  if ALG_SM2

//*** SM2KeyExchange()
// This function performs the key exchange defined in SM2.
// The first step is to compute
//  'tA' = ('dsA' + 'deA'  avf(Xe,A)) mod 'n'
// Then, compute the 'Z' value from
// 'outZ' = ('h'  'tA' mod 'n') ('QsA' + [avf('QeB.x')]('QeB')).
// The function will compute the ephemeral public key from the ephemeral
// private key.
// All points are required to be on the curve of 'inQsA'. The function will fail
// catastrophically if this is not the case
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        the value for dsA does not give a valid point on the
//                              curve
LIB_EXPORT TPM_RC SM2KeyExchange(
				 TPMS_ECC_POINT*      outZ,     // OUT: the computed point
				 TPM_ECC_CURVE        curveId,  // IN: the curve for the computations
				 TPM2B_ECC_PARAMETER* dsAIn,    // IN: static private TPM key
				 TPM2B_ECC_PARAMETER* deAIn,    // IN: ephemeral private TPM key
				 TPMS_ECC_POINT*      QsBIn,    // IN: static public party B key
				 TPMS_ECC_POINT*      QeBIn     // IN: ephemeral public party B key
				 );
#  endif
#endif  // CC_ZGen_2Phase

#endif  // _CRYPT_ECC_KEY_EXCHANGE_FP_H_
