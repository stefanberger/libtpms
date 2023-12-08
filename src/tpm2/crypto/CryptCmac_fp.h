/********************************************************************************/
/*	Message Authentication Codes Based on a Symmetric Block Cipher		*/
/*		Implementation of cryptographic functions for hashing.		*/
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
/*  (c) Copyright IBM Corp. and others, 2018 - 2023				*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _CRYPT_CMAC_FP_H_
#define _CRYPT_CMAC_FP_H_

#if ALG_CMAC

//*** CryptCmacStart()
// This is the function to start the CMAC sequence operation. It initializes the
// dispatch functions for the data and end operations for CMAC and initializes the
// parameters that are used for the processing of data, including the key, key size
// and block cipher algorithm.
UINT16
CryptCmacStart(
	       SMAC_STATE* state, TPMU_PUBLIC_PARMS* keyParms, TPM_ALG_ID macAlg, TPM2B* key);

//*** CryptCmacData()
// This function is used to add data to the CMAC sequence computation. The function
// will XOR new data into the IV. If the buffer is full, and there is additional
// input data, the data is encrypted into the IV buffer, the new data is then
// XOR into the IV. When the data runs out, the function returns without encrypting
// even if the buffer is full. The last data block of a sequence will not be
// encrypted until the call to CryptCmacEnd(). This is to allow the proper subkey
// to be computed and applied before the last block is encrypted.
void CryptCmacData(SMAC_STATES* state, UINT32 size, const BYTE* buffer);

//*** CryptCmacEnd()
// This is the completion function for the CMAC. It does padding, if needed, and
// selects the subkey to be applied before the last block is encrypted.
UINT16
CryptCmacEnd(SMAC_STATES* state, UINT32 outSize, BYTE* outBuffer);
#endif

#endif  // _CRYPT_CMAC_FP_H_
