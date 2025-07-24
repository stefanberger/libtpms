/********************************************************************************/
/*										*/
/*			ECC curve data 						*/
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
 *  Created by TpmStructures; Version 4.4 Mar 26, 2019
 *  Date: Aug 30, 2019  Time: 02:11:52PM
 */

#include "Tpm.h"
#include "OIDs.h"

#if ALG_ECC

// This file contains the TPM Specific ECC curve metadata and pointers to the ecc-lib specific
// constant structure.
// The CURVE_NAME macro is used to remove the name string from normal builds, but leaves the
// string available in the initialization lists for potenial use during debugging by changing this
// macro (and the structure declaration)
#  define CURVE_NAME(N)

#  define comma
const TPM_ECC_CURVE_METADATA eccCurves[] = {
#  if ECC_NIST_P192
    comma{TPM_ECC_NIST_P192,
          192,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SHA256}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_NIST_P192 CURVE_NAME("NIST_P192")}
#    undef comma
#    define comma ,
#  endif  // ECC_NIST_P192
#  if ECC_NIST_P224
    comma{TPM_ECC_NIST_P224,
          224,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SHA256}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_NIST_P224 CURVE_NAME("NIST_P224")}
#    undef comma
#    define comma ,
#  endif  // ECC_NIST_P224
#  if ECC_NIST_P256
    comma{TPM_ECC_NIST_P256,
          256,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SHA256}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_NIST_P256 CURVE_NAME("NIST_P256")}
#    undef comma
#    define comma ,
#  endif  // ECC_NIST_P256
#  if ECC_NIST_P384
    comma{TPM_ECC_NIST_P384,
          384,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SHA384}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_NIST_P384 CURVE_NAME("NIST_P384")}
#    undef comma
#    define comma ,
#  endif  // ECC_NIST_P384
#  if ECC_NIST_P521
    comma{TPM_ECC_NIST_P521,
          521,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SHA512}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_NIST_P521 CURVE_NAME("NIST_P521")}
#    undef comma
#    define comma ,
#  endif  // ECC_NIST_P521
#  if ECC_BN_P256
    comma{TPM_ECC_BN_P256,
          256,
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_BN_P256 CURVE_NAME("BN_P256")}
#    undef comma
#    define comma ,
#  endif  // ECC_BN_P256
#  if ECC_BN_P638
    comma{TPM_ECC_BN_P638,
          638,
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_BN_P638 CURVE_NAME("BN_P638")}
#    undef comma
#    define comma ,
#  endif  // ECC_BN_P638
#  if ECC_SM2_P256
    comma{TPM_ECC_SM2_P256,
          256,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SM3_256}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_SM2_P256 CURVE_NAME("SM2_P256")}
#    undef comma
#    define comma ,
#  endif  // ECC_SM2_P256
};

#endif  // TPM_ALG_ECC
