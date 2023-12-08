/********************************************************************************/
/*										*/
/*			   Structure definitions used for ECC 			*/
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

//** Introduction
//
// This file contains structure definitions used for ECC. The structures in this
// file are only used internally. The ECC-related structures that cross the
// public TPM interface are defined in TpmTypes.h
//

// ECC Curve data type decoder ring
// ================================
// | Name                      | Old Name*      | Comments                                                                                   |
// | ------------------------- | -------------- | ------------------------------------------------------------------------------------------ |
// | TPM_ECC_CURVE             |                | 16-bit Curve ID from Part 2 of TCG TPM Spec                                                |
// | TPM_ECC_CURVE_METADATA    | ECC_CURVE      | See description below                                                                      |
// |                           |                |                                                                                            |
// * - if different

// TPM_ECC_CURVE_METADATA
// ======================
// TPM-specific metadata for a particular curve, such as OIDs and signing/kdf
// schemes associated with the curve.
//
// TODO_ECC: Need to remove the curve constants from this structure and replace
// them with a reference to math-lib provided calls. <Once done, add this
// revised comment to the above description> Note: this structure does *NOT*
// include the actual curve constants. The curve constants are no longer in this
// structure because the constants need to be in a format compatible with the
// math library and are retrieved by the `ExtEcc_CurveGet*` family of functions.
//
// Using the math library's constant structure here is not necessary and breaks
// encapsulation.  Using a tpm-specific format means either redundancy (the same
// values exist here and in a math-specific format), or forces the math library
// to adopt a particular format determined by this structure.  Neither outcome
// is as clean as simply leaving the actual constants out of this structure.

#ifndef _CRYPT_ECC_H
#define _CRYPT_ECC_H

//** Structures

typedef struct ECC_CURVE
{
    const TPM_ECC_CURVE          curveId;
    const UINT16                 keySizeBits;
    const TPMT_KDF_SCHEME        kdf;
    const TPMT_ECC_SCHEME        sign;
    const ECC_CURVE_DATA        *curveData; // the address of the curve data
    const BYTE                  *OID;
} ECC_CURVE;


//*** Macros
#define CURVE_DATA_DEF(CURVE)						\
    const ECC_CURVE_DATA CURVE = {					\
	(bigNum)&CURVE##_p_DATA, (bigNum)&CURVE##_n_DATA, (bigNum)&CURVE##_h_DATA, \
	(bigNum)&CURVE##_a_DATA, (bigNum)&CURVE##_b_DATA,		\
	{(bigNum)&CURVE##_gX_DATA, (bigNum)&CURVE##_gY_DATA, (bigNum)&BN_ONE} };

extern const ECC_CURVE eccCurves[ECC_CURVE_COUNT];

#define CURVE_DEF(CURVE)						\
    {									\
	TPM_ECC_##CURVE,						\
	    CURVE##_KEY_SIZE,						\
	    CURVE##_KDF,						\
	    CURVE##_SIGN,						\
	    &##CURVE,							\
	    OID_ECC_##CURVE						\
	    }
#define CURVE_NAME(N)

#endif
