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

//** Introduction
// Prototypes for functions the bignum library requires
// from a bignum-based math support library.
// Functions contained in the MathInterface but not listed here are provided by
// the TpmBigNum library itself.
//
// This file contains the function prototypes for the functions that need to be
// present in the selected math library. For each function listed, there should
// be a small stub function. That stub provides the interface between the TPM
// code and the support library. In most cases, the stub function will only need
// to do a format conversion between the TPM big number and the support library
// big number. The TPM big number format was chosen to make this relatively
// simple and fast.
//
// Arithmetic operations return a BOOL to indicate if the operation completed
// successfully or not.

#ifndef BN_SUPPORT_INTERFACE_H
#define BN_SUPPORT_INTERFACE_H
// TODO_RENAME_INC_FOLDER:private refers to the TPM_CoreLib private headers
#include "GpMacros.h"
#include "BnValues.h"

//** BnSupportLibInit()
// This function is called by CryptInit() so that necessary initializations can be
// performed on the cryptographic library.
LIB_EXPORT
int BnSupportLibInit(void);

//** MathLibraryCompatibililtyCheck()
// This function is only used during development to make sure that the library
// that is being referenced is using the same size of data structures as the TPM.
BOOL BnMathLibraryCompatibilityCheck(void);

//** BnModMult()
// Does 'op1' * 'op2' and divide by 'modulus' returning the remainder of the divide.
LIB_EXPORT BOOL BnModMult(
			  bigNum result, bigConst op1, bigConst op2, bigConst modulus);

//** BnMult()
// Multiplies two numbers and returns the result
LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand, bigConst multiplier);

//** BnDiv()
// This function divides two bigNum values. The function returns FALSE if there is
// an error in the operation.
LIB_EXPORT BOOL BnDiv(
		      bigNum quotient, bigNum remainder, bigConst dividend, bigConst divisor);
//** BnMod()
#define BnMod(a, b) BnDiv(NULL, (a), (a), (b))

#if ALG_RSA
//** BnGcd()
// Get the greatest common divisor of two numbers. This function is only needed
// when the TPM implements RSA.
LIB_EXPORT BOOL BnGcd(bigNum gcd, bigConst number1, bigConst number2);

//** BnModExp()
// Do modular exponentiation using bigNum values. This function is only needed
// when the TPM implements RSA.
LIB_EXPORT BOOL BnModExp(
			 bigNum result, bigConst number, bigConst exponent, bigConst modulus);
#endif  // ALG_RSA

	//** BnModInverse()
	// Modular multiplicative inverse.
LIB_EXPORT BOOL BnModInverse(bigNum result, bigConst number, bigConst modulus);

#if ALG_ECC

//** BnCurveInitialize()
// This function is used to initialize the pointers of a bigCurveData structure. The
// structure is a set of pointers to bigNum values. The curve-dependent values are
// set by a different function. This function is only needed
// if the TPM supports ECC.
LIB_EXPORT bigCurveData* BnCurveInitialize(bigCurveData* E, TPM_ECC_CURVE curveId);

//*** BnCurveFree()
// This function will free the allocated components of the curve and end the
// frame in which the curve data exists
LIB_EXPORT void BnCurveFree(bigCurveData* E);

//** BnEccModMult()
// This function does a point multiply of the form R = [d]S. A return of FALSE
// indicates that the result was the point at infinity. This function is only needed
// if the TPM supports ECC.
LIB_EXPORT BOOL BnEccModMult(
			     bigPoint R, pointConst S, bigConst d, const bigCurveData* E);

//** BnEccModMult2()
// This function does a point multiply of the form R = [d]S + [u]Q. A return of
// FALSE indicates that the result was the point at infinity. This function is only
// needed if the TPM supports ECC.
LIB_EXPORT BOOL BnEccModMult2(bigPoint            R,
			      pointConst          S,
			      bigConst            d,
			      pointConst          Q,
			      bigConst            u,
			      const bigCurveData* E);

//** BnEccAdd()
// This function does a point add R = S + Q. A return of FALSE
// indicates that the result was the point at infinity. This function is only needed
// if the TPM supports ECC.
LIB_EXPORT BOOL BnEccAdd(
			 bigPoint R, pointConst S, pointConst Q, const bigCurveData* E);

#endif  // ALG_ECC

//			libtpms: added begin
bigCurveData*
BnCurveInitialize(
                  bigCurveData*     E,           // IN: curve structure to initialize
                  TPM_ECC_CURVE     curveId      // IN: curve identifier
                  );
//			libtpms: added end

#endif  //BN_SUPPORT_INTERFACE_H
