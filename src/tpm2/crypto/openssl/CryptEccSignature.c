/********************************************************************************/
/*										*/
/*			     ECC Signatures					*/
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

//** Includes and Defines
#include "Tpm.h"
#include "CryptEccSignature_fp.h"
#include "TpmEcc_Signature_ECDAA_fp.h"
#include "TpmEcc_Signature_ECDSA_fp.h"
#include "TpmEcc_Signature_Schnorr_fp.h"
#include "TpmEcc_Signature_SM2_fp.h"
#include "TpmToOsslMath_fp.h"  // libtpms added
#if ALG_ECC
/* 10.2.12.2 Utility Functions */

/* 10.2.12.3.6 CryptEccSign() */
/* This function is the dispatch function for the various ECC-based signing schemes. There is a bit
   of ugliness to the parameter passing. In order to test this, we sometime would like to use a
   deterministic RNG so that we can get the same signatures during testing. The easiest way to do
   this for most schemes is to pass in a deterministic RNG and let it return canned values during
   testing. There is a competing need for a canned parameter to use in ECDAA. To accommodate both
   needs with minimal fuss, a special type of RAND_STATE is defined to carry the address of the
   commit value. The setup and handling of this is not very different for the caller than what was
   in previous versions of the code. */
/* Error Returns Meaning */
/* TPM_RC_SCHEME scheme is not supported */
LIB_EXPORT TPM_RC
CryptEccSign(
	     TPMT_SIGNATURE          *signature,     // OUT: signature
	     OBJECT                  *signKey,       // IN: ECC key to sign the hash
	     const TPM2B_DIGEST      *digest,        // IN: digest to sign
	     TPMT_ECC_SCHEME         *scheme,        // IN: signing scheme
	     RAND_STATE              *rand
	     )
{
    CURVE_INITIALIZED(E, signKey->publicArea.parameters.eccDetail.curveID);
    ECC_INITIALIZED(bnD, &signKey->sensitive.sensitive.ecc.b);
    ECC_NUM(bnR);
    ECC_NUM(bnS);
    const ECC_CURVE_DATA   *C;
    TPM_RC                  retVal = TPM_RC_SCHEME;
    //
    NOT_REFERENCED(scheme);
    if(E == NULL)
	ERROR_EXIT(TPM_RC_VALUE);
    C = AccessCurveData(E);
    signature->signature.ecdaa.signatureR.t.size
	= sizeof(signature->signature.ecdaa.signatureR.t.buffer);
    signature->signature.ecdaa.signatureS.t.size
	= sizeof(signature->signature.ecdaa.signatureS.t.buffer);
    TEST(signature->sigAlg);
    switch(signature->sigAlg)
	{
	  case TPM_ALG_ECDSA:
	    retVal = BnSignEcdsa(bnR, bnS, E, bnD, digest, rand);
	    break;
#if ALG_ECDAA
	  case TPM_ALG_ECDAA:
	    retVal = BnSignEcdaa(&signature->signature.ecdaa.signatureR, bnS, E,
				 bnD, digest, scheme, signKey, rand);
	    bnR = NULL;
	    break;
#endif
#if ALG_ECSCHNORR
	  case TPM_ALG_ECSCHNORR:
	    retVal = BnSignEcSchnorr(bnR, bnS, E, bnD, digest,
				     signature->signature.ecschnorr.hash,
				     rand);
	    break;
#endif
#if ALG_SM2
	  case TPM_ALG_SM2:
	    retVal = BnSignEcSm2(bnR, bnS, E, bnD, digest, rand);
	    break;
#endif
	  default:
	    break;
	}
    // If signature generation worked, convert the results.
    if(retVal == TPM_RC_SUCCESS)
	{
	    NUMBYTES     orderBytes =
		(NUMBYTES)BITS_TO_BYTES(BnSizeInBits(CurveGetOrder(C)));
	    if(bnR != NULL)
		BnTo2B(bnR, &signature->signature.ecdaa.signatureR.b, orderBytes);
	    if(bnS != NULL)
		BnTo2B(bnS, &signature->signature.ecdaa.signatureS.b, orderBytes);
	}
 Exit:
    CURVE_FREE(E);
    return retVal;
}
//********************* Signature Validation   ********************

//*** CryptEccValidateSignature()
// This function validates an EcDsa or EcSchnorr signature.
// The point 'Qin' needs to have been validated to be on the curve of 'curveId'.
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE            not a valid signature
LIB_EXPORT TPM_RC CryptEccValidateSignature(
					    TPMT_SIGNATURE*     signature,  // IN: signature to be verified
					    OBJECT*             signKey,    // IN: ECC key signed the hash
					    const TPM2B_DIGEST* digest      // IN: digest that was signed
					    )
{
    CURVE_INITIALIZED(E, signKey->publicArea.parameters.eccDetail.curveID);
    ECC_NUM(bnR);
    ECC_NUM(bnS);
    POINT_INITIALIZED(ecQ, &signKey->publicArea.unique.ecc);
    bigConst                 order;
    TPM_RC           retVal;

    if(E == NULL)
	ERROR_EXIT(TPM_RC_VALUE);
    order = CurveGetOrder(AccessCurveData(E));
    //    // Make sure that the scheme is valid
    switch(signature->sigAlg)
	{
	  case TPM_ALG_ECDSA:
#  if ALG_ECSCHNORR
	  case TPM_ALG_ECSCHNORR:
#  endif
#  if ALG_SM2
	  case TPM_ALG_SM2:
#  endif
	    break;
	  default:
	    ERROR_EXIT(TPM_RC_SCHEME);
	    break;
	}
    // Can convert r and s after determining that the scheme is an ECC scheme. If
    // this conversion doesn't work, it means that the unmarshaling code for
    // an ECC signature is broken.
    BnFrom2B(bnR, &signature->signature.ecdsa.signatureR.b);
    BnFrom2B(bnS, &signature->signature.ecdsa.signatureS.b);
    // r and s have to be greater than 0 but less than the curve order
    if(BnEqualZero(bnR) || BnEqualZero(bnS))
	ERROR_EXIT(TPM_RC_SIGNATURE);
    if((BnUnsignedCmp(bnS, order) >= 0)
       || (BnUnsignedCmp(bnR, order) >= 0))
	ERROR_EXIT(TPM_RC_SIGNATURE);

    switch(signature->sigAlg)
	{
	  case TPM_ALG_ECDSA:
	    retVal = BnValidateSignatureEcdsa(bnR, bnS, E, ecQ, digest);
	    break;
#if ALG_ECSCHNORR
	  case TPM_ALG_ECSCHNORR:
	    retVal = BnValidateSignatureEcSchnorr(bnR, bnS,
						  signature->signature.any.hashAlg,
						  E, ecQ, digest);
	    break;
#endif
#if ALG_SM2
	  case TPM_ALG_SM2:
	    retVal = BnValidateSignatureEcSm2(bnR, bnS, E, ecQ, digest);
	    break;
#endif
	  default:
	    FAIL(FATAL_ERROR_INTERNAL);
	}
 Exit:
    CURVE_FREE(E);
    return retVal;
}

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
					)
{
    CURVE_INITIALIZED(curve, curveId);  	// Normally initialize E as the curve, but E means
						// something else in this function
    ECC_INITIALIZED(bnR, r);
    TPM_RC               retVal = TPM_RC_SUCCESS;
    //
    // Validate that the required parameters are provided.
    // Note: E has to be provided if computing E := [r]Q or E := [r]M. Will do
    // E := [r]Q if both M and B are NULL.
    pAssert(r != NULL && E != NULL);

    // Initialize the output points in case they are not computed
    ClearPoint2B(K);
    ClearPoint2B(L);
    ClearPoint2B(E);

    // Sizes of the r parameter may not be zero
    pAssert(r->t.size > 0);

    // If B is provided, compute K=[d]B and L=[r]B
    if(B != NULL)
	{
	    ECC_INITIALIZED(bnD, d);
	    POINT_INITIALIZED(pB, B);
	    POINT(pK);
	    POINT(pL);
	    //
	    pAssert(d != NULL && K != NULL && L != NULL);
	    if(!BnIsOnCurve(pB, AccessCurveData(curve)))
		ERROR_EXIT(TPM_RC_VALUE);
	    // do the math for K = [d]B
	    if((retVal = BnPointMult(pK, pB, bnD, NULL, NULL, curve)) != TPM_RC_SUCCESS)
		goto Exit;
	    // Convert BN K to TPM2B K
	    BnPointTo2B(K, pK, curve);
	    //  compute L= [r]B after checking for cancel
	    if(_plat__IsCanceled())
		ERROR_EXIT(TPM_RC_CANCELED);
	    // compute L = [r]B
	    if(!BnIsValidPrivateEcc(bnR, curve))
		ERROR_EXIT(TPM_RC_VALUE);
	    if((retVal = BnPointMult(pL, pB, bnR, NULL, NULL, curve)) != TPM_RC_SUCCESS)
		goto Exit;
	    // Convert BN L to TPM2B L
	    BnPointTo2B(L, pL, curve);
	}
    if((M != NULL) || (B == NULL))
	{
	    POINT_INITIALIZED(pM, M);
	    POINT(pE);
	    //
	    // Make sure that a place was provided for the result
	    pAssert(E != NULL);

	    // if this is the third point multiply, check for cancel first
	    if((B != NULL) && _plat__IsCanceled())
		ERROR_EXIT(TPM_RC_CANCELED);

	    // If M provided, then pM will not be NULL and will compute E = [r]M.
	    // However, if M was not provided, then pM will be NULL and E = [r]G
	    // will be computed
	    if((retVal = BnPointMult(pE, pM, bnR, NULL, NULL, curve)) != TPM_RC_SUCCESS)
		goto Exit;
	    // Convert E to 2B format
	    BnPointTo2B(E, pE, curve);
	}
 Exit:
    CURVE_FREE(curve);
    return retVal;
}

#endif  // ALG_ECC
