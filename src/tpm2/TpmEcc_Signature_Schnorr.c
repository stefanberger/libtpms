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
/*  (c) Copyright IBM Corp. and others, 2023					*/
/*										*/
/********************************************************************************/

#include "Tpm.h"
#include "TpmEcc_Signature_Schnorr_fp.h"
#include "TpmEcc_Signature_Util_fp.h"
#include "TpmMath_Util_fp.h"

#if ALG_ECC && ALG_ECSCHNORR

/* 10.2.12.3.3 SchnorrReduce() */
/* Function to reduce a hash result if it's magnitude is to large. The size of number is set so that
   it has no more bytes of significance than the reference value. If the resulting number can have
   more bits of significance than the reference. */
static void
SchnorrReduce(
	      TPM2B       *number,        // IN/OUT: Value to reduce
	      bigConst     reference      // IN: the reference value
	      )
{
    UINT16      maxBytes = (UINT16)BITS_TO_BYTES(BnSizeInBits(reference));
    if(number->size > maxBytes)
	number->size = maxBytes;
}
/* 10.2.12.3.4 SchnorrEcc() */
/* This function is used to perform a modified Schnorr signature. */
/* This function will generate a random value k and compute */
/* a) (xR, yR) = [k]G */
/* b) r = hash(xR || P)(mod q) */
/* c) rT = truncated r */
/* d) s= k + rT * ds (mod q) */
/* e) return the tuple rT, s */
/* Error Returns Meaning */
/* TPM_RC_NO_RESULT failure in the Schnorr sign process */
/* TPM_RC_SCHEME hashAlg can't produce zero-length digest */
TPM_RC
BnSignEcSchnorr(
		bigNum                   bnR,           // OUT: r component of the signature
		bigNum                   bnS,           // OUT: s component of the signature
		bigCurve                 E,             // IN: the curve used in signing
		bigNum                   bnD,           // IN: the signing key
		const TPM2B_DIGEST      *digest,        // IN: the digest to sign
		TPM_ALG_ID               hashAlg,       // IN: signing scheme (contains a hash)
		RAND_STATE              *rand           // IN: non-NULL when testing
		)
{
    HASH_STATE               hashState;
    UINT16                   digestSize
	= CryptHashGetDigestSize(hashAlg);
    TPM2B_TYPE(T, MAX(MAX_DIGEST_SIZE, MAX_ECC_KEY_BYTES));
    TPM2B_T                  T2b;
    TPM2B                   *e = &T2b.b;
    TPM_RC                   retVal = TPM_RC_NO_RESULT;
    const ECC_CURVE_DATA    *C;
    bigConst                 order;
    bigConst                 prime;
    ECC_NUM(bnK);
    POINT(ecR);
    //
    // Parameter checks
    if(E == NULL)
	ERROR_EXIT(TPM_RC_VALUE);
    C = AccessCurveData(E);
    order = CurveGetOrder(C);
    prime = CurveGetOrder(C);
    // If the digest does not produce a hash, then null the signature and return
    // a failure.
    if(digestSize == 0)
	{
	    BnSetWord(bnR, 0);
	    BnSetWord(bnS, 0);
	    ERROR_EXIT(TPM_RC_SCHEME);
	}
    do
	{
	    // Generate a random key pair
	    if(!BnEccGenerateKeyPair(bnK, ecR, E, rand))
		break;
	    // Convert R.x to a string
	    BnTo2B(ecR->x, e, (NUMBYTES)BITS_TO_BYTES(BnSizeInBits(prime)));
	    // f) compute r = Hash(e || P) (mod n)
	    CryptHashStart(&hashState, hashAlg);
	    CryptDigestUpdate2B(&hashState, e);
	    CryptDigestUpdate2B(&hashState, &digest->b);
	    e->size = CryptHashEnd(&hashState, digestSize, e->buffer);
	    // Reduce the hash size if it is larger than the curve order
	    SchnorrReduce(e, order);
	    // Convert hash to number
	    BnFrom2B(bnR, e);
	    // libtpms: Note: e is NOT a concern for constant-timeness
	    // Do the Schnorr computation
	    retVal = BnSchnorrSign(bnS, bnK, bnR, bnD, CurveGetOrder(C));
	} while(retVal == TPM_RC_NO_RESULT);
 Exit:
    return retVal;
}

/* 10.2.12.3.9 BnValidateSignatureEcSchnorr() */
/* This function is used to validate an EC Schnorr signature. */
/* Error Returns Meaning */
/* TPM_RC_SIGNATURE signature not valid */
TPM_RC
BnValidateSignatureEcSchnorr(
			     bigNum               bnR,       // IN: r component of the signature
			     bigNum               bnS,       // IN: s component of the signature
			     TPM_ALG_ID           hashAlg,   // IN: hash algorithm of the signature
			     bigCurve             E,         // IN: the curve used in the signature
			     //     process
			     bigPoint             ecQ,       // IN: the public point of the key
			     const TPM2B_DIGEST  *digest     // IN: the digest that was signed
			     )
{
    BN_MAX(bnRn);
    POINT(ecE);
    BN_MAX(bnEx);
    const ECC_CURVE_DATA    *C = AccessCurveData(E);
    bigConst                 order = CurveGetOrder(C);
    UINT16                   digestSize = CryptHashGetDigestSize(hashAlg);
    HASH_STATE               hashState;
    TPM2B_TYPE(BUFFER, MAX(MAX_ECC_PARAMETER_BYTES, MAX_DIGEST_SIZE));
    TPM2B_BUFFER             Ex2 = {{sizeof(Ex2.t.buffer),{ 0 }}};
    BOOL                     OK;
    //
    // E = [s]G - [r]Q
    BnMod(bnR, order);
    // Make -r = n - r
    BnSub(bnRn, order, bnR);
    // E = [s]G + [-r]Q
    OK = BnPointMult(ecE, CurveGetG(C), bnS, ecQ, bnRn, E) == TPM_RC_SUCCESS;
    //   // reduce the x portion of E mod q
    //    OK = OK && BnMod(ecE->x, order);
    // Convert to byte string
    OK = OK && BnTo2B(ecE->x, &Ex2.b,
		      (NUMBYTES)(BITS_TO_BYTES(BnSizeInBits(order))));
    if(OK)
	{
	    // Ex = h(pE.x || digest)
	    CryptHashStart(&hashState, hashAlg);
	    CryptDigestUpdate(&hashState, Ex2.t.size, Ex2.t.buffer);
	    CryptDigestUpdate(&hashState, digest->t.size, digest->t.buffer);
	    Ex2.t.size = CryptHashEnd(&hashState, digestSize, Ex2.t.buffer);
	    SchnorrReduce(&Ex2.b, order);
	    BnFrom2B(bnEx, &Ex2.b);
	    // see if Ex matches R
	    OK = BnUnsignedCmp(bnEx, bnR) == 0;
	}
    return (OK) ? TPM_RC_SUCCESS : TPM_RC_SIGNATURE;
}

#endif  // ALG_ECC && ALG_ECSCHNORR
