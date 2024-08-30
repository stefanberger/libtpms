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
#include "TpmMath_Debug_fp.h"
#include "TpmMath_Util_fp.h"

#if ALG_ECC && ALG_ECSCHNORR

//*** SchnorrReduce()
// Function to reduce a hash result if it's magnitude is too large. The size of
// 'number' is set so that it has no more bytes of significance than 'reference'
// value. If the resulting number can have more bits of significance than
// 'reference'.
static void SchnorrReduce(TPM2B*           number,    // IN/OUT: Value to reduce
			  const Crypt_Int* reference  // IN: the reference value
			  )
{
    UINT16 maxBytes = (UINT16)BITS_TO_BYTES(ExtMath_SizeInBits(reference));
    if(number->size > maxBytes)
	number->size = maxBytes;
}

//*** SchnorrEcc()
// This function is used to perform a modified Schnorr signature.
//
// This function will generate a random value 'k' and compute
// a) ('xR', 'yR') = ['k']'G'
// b) 'r' = "Hash"('xR' || 'P')(mod 'q')
// c) 'rT' = truncated 'r'
// d) 's'= 'k' + 'rT' * 'ds' (mod 'q')
// e) return the tuple 'rT', 's'
//
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        failure in the Schnorr sign process
//      TPM_RC_SCHEME           hashAlg can't produce zero-length digest
TPM_RC TpmEcc_SignEcSchnorr(
			    Crypt_Int*            bnR,      // OUT: 'r' component of the signature
			    Crypt_Int*            bnS,      // OUT: 's' component of the signature
			    const Crypt_EccCurve* E,        // IN: the curve used in signing
			    Crypt_Int*            bnD,      // IN: the signing key
			    const TPM2B_DIGEST*   digest,   // IN: the digest to sign
			    TPM_ALG_ID            hashAlg,  // IN: signing scheme (contains a hash)
			    RAND_STATE*           rand      // IN: non-NULL when testing
			    )
{
    HASH_STATE hashState;
    UINT16     digestSize = CryptHashGetDigestSize(hashAlg);
    TPM2B_TYPE(T, MAX(MAX_DIGEST_SIZE, MAX_ECC_KEY_BYTES));
    TPM2B_T          T2b;
    TPM2B*           e      = &T2b.b;
    TPM_RC           retVal = TPM_RC_NO_RESULT;
    const Crypt_Int* order;
    const Crypt_Int* prime;
    CRYPT_ECC_NUM(bnK);
    CRYPT_POINT_VAR(ecR);
    //
    // Parameter checks
    if(E == NULL)
	ERROR_EXIT(TPM_RC_VALUE);

    order = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));
    prime = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));

    // If the digest does not produce a hash, then null the signature and return
    // a failure.
    if(digestSize == 0)
	{
	    ExtMath_SetWord(bnR, 0);
	    ExtMath_SetWord(bnS, 0);
	    ERROR_EXIT(TPM_RC_SCHEME);
	}
    do
	{
	    // Generate a random key pair
	    if(!TpmEcc_GenerateKeyPair(bnK, ecR, E, rand))
		break;
	    // Convert R.x to a string
	    TpmMath_IntTo2B(ExtEcc_PointX(ecR),
			    e,
			    (NUMBYTES)BITS_TO_BYTES(ExtMath_SizeInBits(prime)));

	    // f) compute r = Hash(e || P) (mod n)
	    CryptHashStart(&hashState, hashAlg);
	    CryptDigestUpdate2B(&hashState, e);
	    CryptDigestUpdate2B(&hashState, &digest->b);
	    e->size = CryptHashEnd(&hashState, digestSize, e->buffer);
	    // Reduce the hash size if it is larger than the curve order
	    SchnorrReduce(e, order);
	    // Convert hash to number
	    TpmMath_IntFrom2B(bnR, e);
	    // libtpms: Note: e is NOT a concern for constant-timeness
	    // Do the Schnorr computation
	    retVal = TpmEcc_SchnorrCalculateS(
					      bnS, bnK, bnR, bnD, ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E)));
	} while(retVal == TPM_RC_NO_RESULT);
 Exit:
    return retVal;
}

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
					 )
{
    CRYPT_INT_MAX(bnRn);
    CRYPT_POINT_VAR(ecE);
    CRYPT_INT_MAX(bnEx);
    const Crypt_Int* order      = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));
    UINT16           digestSize = CryptHashGetDigestSize(hashAlg);
    HASH_STATE       hashState;
    TPM2B_TYPE(BUFFER, MAX(MAX_ECC_PARAMETER_BYTES, MAX_DIGEST_SIZE));
    TPM2B_BUFFER Ex2 = {{sizeof(Ex2.t.buffer), {0}}};
    BOOL         OK;

    if (hashAlg == TPM_ALG_SHA1 &&				// libtpms added begin
	RuntimeProfileRequiresAttributeFlags(&g_RuntimeProfile,
					     RUNTIME_ATTRIBUTE_NO_SHA1_VERIFICATION))
	return TPM_RC_HASH;					// libtpms added end
    //
    // E = [s]G - [r]Q
    ExtMath_Mod(bnR, order);
    // Make -r = n - r
    ExtMath_Subtract(bnRn, order, bnR);
    // E = [s]G + [-r]Q
    OK = TpmEcc_PointMult(
			  ecE, ExtEcc_CurveGetG(ExtEcc_CurveGetCurveId(E)), bnS, ecQ, bnRn, E)
	 == TPM_RC_SUCCESS;
    //   // reduce the x portion of E mod q
    //    OK = OK && ExtMath_Mod(ecE->x, order);
    // Convert to byte string
    OK = OK
	 && TpmMath_IntTo2B(ExtEcc_PointX(ecE),
			    &Ex2.b,
			    (NUMBYTES)(BITS_TO_BYTES(ExtMath_SizeInBits(order))));
    if(OK)
	{
	    // Ex = h(pE.x || digest)
	    CryptHashStart(&hashState, hashAlg);
	    CryptDigestUpdate(&hashState, Ex2.t.size, Ex2.t.buffer);
	    CryptDigestUpdate(&hashState, digest->t.size, digest->t.buffer);
	    Ex2.t.size = CryptHashEnd(&hashState, digestSize, Ex2.t.buffer);
	    SchnorrReduce(&Ex2.b, order);
	    TpmMath_IntFrom2B(bnEx, &Ex2.b);
	    // see if Ex matches R
	    OK = ExtMath_UnsignedCmp(bnEx, bnR) == 0;
	}
    return (OK) ? TPM_RC_SUCCESS : TPM_RC_SIGNATURE;
}

#endif  // ALG_ECC && ALG_ECSCHNORR
