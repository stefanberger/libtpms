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
#include "TpmEcc_Signature_ECDSA_fp.h"
#include "TpmMath_Debug_fp.h"
#include "TpmMath_Util_fp.h"
#include "BnToOsslMath_fp.h"

#if ALG_ECC && ALG_ECDSA
//*** TpmEcc_AdjustEcdsaDigest()
// Function to adjust the digest so that it is no larger than the order of the
// curve. This is used for ECDSA sign and verification.
#if !USE_OPENSSL_FUNCTIONS_ECDSA       // libtpms added
static Crypt_Int* TpmEcc_AdjustEcdsaDigest(
					   Crypt_Int*          bnD,     // OUT: the adjusted digest
					   const TPM2B_DIGEST* digest,  // IN: digest to adjust
					   const Crypt_Int*    max      // IN: value that indicates the maximum
					   //     number of bits in the results
					   )
{
    int bitsInMax = ExtMath_SizeInBits(max);
    int shift;
    //
    if(digest == NULL)
	ExtMath_SetWord(bnD, 0);
    else
	{
	    ExtMath_IntFromBytes(bnD,
				 digest->t.buffer,
				 (NUMBYTES)MIN(digest->t.size, BITS_TO_BYTES(bitsInMax)));
	    shift = ExtMath_SizeInBits(bnD) - bitsInMax;
	    if(shift > 0)
		ExtMath_ShiftRight(bnD, bnD, shift);
	}
    return bnD;
}
#endif                                 // libtpms added

//*** TpmEcc_SignEcdsa()
// This function implements the ECDSA signing algorithm. The method is described
// in the comments below.
#if !USE_OPENSSL_FUNCTIONS_ECDSA       // libtpms added
TPM_RC
TpmEcc_SignEcdsa(Crypt_Int*            bnR,   // OUT: 'r' component of the signature
		 Crypt_Int*            bnS,   // OUT: 's' component of the signature
		 const Crypt_EccCurve* E,     // IN: the curve used in the signature
		 //     process
		 Crypt_Int*          bnD,     // IN: private signing key
		 const TPM2B_DIGEST* digest,  // IN: the digest to sign
		 RAND_STATE*         rand     // IN: used in debug of signing
		 )
{
    CRYPT_ECC_NUM(bnK);
    CRYPT_ECC_NUM(bnIk);
    CRYPT_INT_VAR(bnE, MAX_ECC_KEY_BITS);
    CRYPT_POINT_VAR(ecR);
    CRYPT_ECC_NUM(bnX);
    const Crypt_Int* order  = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));
    TPM_RC           retVal = TPM_RC_SUCCESS;
    INT32            tries  = 10;
    BOOL             OK     = FALSE;
    //
    pAssert(digest != NULL);
    // The algorithm as described in "Suite B Implementer's Guide to FIPS
    // 186-3(ECDSA)"
    // 1. Use one of the routines in Appendix A.2 to generate (k, k^-1), a
    //    per-message secret number and its inverse modulo n. Since n is prime,
    //    the output will be invalid only if there is a failure in the RBG.
    // 2. Compute the elliptic curve point R = [k]G = (xR, yR) using EC scalar
    //    multiplication (see [Routines]), where G is the base point included in
    //    the set of domain parameters.
    // 3. Compute r = xR mod n. If r = 0, then return to Step 1. 1.
    // 4. Use the selected hash function to compute H = Hash(M).
    // 5. Convert the bit string H to an integer e as described in Appendix B.2.
    // 6. Compute s = (k^-1 *  (e + d *  r)) mod q. If s = 0, return to Step 1.2.
    // 7. Return (r, s).
    // In the code below, q is n (that it, the order of the curve is p)

    do  // This implements the loop at step 6. If s is zero, start over.
	{
	    for(; tries > 0; tries--)
		{
		    // Step 1 and 2 -- generate an ephemeral key and the modular inverse
		    // of the private key.
		    if(!TpmEcc_GenerateKeyPair(bnK, ecR, E, rand))
			continue;
		    // get mutable copy of X coordinate
		    ExtMath_Copy(bnX, ExtEcc_PointX(ecR));
		    // x coordinate is mod p.  Make it mod q
		    ExtMath_Mod(bnX, order);
		    // Make sure that it is not zero;
		    if(ExtMath_IsZero(bnX))
			continue;
		    // write the modular reduced version of r as part of the signature
		    ExtMath_Copy(bnR, bnX);
		    // Make sure that a modular inverse exists and try again if not
		    OK = (ExtMath_ModInverse(bnIk, bnK, order));
		    if(OK)
			break;
		}
	    if(!OK)
		goto Exit;

	    TpmEcc_AdjustEcdsaDigest(bnE, digest, order);

	    // now have inverse of K (bnIk), e (bnE), r (bnR),  d (bnD) and
	    // ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E))
	    // Compute s = k^-1 (e + r*d)(mod q)
	    //  first do s = r*d mod q
	    ExtMath_ModMult(bnS, bnR, bnD, order);
	    // s = e + s = e + r * d
	    ExtMath_Add(bnS, bnE, bnS);
	    // s = k^(-1)s (mod n) = k^(-1)(e + r * d)(mod n)
	    ExtMath_ModMult(bnS, bnIk, bnS, order);

	    // If S is zero, try again
	} while(ExtMath_IsZero(bnS));
 Exit:
    return retVal;
}
#else // !USE_OPENSSL_FUNCTIONS_ECDSA  libtpms added begin
TPM_RC
TpmEcc_SignEcdsa(Crypt_Int*            bnR,   // OUT: 'r' component of the signature
		 Crypt_Int*            bnS,   // OUT: 's' component of the signature
		 const Crypt_EccCurve* E,     // IN: the curve used in the signature
		 //     process
		 Crypt_Int*          bnD,     // IN: private signing key
		 const TPM2B_DIGEST* digest,  // IN: the digest to sign
		 RAND_STATE*         rand LIBTPMS_ATTR_UNUSED  // IN: used in debug of signing
		 )
{
    ECDSA_SIG*    sig = NULL;
    EC_KEY*       eckey;
    int           retVal;
    const BIGNUM* r;
    const BIGNUM* s;
    BIGNUM*       d = BN_new();

    d = BigInitialized(d, (bigConst)bnD);

    eckey = EC_KEY_new();

    if (d == NULL || eckey == NULL)
        ERROR_EXIT(TPM_RC_FAILURE);

    if (EC_KEY_set_group(eckey, E->G) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    if (EC_KEY_set_private_key(eckey, d) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    sig = ECDSA_do_sign(digest->b.buffer, digest->b.size, eckey);
    if (sig == NULL)
        ERROR_EXIT(TPM_RC_FAILURE);

    ECDSA_SIG_get0(sig, &r, &s);
    OsslToTpmBn((bigNum)bnR, r);
    OsslToTpmBn((bigNum)bnS, s);

    retVal = TPM_RC_SUCCESS;

 Exit:
    BN_clear_free(d);
    EC_KEY_free(eckey);
    ECDSA_SIG_free(sig);

    return retVal;
}
#endif  // USE_OPENSSL_FUNCTIONS_ECDSA libtpms added end

//*** TpmEcc_ValidateSignatureEcdsa()
// This function validates an ECDSA signature. rIn and sIn should have been checked
// to make sure that they are in the range 0 < 'v' < 'n'
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE           signature not valid
#if !USE_OPENSSL_FUNCTIONS_ECDSA  // libtpms added
TPM_RC
TpmEcc_ValidateSignatureEcdsa(
			      Crypt_Int*            bnR,  // IN: 'r' component of the signature
			      Crypt_Int*            bnS,  // IN: 's' component of the signature
			      const Crypt_EccCurve* E,    // IN: the curve used in the signature
			      //     process
			      const Crypt_Point*  ecQ,    // IN: the public point of the key
			      const TPM2B_DIGEST* digest  // IN: the digest that was signed
			      )
{
    // Make sure that the allocation for the digest is big enough for a maximum
    // digest
    CRYPT_INT_VAR(bnE, MAX_ECC_KEY_BITS);
    CRYPT_POINT_VAR(ecR);
    CRYPT_ECC_NUM(bnU1);
    CRYPT_ECC_NUM(bnU2);
    CRYPT_ECC_NUM(bnW);
    CRYPT_ECC_NUM(bnV);
    const Crypt_Int* order  = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));
    TPM_RC           retVal = TPM_RC_SIGNATURE;

    if (digest->b.size == CryptHashGetDigestSize(TPM_ALG_SHA1) &&	// libtpms added begin
	RuntimeProfileRequiresAttributeFlags(&g_RuntimeProfile,
					     RUNTIME_ATTRIBUTE_NO_SHA1_VERIFICATION))
	return TPM_RC_HASH;						// libtpms added end
    //
    // Get adjusted digest
    TpmEcc_AdjustEcdsaDigest(bnE, digest, order);
    // 1. If r and s are not both integers in the interval [1, n - 1], output
    //    INVALID.
    //  bnR  and bnS were validated by the caller
    // 2. Use the selected hash function to compute H0 = Hash(M0).
    // This is an input parameter
    // 3. Convert the bit string H0 to an integer e as described in Appendix B.2.
    // Done at entry
    // 4. Compute w = (s')^-1 mod n, using the routine in Appendix B.1.
    if(!ExtMath_ModInverse(bnW, bnS, order))
	goto Exit;
    // 5. Compute u1 = (e' *   w) mod n, and compute u2 = (r' *  w) mod n.
    ExtMath_ModMult(bnU1, bnE, bnW, order);
    ExtMath_ModMult(bnU2, bnR, bnW, order);
    // 6. Compute the elliptic curve point R = (xR, yR) = u1G+u2Q, using EC
    //    scalar multiplication and EC addition (see [Routines]). If R is equal to
    //    the point at infinity O, output INVALID.
    if(TpmEcc_PointMult(
			ecR, ExtEcc_CurveGetG(ExtEcc_CurveGetCurveId(E)), bnU1, ecQ, bnU2, E)
       != TPM_RC_SUCCESS)
	goto Exit;
    // 7. Compute v = Rx mod n.
    ExtMath_Copy(bnV, ExtEcc_PointX(ecR));
    ExtMath_Mod(bnV, order);
    // 8. Compare v and r0. If v = r0, output VALID; otherwise, output INVALID
    if(ExtMath_UnsignedCmp(bnV, bnR) != 0)
	goto Exit;

    retVal = TPM_RC_SUCCESS;
 Exit:
    return retVal;
}
#else // USE_OPENSSL_FUNCTIONS_ECDSA     libtpms added begin
TPM_RC
TpmEcc_ValidateSignatureEcdsa(
			      Crypt_Int*            bnR,  // IN: 'r' component of the signature
			      Crypt_Int*            bnS,  // IN: 's' component of the signature
			      const Crypt_EccCurve* E,    // IN: the curve used in the signature
			      //     process
			      const Crypt_Point*  ecQ,    // IN: the public point of the key
			      const TPM2B_DIGEST* digest  // IN: the digest that was signed
			      )
{
    int        retVal;
    int        rc;
    ECDSA_SIG* sig = NULL;
    EC_KEY*    eckey = NULL;
    BIGNUM*    r = BN_new();
    BIGNUM*    s = BN_new();
    EC_POINT*  q = EcPointInitialized((bn_point_t*)ecQ, E);

    if (digest->b.size == CryptHashGetDigestSize(TPM_ALG_SHA1) &&
	RuntimeProfileRequiresAttributeFlags(&g_RuntimeProfile,
					     RUNTIME_ATTRIBUTE_NO_SHA1_VERIFICATION))
	ERROR_EXIT(TPM_RC_HASH);

    r = BigInitialized(r, (bigConst)bnR);
    s = BigInitialized(s, (bigConst)bnS);

    sig = ECDSA_SIG_new();
    eckey = EC_KEY_new();

    if (r == NULL || s == NULL || q == NULL || sig == NULL || eckey == NULL)
        ERROR_EXIT(TPM_RC_FAILURE);

    if (EC_KEY_set_group(eckey, E->G) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    if (EC_KEY_set_public_key(eckey, q) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    if (ECDSA_SIG_set0(sig, r, s) != 1)
        ERROR_EXIT(TPM_RC_FAILURE);

    /* sig now owns r and s */
    r = NULL;
    s = NULL;

    rc = ECDSA_do_verify(digest->b.buffer, digest->b.size, sig, eckey);
    switch (rc) {
    case 1:
        retVal = TPM_RC_SUCCESS;
        break;
    case 0:
        retVal = TPM_RC_SIGNATURE;
        break;
    default:
        retVal = TPM_RC_FAILURE;
        break;
    }

 Exit:
    EC_KEY_free(eckey);
    ECDSA_SIG_free(sig);
    EC_POINT_clear_free(q);
    BN_clear_free(r);
    BN_clear_free(s);

    return retVal;
}
#endif // USE_OPENSSL_FUNCTIONS_ECDSA     libtpms added end

#endif  // ALG_ECC && ALG_ECDSA
