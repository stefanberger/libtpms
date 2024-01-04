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
#include "TpmEcc_Signature_SM2_fp.h"
#include "TpmMath_Debug_fp.h"
#include "TpmMath_Util_fp.h"

#if ALG_ECC && ALG_SM2

//*** TpmEcc_SignEcSm2()
// This function signs a digest using the method defined in SM2 Part 2. The method
// in the standard will add a header to the message to be signed that is a hash of
// the values that define the key. This then hashed with the message to produce a
// digest ('e'). This function signs 'e'.
//  Return Type: TPM_RC
//      TPM_RC_VALUE         bad curve
TPM_RC TpmEcc_SignEcSm2(Crypt_Int* bnR,  // OUT: 'r' component of the signature
			Crypt_Int* bnS,  // OUT: 's' component of the signature
			const Crypt_EccCurve* E,    // IN: the curve used in signing
			Crypt_Int*            bnD,  // IN: the private key
			const TPM2B_DIGEST*   digest,  // IN: the digest to sign
			RAND_STATE* rand  // IN: random number generator (mostly for
			//     debug)
			)
{
    CRYPT_INT_MAX_INITIALIZED(bnE, digest);  // Don't know how big digest might be
    CRYPT_ECC_NUM(bnN);
    CRYPT_ECC_NUM(bnK);
    CRYPT_ECC_NUM(bnT);  // temp
    CRYPT_POINT_VAR(Q1);
    const Crypt_Int* order =
	(E != NULL) ? ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E)) : NULL;
// libtpms added begin
    UINT32                    orderBits = ExtMath_SizeInBits(order);
    BOOL                      atByteBoundary = (orderBits & 7) == 0;
    CRYPT_ECC_NUM(bnK1);
    if (!E)
	return TPM_RC_VALUE;
// libtpms added end

    //
#  ifdef _SM2_SIGN_DEBUG
    TpmEccDebug_FromHex(bnE,
			"B524F552CD82B8B028476E005C377FB1"
			"9A87E6FC682D48BB5D42E3D9B9EFFE76",
			MAX_ECC_KEY_BYTES);
    TpmEccDebug_FromHex(bnD,
			"128B2FA8BD433C6C068C8D803DFF7979"
			"2A519A55171B1B650C23661D15897263",
			MAX_ECC_KEY_BYTES);
#  endif
    // A3: Use random number generator to generate random number 1 <= k <= n-1;
    // NOTE: Ax: numbers are from the SM2 standard
 loop:
    {
	// Get a random number 0 < k < n
	//						libtpms modified begin
	//
	// We take a dual approach here. One for curves whose order is not at
	// the byte boundary, e.g. NIST P521, we get a random number bnK and add
	// the order to that number to have bnK1. This will not spill over into
	// a new byte and we can then use bnK1 to do the do the BnEccModMult
	// with a constant number of bytes. For curves whose order is at the
	// byte boundary we require that the random number bnK comes back with
	// a requested number of bytes.
	if (!atByteBoundary) {
	    TpmMath_GetRandomInRange(bnK, order, rand);
	    ExtMath_Add(bnK1, bnK, order);
#  ifdef _SM2_SIGN_DEBUG
	TpmEccDebug_FromHex(bnK,
			    "6CB28D99385C175C94F94E934817663F"
			    "C176D925DD72B727260DBAAE1FB2F96F",
			    MAX_ECC_KEY_BYTES);
#  endif
	    // A4: Figure out the point of elliptic curve (x1, y1)=[k]G, and according
	    // to details specified in 4.2.7 in Part 1 of this document, transform the
	    // data type of x1 into an integer;
	    if(!ExtEcc_PointMultiply(Q1, NULL, bnK1, E))
	        goto loop;
	} else {
	    BnGenerateRandomInRangeAllBytes((bigNum)bnK, (bigNum)order, rand);
#  ifdef _SM2_SIGN_DEBUG
	TpmEccDebug_FromHex(bnK,
			    "6CB28D99385C175C94F94E934817663F"
			    "C176D925DD72B727260DBAAE1FB2F96F",
			    MAX_ECC_KEY_BYTES);
#  endif
	    if(!ExtEcc_PointMultiply(Q1, NULL, bnK, E))
	        goto loop;
	}						// libtpms modified end
	// A5: Figure out 'r' = ('e' + 'x1') mod 'n',
	ExtMath_Add(bnR, bnE, ExtEcc_PointX(Q1));
	ExtMath_Mod(bnR, order);
#  ifdef _SM2_SIGN_DEBUG
	pAssert(TpmEccDebug_HexEqual(bnR,
				     "40F1EC59F793D9F49E09DCEF49130D41"
				     "94F79FB1EED2CAA55BACDB49C4E755D1"));
#  endif
	// if r=0 or r+k=n, return to A3;
	if(ExtMath_IsZero(bnR))
	    goto loop;
	ExtMath_Add(bnT, bnK, bnR);
	if(ExtMath_UnsignedCmp(bnT, bnN) == 0)
	    goto loop;
	// A6: Figure out s = ((1 + dA)^-1  (k - r  dA)) mod n,
	// if s=0, return to A3;
	// compute t = (1+dA)^-1
	ExtMath_AddWord(bnT, bnD, 1);
	ExtMath_ModInverse(bnT, bnT, order);
#  ifdef _SM2_SIGN_DEBUG
	pAssert(TpmEccDebug_HexEqual(bnT,
				     "79BFCF3052C80DA7B939E0C6914A18CB"
				     "B2D96D8555256E83122743A7D4F5F956"));
#  endif
	// compute s = t * (k - r * dA) mod n
	ExtMath_ModMult(bnS, bnR, bnD, order);
	// k - r * dA mod n = k + n - ((r * dA) mod n)
	ExtMath_Subtract(bnS, order, bnS);
	ExtMath_Add(bnS, bnK, bnS);
	ExtMath_ModMult(bnS, bnS, bnT, order);
#  ifdef _SM2_SIGN_DEBUG
	pAssert(TpmEccDebug_HexEqual(bnS,
				     "6FC6DAC32C5D5CF10C77DFB20F7C2EB6"
				     "67A457872FB09EC56327A67EC7DEEBE7"));
#  endif
	if(ExtMath_IsZero(bnS))
	    goto loop;
    }
    // A7: According to details specified in 4.2.1 in Part 1 of this document,
    // transform the data type of r, s into bit strings, signature of message M
    // is (r, s).
    // This is handled by the common return code
#  ifdef _SM2_SIGN_DEBUG
    pAssert(TpmEccDebug_HexEqual(bnR,
				 "40F1EC59F793D9F49E09DCEF49130D41"
				 "94F79FB1EED2CAA55BACDB49C4E755D1"));
    pAssert(TpmEccDebug_HexEqual(bnS,
				 "6FC6DAC32C5D5CF10C77DFB20F7C2EB6"
				 "67A457872FB09EC56327A67EC7DEEBE7"));
#  endif
    return TPM_RC_SUCCESS;
}

//*** TpmEcc_ValidateSignatureEcSm2()
// This function is used to validate an SM2 signature.
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE            signature not valid
TPM_RC TpmEcc_ValidateSignatureEcSm2(
				     Crypt_Int*            bnR,  // IN: 'r' component of the signature
				     Crypt_Int*            bnS,  // IN: 's' component of the signature
				     const Crypt_EccCurve* E,    // IN: the curve used in the signature
				     //     process
				     Crypt_Point*        ecQ,    // IN: the public point of the key
				     const TPM2B_DIGEST* digest  // IN: the digest that was signed
				     )
{
    CRYPT_POINT_VAR(P);
    CRYPT_ECC_NUM(bnRp);
    CRYPT_ECC_NUM(bnT);
    CRYPT_INT_MAX_INITIALIZED(bnE, digest);
    BOOL             OK;
    const Crypt_Int* order = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));

#  ifdef _SM2_SIGN_DEBUG
    // Make sure that the input signature is the test signature
    pAssert(TpmEccDebug_HexEqual(bnR,
				 "40F1EC59F793D9F49E09DCEF49130D41"
				 "94F79FB1EED2CAA55BACDB49C4E755D1"));
    pAssert(TpmEccDebug_HexEqual(bnS,
				 "6FC6DAC32C5D5CF10C77DFB20F7C2EB6"
				 "67A457872FB09EC56327A67EC7DEEBE7"));
#  endif
    // b)   compute t  := (r + s) mod n
    ExtMath_Add(bnT, bnR, bnS);
    ExtMath_Mod(bnT, order);
#  ifdef _SM2_SIGN_DEBUG
    pAssert(TpmEccDebug_HexEqual(bnT,
				 "2B75F07ED7ECE7CCC1C8986B991F441A"
				 "D324D6D619FE06DD63ED32E0C997C801"));
#  endif
    // c)   verify that t > 0
    OK = !ExtMath_IsZero(bnT);
    if(!OK)
	// set T to a value that should allow rest of the computations to run
	// without trouble
	ExtMath_Copy(bnT, bnS);
    // d)   compute (x, y) := [s]G + [t]Q
    OK = ExtEcc_PointMultiplyAndAdd(P, NULL, bnS, ecQ, bnT, E);
#  ifdef _SM2_SIGN_DEBUG
    pAssert(OK
	    && TpmEccDebug_HexEqual(ExtEcc_PointX(P),
				    "110FCDA57615705D5E7B9324AC4B856D"
				    "23E6D9188B2AE47759514657CE25D112"));
#  endif
    // e)   compute r' := (e + x) mod n (the x coordinate is in bnT)
    OK = OK && ExtMath_Add(bnRp, bnE, ExtEcc_PointX(P));
    OK = OK && ExtMath_Mod(bnRp, order);

    // f)   verify that r' = r
    OK = OK && (ExtMath_UnsignedCmp(bnR, bnRp) == 0);

    if(!OK)
	return TPM_RC_SIGNATURE;
    else
	return TPM_RC_SUCCESS;
}

#endif  // ALG_ECC && ALG_SM2
