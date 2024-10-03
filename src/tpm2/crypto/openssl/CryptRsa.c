/********************************************************************************/
/*										*/
/*		Implementation of cryptographic primitives for RSA		*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2024				*/
/*										*/
/********************************************************************************/

//** Introduction
//
// This file contains implementation of cryptographic primitives for RSA.
// Vendors may replace the implementation in this file with their own library
// functions.

//**  Includes
// Need this define to get the 'private' defines for this function
#define CRYPT_RSA_C
#include "Tpm.h"
#include "TpmMath_Util_fp.h"
#include "Helpers_fp.h"  // libtpms added

#include <assert.h>	 // libtpms added
#include <openssl/rsa.h> // libtpms added

#if ALG_RSA

//**  Obligatory Initialization Functions

//*** CryptRsaInit()
// Function called at _TPM_Init().
BOOL CryptRsaInit(void)
{
    return TRUE;
}

//*** CryptRsaStartup()
// Function called at TPM2_Startup()
BOOL CryptRsaStartup(void)
{
    return TRUE;
}

//** Internal Functions

//*** RsaInitializeExponent()
// This function initializes the bignum data structure that holds the private
// exponent. This function returns the pointer to the private exponent value so that
// it can be used in an initializer for a data declaration.

static privateExponent* RsaInitializeExponent(privateExponent* Z)
{
    // verify privateExponent packing matches the usage of the bn pointer as an
    // array in below function
    MUST_BE(offsetof(privateExponent, Q) == SIZEOF_MEMBER(privateExponent, P));

    Crypt_Int** bn = (Crypt_Int**)&Z->P;
    int         i;
    //
    for(i = 0; i < 5; i++)
	{
	    bn[i] = (Crypt_Int*)&(Z->entries[i]);
	    ExtMath_Initialize_Int(bn[i], MAX_RSA_KEY_BITS / 2);
	}
    return Z;
}

//*** MakePgreaterThanQ()
// This function swaps the pointers for P and Q if Q happens to be larger than Q.
static void MakePgreaterThanQ(privateExponent* Z)
{
    if(ExtMath_UnsignedCmp(Z->P, Z->Q) < 0)
	{
	    Crypt_Int* bnT = Z->P;
	    Z->P           = Z->Q;
	    Z->Q           = bnT;
	}
}

#if 0					// 	libtpms added
//*** PackExponent()
// This function takes the bignum private exponent and converts it into TPM2B form.
// In this form, the size field contains the overall size of the packed data. The
// buffer contains 5, equal sized values in P, Q, dP, dQ, qInv order. For example, if
// a key has a 2Kb public key, then the packed private key will contain 5, 1Kb values.
// This form makes it relatively easy to load and save the values without changing
// the normal unmarshaling to do anything more than allow a larger TPM2B for the
// private key. Also, when exporting the value, all that is needed is to change the
// size field of the private key in order to save just the P value.
//  Return Type: BOOL
//      TRUE(1)     success
//      FALSE(0)    failure         // The data is too big to fit
static BOOL PackExponent(TPM2B_PRIVATE_KEY_RSA* packed, privateExponent* Z)
{
    int    i;
    UINT16 primeSize = (UINT16)BITS_TO_BYTES(ExtMath_MostSigBitNum(Z->P));
    UINT16 pS        = primeSize;
    //
    pAssert((primeSize * 5) <= sizeof(packed->t.buffer));
    packed->t.size = (primeSize * 5) + RSA_prime_flag;
    for(i = 0; i < 5; i++)
	if(!ExtMath_IntToBytes(
			       (Crypt_Int*)&Z->entries[i], &packed->t.buffer[primeSize * i], &pS))
	    return FALSE;
    if(pS != primeSize)
	return FALSE;
    return TRUE;
}

//*** UnpackExponent()
// This function unpacks the private exponent from its TPM2B form into its bignum
// form.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        TPM2B is not the correct size
static BOOL UnpackExponent(TPM2B_PRIVATE_KEY_RSA* b, privateExponent* Z)
{
    UINT16      primeSize = b->t.size & ~RSA_prime_flag;
    int         i;
    Crypt_Int** bn = &Z->P;
    //
    GOTO_ERROR_UNLESS(b->t.size & RSA_prime_flag);
    RsaInitializeExponent(Z);
    GOTO_ERROR_UNLESS((primeSize % 5) == 0);
    primeSize /= 5;
    for(i = 0; i < 5; i++)
	GOTO_ERROR_UNLESS(
			  ExtMath_IntFromBytes(bn[i], &b->t.buffer[primeSize * i], primeSize)
			  != NULL);
    MakePgreaterThanQ(Z);
    return TRUE;
 Error:
    return FALSE;
}
#endif					// libtpms added

//*** ComputePrivateExponent()
// This function computes the private exponent from the primes.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure
static BOOL ComputePrivateExponent(
				   Crypt_Int*       pubExp,  // IN: the public exponent
				   privateExponent* Z        // IN/OUT: on input, has primes P and Q. On
				   //         output, has P, Q, dP, dQ, and pInv
				   )
{
    BOOL pOK;
    BOOL qOK;
    CRYPT_PRIME_VAR(pT);
    //
    // make p the larger value so that m2 is always less than p
    MakePgreaterThanQ(Z);

    //dP = (1/e) mod (p-1)
    pOK = ExtMath_SubtractWord(pT, Z->P, 1);
    pOK = pOK && ExtMath_ModInverse(Z->dP, pubExp, pT);
    //dQ = (1/e) mod (q-1)
    qOK = ExtMath_SubtractWord(pT, Z->Q, 1);
    qOK = qOK && ExtMath_ModInverse(Z->dQ, pubExp, pT);
    // qInv = (1/q) mod p
    if(pOK && qOK)
	pOK = qOK = ExtMath_ModInverse(Z->qInv, Z->Q, Z->P);
    if(!pOK)
	ExtMath_SetWord(Z->P, 0);
    if(!qOK)
	ExtMath_SetWord(Z->Q, 0);
    return pOK && qOK;
}

//*** RsaPrivateKeyOp()
// This function is called to do the exponentiation with the private key. Compile
// options allow use of the simple (but slow) private exponent, or the more complex
// but faster CRT method.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure
static BOOL RsaPrivateKeyOp(Crypt_Int* inOut,  // IN/OUT: number to be exponentiated
			    privateExponent* Z)
{
    CRYPT_RSA_VAR(M1);
    CRYPT_RSA_VAR(M2);
    CRYPT_RSA_VAR(M);
    CRYPT_RSA_VAR(H);
    //
    MakePgreaterThanQ(Z);
    // m1 = cdP mod p
    GOTO_ERROR_UNLESS(ExtMath_ModExp(M1, inOut, Z->dP, Z->P));
    // m2 = cdQ mod q
    GOTO_ERROR_UNLESS(ExtMath_ModExp(M2, inOut, Z->dQ, Z->Q));
    // h = qInv * (m1 - m2) mod p = qInv * (m1 + P - m2) mod P because Q < P
    // so m2 < P
    GOTO_ERROR_UNLESS(ExtMath_Subtract(H, Z->P, M2));
    GOTO_ERROR_UNLESS(ExtMath_Add(H, H, M1));
    GOTO_ERROR_UNLESS(ExtMath_ModMult(H, H, Z->qInv, Z->P));
    // m = m2 + h * q
    GOTO_ERROR_UNLESS(ExtMath_Multiply(M, H, Z->Q));
    GOTO_ERROR_UNLESS(ExtMath_Add(inOut, M2, M));
    return TRUE;
 Error:
    return FALSE;
}

//*** RSAEP()
// This function performs the RSAEP operation defined in PKCS#1v2.1. It is
// an exponentiation of a value ('m') with the public exponent ('e'), modulo
// the public ('n').
//
//  Return Type: TPM_RC
//      TPM_RC_VALUE     number to exponentiate is larger than the modulus
//
#if !USE_OPENSSL_FUNCTIONS_RSA         // libtpms added
static TPM_RC RSAEP(TPM2B* dInOut,  // IN: size of the encrypted block and the size of
		    //     the encrypted value. It must be the size of
		    //     the modulus.
		    // OUT: the encrypted data. Will receive the
		    //      decrypted value
		    OBJECT* key     // IN: the key to use
		    )
{
    TPM2B_TYPE(4BYTES, 4);
    TPM2B_4BYTES e2B;
    UINT32       e = key->publicArea.parameters.rsaDetail.exponent;
    //
    if(e == 0)
	e = RSA_DEFAULT_PUBLIC_EXPONENT;
    UINT32_TO_BYTE_ARRAY(e, e2B.t.buffer);
    e2B.t.size = 4;
    return ModExpB(dInOut->size,
		   dInOut->buffer,
		   dInOut->size,
		   dInOut->buffer,
		   e2B.t.size,
		   e2B.t.buffer,
		   key->publicArea.unique.rsa.t.size,
		   key->publicArea.unique.rsa.t.buffer);
}

//*** RSADP()
// This function performs the RSADP operation defined in PKCS#1v2.1. It is
// an exponentiation of a value ('c') with the private exponent ('d'), modulo
// the public modulus ('n'). The decryption is in place.
//
// This function also checks the size of the private key. If the size indicates
// that only a prime value is present, the key is converted to being a private
// exponent.
//
//  Return Type: TPM_RC
//      TPM_RC_SIZE         the value to decrypt is larger than the modulus
//
static TPM_RC RSADP(TPM2B*  inOut,  // IN/OUT: the value to encrypt
		    OBJECT* key     // IN: the key
		    )
{
    CRYPT_RSA_INITIALIZED(bnM, inOut);
    NEW_PRIVATE_EXPONENT(Z);
    if(UnsignedCompareB(inOut->size,
			inOut->buffer,
			key->publicArea.unique.rsa.t.size,
			key->publicArea.unique.rsa.t.buffer)
       >= 0)
	return TPM_RC_SIZE;
    // private key operation requires that private exponent be loaded
    // During self-test, this might not be the case so load it up if it hasn't
    // already done
    // been done
    if(!key->attributes.privateExp)					// libtpms changed begin: use older verions
	{
	    if(CryptRsaLoadPrivateExponent(&key->publicArea, &key->sensitive, key)
	       != TPM_RC_SUCCESS)
		return TPM_RC_BINDING;
	}
    GOTO_ERROR_UNLESS(TpmMath_IntFrom2B(Z->P, &key->sensitive.sensitive.rsa.b) != NULL);
    RsaSetExponentFromOld(Z, &key->privateExponent);
    // GOTO_ERROR_UNLESS(UnpackExponent(&key->sensitive.sensitive.rsa, Z));	// libtpms changed end
    GOTO_ERROR_UNLESS(RsaPrivateKeyOp(bnM, Z));
    GOTO_ERROR_UNLESS(TpmMath_IntTo2B(bnM, inOut, inOut->size));
    return TPM_RC_SUCCESS;
 Error:
    return TPM_RC_FAILURE;
}

//*** OaepEncode()
// This function performs OAEP padding. The size of the buffer to receive the
// OAEP padded data must equal the size of the modulus
//
//  Return Type: TPM_RC
//      TPM_RC_VALUE     'hashAlg' is not valid or message size is too large
//
static TPM_RC OaepEncode(
			 TPM2B*       padded,   // OUT: the pad data
			 TPM_ALG_ID   hashAlg,  // IN: algorithm to use for padding
			 const TPM2B* label,    // IN: null-terminated string (may be NULL)
			 TPM2B*       message,  // IN: the message being padded
			 RAND_STATE*  rand      // IN: the random number generator to use
			 )
{
    INT32  padLen;
    INT32  dbSize;
    INT32  i;
    BYTE   mySeed[MAX_DIGEST_SIZE];
    BYTE*  seed = mySeed;
    UINT16 hLen = CryptHashGetDigestSize(hashAlg);
    BYTE   mask[MAX_RSA_KEY_BYTES];
    BYTE*  pp;
    BYTE*  pm;
    TPM_RC retVal = TPM_RC_SUCCESS;

    pAssert(padded != NULL && message != NULL);

    // A value of zero is not allowed because the KDF can't produce a result
    // if the digest size is zero.
    if(hLen == 0)
	return TPM_RC_VALUE;

    // Basic size checks
    //  make sure digest isn't too big for key size
    if(padded->size < (2 * hLen) + 2)
	ERROR_EXIT(TPM_RC_HASH);

    // and that message will fit messageSize <= k - 2hLen - 2
    if(message->size > (padded->size - (2 * hLen) - 2))
	ERROR_EXIT(TPM_RC_VALUE);

    // Hash L even if it is null
    // Offset into padded leaving room for masked seed and byte of zero
    pp = &padded->buffer[hLen + 1];
    if(CryptHashBlock(hashAlg, label->size, (BYTE*)label->buffer, hLen, pp) != hLen)
	ERROR_EXIT(TPM_RC_FAILURE);

    // concatenate PS of k  mLen  2hLen  2
    padLen = padded->size - message->size - (2 * hLen) - 2;
    MemorySet(&pp[hLen], 0, padLen);
    pp[hLen + padLen] = 0x01;
    padLen += 1;
    memcpy(&pp[hLen + padLen], message->buffer, message->size);

    // The total size of db = hLen + pad + mSize;
    dbSize = hLen + padLen + message->size;

    DRBG_Generate(rand, mySeed, (UINT16)hLen);
    if(g_inFailureMode)
	ERROR_EXIT(TPM_RC_FAILURE);
    // mask = MGF1 (seed, nSize  hLen  1)
    CryptMGF_KDF(dbSize, mask, hashAlg, hLen, seed, 0);

    // Create the masked db
    pm = mask;
    for(i = dbSize; i > 0; i--)
	*pp++ ^= *pm++;
    pp = &padded->buffer[hLen + 1];

    // Run the masked data through MGF1
    if(CryptMGF_KDF(hLen, &padded->buffer[1], hashAlg, dbSize, pp, 0)
       != (unsigned)hLen)
	ERROR_EXIT(TPM_RC_VALUE);
    // Now XOR the seed to create masked seed
    pp = &padded->buffer[1];
    pm = seed;
    for(i = hLen; i > 0; i--)
	*pp++ ^= *pm++;
    // Set the first byte to zero
    padded->buffer[0] = 0x00;
 Exit:
    return retVal;
}

//*** OaepDecode()
// This function performs OAEP padding checking. The size of the buffer to receive
// the recovered data. If the padding is not valid, the 'dSize' size is set to zero
// and the function returns TPM_RC_VALUE.
//
// The 'dSize' parameter is used as an input to indicate the size available in the
// buffer.

// If insufficient space is available, the size is not changed and the return code
// is TPM_RC_VALUE.
//
//  Return Type: TPM_RC
//      TPM_RC_VALUE        the value to decode was larger than the modulus, or
//                          the padding is wrong or the buffer to receive the
//                          results is too small
//
//
static TPM_RC OaepDecode(
			 TPM2B*       dataOut,  // OUT: the recovered data
			 TPM_ALG_ID   hashAlg,  // IN: algorithm to use for padding
			 const TPM2B* label,    // IN: null-terminated string (may be NULL)
			 TPM2B*       padded    // IN: the padded data
			 )
{
    UINT32 i;
    BYTE   seedMask[MAX_DIGEST_SIZE];
    UINT32 hLen = CryptHashGetDigestSize(hashAlg);

    BYTE   mask[MAX_RSA_KEY_BYTES];
    BYTE*  pp;
    BYTE*  pm;
    TPM_RC retVal = TPM_RC_SUCCESS;

    // Strange size (anything smaller can't be an OAEP padded block)
    // Also check for no leading 0
    if((padded->size < (unsigned)((2 * hLen) + 2)) || (padded->buffer[0] != 0))
	ERROR_EXIT(TPM_RC_VALUE);
    // Use the hash size to determine what to put through MGF1 in order
    // to recover the seedMask
    CryptMGF_KDF(hLen,
		 seedMask,
		 hashAlg,
		 padded->size - hLen - 1,
		 &padded->buffer[hLen + 1],
		 0);

    // Recover the seed into seedMask
    pAssert(hLen <= sizeof(seedMask));
    pp = &padded->buffer[1];
    pm = seedMask;
    for(i = hLen; i > 0; i--)
	*pm++ ^= *pp++;

    // Use the seed to generate the data mask
    CryptMGF_KDF(padded->size - hLen - 1, mask, hashAlg, hLen, seedMask, 0);

    // Use the mask generated from seed to recover the padded data
    pp = &padded->buffer[hLen + 1];
    pm = mask;
    for(i = (padded->size - hLen - 1); i > 0; i--)
	*pm++ ^= *pp++;

    // Make sure that the recovered data has the hash of the label
    // Put trial value in the seed mask
    if((CryptHashBlock(hashAlg, label->size, (BYTE*)label->buffer, hLen, seedMask))
       != hLen)
	FAIL(FATAL_ERROR_INTERNAL);
    if(memcmp(seedMask, mask, hLen) != 0)
	ERROR_EXIT(TPM_RC_VALUE);

    // find the start of the data
    pm = &mask[hLen];
    for(i = (UINT32)padded->size - (2 * hLen) - 1; i > 0; i--)
	{
	    if(*pm++ != 0)
		break;
	}
    // If we ran out of data or didn't end with 0x01, then return an error
    if(i == 0 || pm[-1] != 0x01)
	ERROR_EXIT(TPM_RC_VALUE);

    // pm should be pointing at the first part of the data
    // and i is one greater than the number of bytes to move
    i--;
    if(i > dataOut->size)
	// Special exit to preserve the size of the output buffer
	return TPM_RC_VALUE;
    memcpy(dataOut->buffer, pm, i);
    dataOut->size = (UINT16)i;
 Exit:
    if(retVal != TPM_RC_SUCCESS)
	dataOut->size = 0;
    return retVal;
}

//*** PKCS1v1_5Encode()
// This function performs the encoding for RSAES-PKCS1-V1_5-ENCRYPT as defined in
// PKCS#1V2.1
//  Return Type: TPM_RC
//      TPM_RC_VALUE     message size is too large
//
static TPM_RC RSAES_PKCS1v1_5Encode(TPM2B* padded,   // OUT: the pad data
				    TPM2B* message,  // IN: the message being padded
				    RAND_STATE* rand)
{
    UINT32 ps = padded->size - message->size - 3;
    //
    if(message->size > padded->size - 11)
	return TPM_RC_VALUE;
    // move the message to the end of the buffer
    memcpy(&padded->buffer[padded->size - message->size],
	   message->buffer,
	   message->size);
    // Set the first byte to 0x00 and the second to 0x02
    padded->buffer[0] = 0;
    padded->buffer[1] = 2;

    // Fill with random bytes
    DRBG_Generate(rand, &padded->buffer[2], (UINT16)ps);
    if(g_inFailureMode)
	return TPM_RC_FAILURE;

    // Set the delimiter for the random field to 0
    padded->buffer[2 + ps] = 0;

    // Now, the only messy part. Make sure that all the 'ps' bytes are non-zero
    // In this implementation, use the value of the current index
    for(ps++; ps > 1; ps--)
	{
	    if(padded->buffer[ps] == 0)
		padded->buffer[ps] = 0x55;  // In the < 0.5% of the cases that the
	    // random value is 0, just pick a value to
	    // put into the spot.
	}
    return TPM_RC_SUCCESS;
}

//*** RSAES_Decode()
// This function performs the decoding for RSAES-PKCS1-V1_5-ENCRYPT as defined in
// PKCS#1V2.1
//
//  Return Type: TPM_RC
//      TPM_RC_FAIL      decoding error or results would no fit into provided buffer
//
static TPM_RC RSAES_Decode(TPM2B* message,  // OUT: the recovered message
			   TPM2B* coded     // IN: the encoded message
			   )
{
    BOOL   fail = FALSE;
    UINT16 pSize;

    fail = (coded->size < 11);
    fail = (coded->buffer[0] != 0x00) | fail;
    fail = (coded->buffer[1] != 0x02) | fail;
    for(pSize = 2; pSize < coded->size; pSize++)
	{
	    if(coded->buffer[pSize] == 0)
		break;
	}
    pSize++;

    // Make sure that pSize has not gone over the end and that there are at least 8
    // bytes of pad data.
    fail = (pSize > coded->size) | fail;
    fail = ((pSize - 2) <= 8) | fail;
    if((message->size < (UINT16)(coded->size - pSize)) || fail)
	return TPM_RC_VALUE;
    message->size = coded->size - pSize;
    memcpy(message->buffer, &coded->buffer[pSize], coded->size - pSize);
    return TPM_RC_SUCCESS;
}
#endif                                  // libtpms added

//*** CryptRsaPssSaltSize()
// This function computes the salt size used in PSS. It is broken out so that
// the X509 code can get the same value that is used by the encoding function in this
// module.
INT16
CryptRsaPssSaltSize(INT16 hashSize, INT16 outSize)
{
    INT16 saltSize;
    //
    // (Mask Length) = (outSize - hashSize - 1);
    // Max saltSize is (Mask Length) - 1
    saltSize = (outSize - hashSize - 1) - 1;
    // Use the maximum salt size allowed by FIPS 186-4
    if(saltSize > hashSize)
	saltSize = hashSize;
    else if(saltSize < 0)
	saltSize = 0;
    return saltSize;
}

#if !USE_OPENSSL_FUNCTIONS_RSA         // libtpms added
//*** PssEncode()
// This function creates an encoded block of data that is the size of modulus.
// The function uses the maximum salt size that will fit in the encoded block.
//
//  Returns TPM_RC_SUCCESS or goes into failure mode.
static TPM_RC PssEncode(TPM2B*      out,      // OUT: the encoded buffer
			TPM_ALG_ID  hashAlg,  // IN: hash algorithm for the encoding
			TPM2B*      digest,   // IN: the digest
			RAND_STATE* rand      // IN: random number source
			)
{
    UINT32     hLen = CryptHashGetDigestSize(hashAlg);
    BYTE       salt[MAX_RSA_KEY_BYTES - 1];
    UINT16     saltSize;
    BYTE*      ps = salt;
    BYTE*      pOut;
    UINT16     mLen;
    HASH_STATE hashState;

    // These are fatal errors indicating bad TPM firmware
    pAssert(out != NULL && hLen > 0 && digest != NULL);

    // Get the size of the mask
    mLen = (UINT16)(out->size - hLen - 1);

    // Set the salt size
    saltSize = CryptRsaPssSaltSize((INT16)hLen, (INT16)out->size);

    //using eOut for scratch space
    // Set the first 8 bytes to zero
    pOut = out->buffer;
    memset(pOut, 0, 8);

    // Get set the salt
    DRBG_Generate(rand, salt, saltSize);
    if(g_inFailureMode)
	return TPM_RC_FAILURE;

    // Create the hash of the pad || input hash || salt
    CryptHashStart(&hashState, hashAlg);
    CryptDigestUpdate(&hashState, 8, pOut);
    CryptDigestUpdate2B(&hashState, digest);
    CryptDigestUpdate(&hashState, saltSize, salt);
    CryptHashEnd(&hashState, hLen, &pOut[out->size - hLen - 1]);

    // Create a mask
    if(CryptMGF_KDF(mLen, pOut, hashAlg, hLen, &pOut[mLen], 0) != mLen)
	FAIL(FATAL_ERROR_INTERNAL);

    // Since this implementation uses key sizes that are all even multiples of
    // 8, just need to make sure that the most significant bit is CLEAR
    *pOut &= 0x7f;

    // Before we mess up the pOut value, set the last byte to 0xbc
    pOut[out->size - 1] = 0xbc;

    // XOR a byte of 0x01 at the position just before where the salt will be XOR'ed
    pOut = &pOut[mLen - saltSize - 1];
    *pOut++ ^= 0x01;

    // XOR the salt data into the buffer
    for(; saltSize > 0; saltSize--)
	*pOut++ ^= *ps++;

    // and we are done
    return TPM_RC_SUCCESS;
}

//*** PssDecode()
// This function checks that the PSS encoded block was built from the
// provided digest. If the check is successful, TPM_RC_SUCCESS is returned.
// Any other value indicates an error.
//
// This implementation of PSS decoding is intended for the reference TPM
// implementation and is not at all generalized.  It is used to check
// signatures over hashes and assumptions are made about the sizes of values.
// Those assumptions are enforce by this implementation.
// This implementation does allow for a variable size salt value to have been
// used by the creator of the signature.
//
//  Return Type: TPM_RC
//      TPM_RC_SCHEME       'hashAlg' is not a supported hash algorithm
//      TPM_RC_VALUE         decode operation failed
//
static TPM_RC PssDecode(
			TPM_ALG_ID hashAlg,  // IN: hash algorithm to use for the encoding
			TPM2B*     dIn,      // In: the digest to compare
			TPM2B*     eIn       // IN: the encoded data
			)
{
    UINT32     hLen = CryptHashGetDigestSize(hashAlg);
    BYTE       mask[MAX_RSA_KEY_BYTES];
    BYTE*      pm = mask;
    BYTE*      pe;
    BYTE       pad[8] = {0};
    UINT32     i;
    UINT32     mLen;
    BYTE       fail;
    TPM_RC     retVal = TPM_RC_SUCCESS;
    HASH_STATE hashState;

    // These errors are indicative of failures due to programmer error
    pAssert(dIn != NULL && eIn != NULL);
    pe = eIn->buffer;

    // check the hash scheme
    if(hLen == 0)
	ERROR_EXIT(TPM_RC_SCHEME);

    // most significant bit must be zero
    fail = pe[0] & 0x80;

    // last byte must be 0xbc
    fail |= pe[eIn->size - 1] ^ 0xbc;

    // Use the hLen bytes at the end of the buffer to generate a mask
    // Doesn't start at the end which is a flag byte
    mLen = eIn->size - hLen - 1;
    CryptMGF_KDF(mLen, mask, hashAlg, hLen, &pe[mLen], 0);

    // Clear the MSO of the mask to make it consistent with the encoding.
    mask[0] &= 0x7F;

    pAssert(mLen <= sizeof(mask));
    // XOR the data into the mask to recover the salt. This sequence
    // advances eIn so that it will end up pointing to the seed data
    // which is the hash of the signature data
    for(i = mLen; i > 0; i--)
	*pm++ ^= *pe++;

    // Find the first byte of 0x01 after a string of all 0x00
    for(pm = mask, i = mLen; i > 0; i--)
	{
	    if(*pm == 0x01)
		break;
	    else
		fail |= *pm++;
	}
    // i should not be zero
    fail |= (i == 0);

    // if we have failed, will continue using the entire mask as the salt value so
    // that the timing attacks will not disclose anything (I don't think that this
    // is a problem for TPM applications but, usually, we don't fail so this
    // doesn't cost anything).
    if(fail)
	{
	    i  = mLen;
	    pm = mask;
	}
    else
	{
	    pm++;
	    i--;
	}
    // i contains the salt size and pm points to the salt. Going to use the input
    // hash and the seed to recreate the hash in the lower portion of eIn.
    CryptHashStart(&hashState, hashAlg);

    // add the pad of 8 zeros
    CryptDigestUpdate(&hashState, 8, pad);

    // add the provided digest value
    CryptDigestUpdate(&hashState, dIn->size, dIn->buffer);

    // and the salt
    CryptDigestUpdate(&hashState, i, pm);

    // get the result
    fail |= (CryptHashEnd(&hashState, hLen, mask) != hLen);

    // Compare all bytes
    for(pm = mask; hLen > 0; hLen--)
	// don't use fail = because that could skip the increment and compare
	// operations after the first failure and that gives away timing
	// information.
	fail |= *pm++ ^ *pe++;

    retVal = (fail != 0) ? TPM_RC_VALUE : TPM_RC_SUCCESS;
 Exit:
    return retVal;
}

//*** MakeDerTag()
// Construct the DER value that is used in RSASSA
//  Return Type: INT16
//   > 0        size of value
//   <= 0       no hash exists
INT16
MakeDerTag(TPM_ALG_ID hashAlg, INT16 sizeOfBuffer, BYTE* buffer)
{
    //    0x30, 0x31,       // SEQUENCE (2 elements) 1st
    //        0x30, 0x0D,   // SEQUENCE (2 elements)
    //            0x06, 0x09,   // HASH OID
    //                0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    //             0x05, 0x00,  // NULL
    //        0x04, 0x20  //  OCTET STRING
    HASH_DEF* info = CryptGetHashDef(hashAlg);
    INT16     oidSize;
    // If no OID, can't do encode
    GOTO_ERROR_UNLESS(info != NULL);
    oidSize = 2 + (info->OID)[1];
    // make sure this fits in the buffer
    GOTO_ERROR_UNLESS(sizeOfBuffer >= (oidSize + 8));
    *buffer++ = 0x30;  // 1st SEQUENCE
    // Size of the 1st SEQUENCE is 6 bytes + size of the hash OID + size of the
    // digest size
    *buffer++ = (BYTE)(6 + oidSize + info->digestSize);  //
    *buffer++ = 0x30;                                    // 2nd SEQUENCE
    // size is 4 bytes of overhead plus the side of the OID
    *buffer++ = (BYTE)(2 + oidSize);
    MemoryCopy(buffer, info->OID, oidSize);
    buffer += oidSize;
    *buffer++ = 0x05;  // Add a NULL
    *buffer++ = 0x00;

    *buffer++ = 0x04;
    *buffer++ = (BYTE)(info->digestSize);
    return oidSize + 8;
 Error:
    return 0;
}

//*** RSASSA_Encode()
// Encode a message using PKCS1v1.5 method.
//
//  Return Type: TPM_RC
//      TPM_RC_SCHEME       'hashAlg' is not a supported hash algorithm
//      TPM_RC_SIZE         'eOutSize' is not large enough
//      TPM_RC_VALUE        'hInSize' does not match the digest size of hashAlg
static TPM_RC RSASSA_Encode(TPM2B* pOut,  // IN:OUT on in, the size of the public key
			    //        on out, the encoded area
			    TPM_ALG_ID hashAlg,  // IN: hash algorithm for PKCS1v1_5
			    TPM2B*     hIn       // IN: digest value to encode
			    )
{
    BYTE   DER[20];
    BYTE*  der     = DER;
    INT32  derSize = MakeDerTag(hashAlg, sizeof(DER), DER);
    BYTE*  eOut;
    INT32  fillSize;
    TPM_RC retVal = TPM_RC_SUCCESS;

    // Can't use this scheme if the algorithm doesn't have a DER string defined.
    if(derSize == 0)
	ERROR_EXIT(TPM_RC_SCHEME);

    // If the digest size of 'hashAl' doesn't match the input digest size, then
    // the DER will misidentify the digest so return an error
    if(CryptHashGetDigestSize(hashAlg) != hIn->size)
	ERROR_EXIT(TPM_RC_VALUE);
    fillSize = pOut->size - derSize - hIn->size - 3;
    eOut     = pOut->buffer;

    // Make sure that this combination will fit in the provided space
    if(fillSize < 8)
	ERROR_EXIT(TPM_RC_SIZE);

    // Start filling
    *eOut++ = 0;  // initial byte of zero
    *eOut++ = 1;  // byte of 0x01
    for(; fillSize > 0; fillSize--)
	*eOut++ = 0xff;  // bunch of 0xff
    *eOut++ = 0;         // another 0
    for(; derSize > 0; derSize--)
	*eOut++ = *der++;  // copy the DER
    der = hIn->buffer;
    for(fillSize = hIn->size; fillSize > 0; fillSize--)
	*eOut++ = *der++;  // copy the hash
 Exit:
    return retVal;
}

//*** RSASSA_Decode()
// This function performs the RSASSA decoding of a signature.
//
//  Return Type: TPM_RC
//      TPM_RC_VALUE          decode unsuccessful
//      TPM_RC_SCHEME        'haslAlg' is not supported
//
static TPM_RC RSASSA_Decode(
			    TPM_ALG_ID hashAlg,  // IN: hash algorithm to use for the encoding
			    TPM2B*     hIn,      // In: the digest to compare
			    TPM2B*     eIn       // IN: the encoded data
			    )
{
    BYTE   fail;
    BYTE   DER[20];
    BYTE*  der     = DER;
    INT32  derSize = MakeDerTag(hashAlg, sizeof(DER), DER);
    BYTE*  pe;
    INT32  hashSize = CryptHashGetDigestSize(hashAlg);
    INT32  fillSize;
    TPM_RC retVal;
    BYTE*  digest;
    UINT16 digestSize;

    pAssert(hIn != NULL && eIn != NULL);
    pe = eIn->buffer;

    // Can't use this scheme if the algorithm doesn't have a DER string
    // defined or if the provided hash isn't the right size
    if(derSize == 0 || (unsigned)hashSize != hIn->size)
	ERROR_EXIT(TPM_RC_SCHEME);

    // Make sure that this combination will fit in the provided space
    // Since no data movement takes place, can just walk though this
    // and accept nearly random values. This can only be called from
    // CryptValidateSignature() so eInSize is known to be in range.
    fillSize = eIn->size - derSize - hashSize - 3;

    // Start checking (fail will become non-zero if any of the bytes do not have
    // the expected value.
    fail = *pe++;       // initial byte of zero
    fail |= *pe++ ^ 1;  // byte of 0x01
    for(; fillSize > 0; fillSize--)
	fail |= *pe++ ^ 0xff;  // bunch of 0xff
    fail |= *pe++;             // another 0
    for(; derSize > 0; derSize--)
	fail |= *pe++ ^ *der++;  // match the DER
    digestSize = hIn->size;
    digest     = hIn->buffer;
    for(; digestSize > 0; digestSize--)
	fail |= *pe++ ^ *digest++;  // match the hash
    retVal = (fail != 0) ? TPM_RC_VALUE : TPM_RC_SUCCESS;
 Exit:
    return retVal;
}
#endif                                 // libtpms added

//** Externally Accessible Functions

//*** CryptRsaSelectScheme()
// This function is used by TPM2_RSA_Decrypt and TPM2_RSA_Encrypt.  It sets up
// the rules to select a scheme between input and object default.
// This function assume the RSA object is loaded.
// If a default scheme is defined in object, the default scheme should be chosen,
// otherwise, the input scheme should be chosen.
// In the case that both the object and 'scheme' are not TPM_ALG_NULL, then
// if the schemes are the same, the input scheme will be chosen.
// if the scheme are not compatible, a NULL pointer will be returned.
//
// The return pointer may point to a TPM_ALG_NULL scheme.
TPMT_RSA_DECRYPT* CryptRsaSelectScheme(
				       TPMI_DH_OBJECT    rsaHandle,  // IN: handle of an RSA key
				       TPMT_RSA_DECRYPT* scheme      // IN: a sign or decrypt scheme
				       )
{
    OBJECT*           rsaObject;
    TPMT_ASYM_SCHEME* keyScheme;
    TPMT_RSA_DECRYPT* retVal = NULL;

    // Get sign object pointer
    rsaObject = HandleToObject(rsaHandle);
    keyScheme = &rsaObject->publicArea.parameters.asymDetail.scheme;

    // if the default scheme of the object is TPM_ALG_NULL, then select the
    // input scheme
    if(keyScheme->scheme == TPM_ALG_NULL)
	{
	    retVal = scheme;
	}
    // if the object scheme is not TPM_ALG_NULL and the input scheme is
    // TPM_ALG_NULL, then select the default scheme of the object.
    else if(scheme->scheme == TPM_ALG_NULL)
	{
	    // if input scheme is NULL
	    retVal = (TPMT_RSA_DECRYPT*)keyScheme;
	}
    // get here if both the object scheme and the input scheme are
    // not TPM_ALG_NULL. Need to insure that they are the same.
    // IMPLEMENTATION NOTE: This could cause problems if future versions have
    // schemes that have more values than just a hash algorithm. A new function
    // (IsSchemeSame()) might be needed then.
    else if(keyScheme->scheme == scheme->scheme
	    && keyScheme->details.anySig.hashAlg == scheme->details.anySig.hashAlg)
	{
	    retVal = scheme;
	}
    // two different, incompatible schemes specified will return NULL
    return retVal;
}

//*** CryptRsaLoadPrivateExponent()
// This function is called to generate the private exponent of an RSA key.
//  Return Type: TPM_RC
//      TPM_RC_BINDING      public and private parts of 'rsaKey' are not matched
TPM_RC
CryptRsaLoadPrivateExponent(TPMT_PUBLIC* publicArea, TPMT_SENSITIVE* sensitive,
			    OBJECT                  *rsaKey	// libtpms added: Should only be NULL
				// in case this function is called for parameter 'testing', such as by
				// TPM2_Import() -> ObjectLoad().
			   )
{
    if(!rsaKey || !rsaKey->attributes.privateExp)			// libtpms changed: still keep rsaKey for privateExp flag
	{
	    if((sensitive->sensitive.rsa.t.size * 2) == publicArea->unique.rsa.t.size)
		{
		    NEW_PRIVATE_EXPONENT(Z);
		    CRYPT_RSA_INITIALIZED(bnN, &publicArea->unique.rsa);
		    CRYPT_RSA_VAR(bnQr);
		    CRYPT_INT_VAR(bnE, RADIX_BITS);

		    TPM_DO_SELF_TEST(TPM_ALG_NULL);

		    GOTO_ERROR_UNLESS((sensitive->sensitive.rsa.t.size * 2)
				      == publicArea->unique.rsa.t.size);
		    // Initialize the exponent
		    ExtMath_SetWord(bnE, publicArea->parameters.rsaDetail.exponent);
		    if(ExtMath_IsZero(bnE))
			ExtMath_SetWord(bnE, RSA_DEFAULT_PUBLIC_EXPONENT);
		    // Convert first prime to 2B
		    GOTO_ERROR_UNLESS(
				      TpmMath_IntFrom2B(Z->P, &sensitive->sensitive.rsa.b) != NULL);

		    // Find the second prime by division. This uses 'bQ' rather than Z->Q
		    // because the division could make the quotient larger than a prime during
		    // some intermediate step.
		    GOTO_ERROR_UNLESS(ExtMath_Divide(Z->Q, bnQr, bnN, Z->P));
		    GOTO_ERROR_UNLESS(ExtMath_IsZero(bnQr));
		    // Compute the private exponent and return it if found
		    if (rsaKey) {					// libtpms added begin
			RsaInitializeExponentOld(&rsaKey->privateExponent);
			ExtMath_Copy((Crypt_Int *)&rsaKey->privateExponent.Q, Z->Q);	// preserve Q
		    }							// libtpms added end
		    GOTO_ERROR_UNLESS(ComputePrivateExponent(bnE, Z));
		    // GOTO_ERROR_UNLESS(PackExponent(&sensitive->sensitive.rsa, Z)); // libtpms: never pack/unpack

		    if (rsaKey)	{					// libtpms added begin
			RsaSetExponentOld(&rsaKey->privateExponent, Z);	// preserve dP, dQ, qInv
		    }							// libtpms added end
		}
	    else
		assert(FALSE);						// libtpms changed begin
	    if (rsaKey)
		rsaKey->attributes.privateExp = TRUE;
	}
    return TPM_RC_SUCCESS;
 Error:
    return TPM_RC_BINDING;
}

static TPM_RC								// libtpms added begin
CryptRSAPairwiseConsistencyTest(OBJECT *key)
{
    TPM2B_PUBLIC_KEY_RSA enc = {
        .t.size = 0,
    };
    TPM2B_PUBLIC_KEY_RSA out = {
        .t.size = sizeof(out.t.buffer),
    };
    TPM2B_TYPE(PLAIN, 20);
    TPM2B_PLAIN          plain = {
        .t.size = sizeof(plain.t.buffer),
    };
    TPM2B_LABEL          label = {{5, {"label"}}};
    TPMT_RSA_DECRYPT     scheme = {
	.scheme               = TPM_ALG_OAEP,
	.details.oaep.hashAlg = TPM_ALG_SHA256,
    };
    TPMT_SIGNATURE       sigOut = {
	.sigAlg                = TPM_ALG_RSAPSS,
	.signature.rsapss.hash = TPM_ALG_SHA256,
    };
    TPM2B_DIGEST         digest = {
        .t.size = SHA256_DIGEST_SIZE,
    };
    TPM_RC               retVal;

    /* encrypt + decrypt */
    DRBG_Generate(NULL, plain.t.buffer, plain.t.size);
    retVal = CryptRsaEncrypt(&enc, &plain.b, key, &scheme, &label.b, NULL);
    if (retVal)
	return retVal;
    if (enc.b.size == plain.b.size ||
        enc.b.size != key->publicArea.unique.rsa.t.size)
        return TPM_RC_FAILURE;

    retVal = CryptRsaDecrypt(&out.b, &enc.b, key, &scheme, &label.b);
    if (retVal)
	return retVal;
    if (out.b.size != plain.b.size ||
	memcmp(out.b.buffer, plain.b.buffer, plain.b.size) != 0)
	return TPM_RC_FAILURE;

    /* sign + verify */
    DRBG_Generate(NULL, digest.t.buffer, digest.t.size);
    retVal = CryptRsaSign(&sigOut, key, &digest, NULL);
    if (retVal)
	return retVal;
    return CryptRsaValidateSignature(&sigOut, key, &digest);
}									// libtpms added end

#if !USE_OPENSSL_FUNCTIONS_RSA         // libtpms added

//*** CryptRsaEncrypt()
// This is the entry point for encryption using RSA. Encryption is
// use of the public exponent. The padding parameter determines what
// padding will be used.
//
// The 'cOutSize' parameter must be at least as large as the size of the key.
//
// If the padding is RSA_PAD_NONE, 'dIn' is treated as a number. It must be
// lower in value than the key modulus.
// NOTE: If dIn has fewer bytes than cOut, then we don't add low-order zeros to
//       dIn to make it the size of the RSA key for the call to RSAEP. This is
//       because the high order bytes of dIn might have a numeric value that is
//       greater than the value of the key modulus. If this had low-order zeros
//       added, it would have a numeric value larger than the modulus even though
//       it started out with a lower numeric value.
//
//  Return Type: TPM_RC
//      TPM_RC_VALUE     'cOutSize' is too small (must be the size
//                        of the modulus)
//      TPM_RC_SCHEME    'padType' is not a supported scheme
//
LIB_EXPORT TPM_RC CryptRsaEncrypt(
				  TPM2B_PUBLIC_KEY_RSA* cOut,    // OUT: the encrypted data
				  TPM2B*                dIn,     // IN: the data to encrypt
				  OBJECT*               key,     // IN: the key used for encryption
				  TPMT_RSA_DECRYPT*     scheme,  // IN: the type of padding and hash
				  //     if needed
				  const TPM2B* label,            // IN: in case it is needed
				  RAND_STATE*  rand              // IN: random number generator
				  //     state (mostly for testing)
				  )
{
    TPM_RC               retVal = TPM_RC_SUCCESS;
    TPM2B_PUBLIC_KEY_RSA dataIn;
    //
    // if the input and output buffers are the same, copy the input to a scratch
    // buffer so that things don't get messed up.
    if(dIn == &cOut->b)
	{
	    MemoryCopy2B(&dataIn.b, dIn, sizeof(dataIn.t.buffer));
	    dIn = &dataIn.b;
	}
    // All encryption schemes return the same size of data
    cOut->t.size = key->publicArea.unique.rsa.t.size;
    TPM_DO_SELF_TEST(scheme->scheme);

    switch(scheme->scheme)
	{
	  case TPM_ALG_NULL:  // 'raw' encryption
	      {
		  INT32 i;
		  INT32 dSize = dIn->size;
		  // dIn can have more bytes than cOut as long as the extra bytes
		  // are zero. Note: the more significant bytes of a number in a byte
		  // buffer are the bytes at the start of the array.
		  if (RuntimeProfileRequiresAttributeFlags(&g_RuntimeProfile,	// libtpms added begin
							   RUNTIME_ATTRIBUTE_NO_UNPADDED_ENCRYPTION))
		      ERROR_EXIT(TPM_RC_SCHEME);				// libtpms added end
		  for(i = 0; (i < dSize) && (dIn->buffer[i] == 0); i++)
		      ;
		  dSize -= i;
		  if(dSize > cOut->t.size)
		      ERROR_EXIT(TPM_RC_VALUE);
		  // Pad cOut with zeros if dIn is smaller
		  memset(cOut->t.buffer, 0, cOut->t.size - dSize);
		  // And copy the rest of the value
		  memcpy(&cOut->t.buffer[cOut->t.size - dSize], &dIn->buffer[i], dSize);

		  // If the size of dIn is the same as cOut dIn could be larger than
		  // the modulus. If it is, then RSAEP() will catch it.
	      }
	      break;
	  case TPM_ALG_RSAES:
	    retVal = RSAES_PKCS1v1_5Encode(&cOut->b, dIn, rand);
	    break;
	  case TPM_ALG_OAEP:
	    retVal =
		OaepEncode(&cOut->b, scheme->details.oaep.hashAlg, label, dIn, rand);
	    break;
	  default:
	    ERROR_EXIT(TPM_RC_SCHEME);
	    break;
	}
    // All the schemes that do padding will come here for the encryption step
    // Check that the Encoding worked
    if(retVal == TPM_RC_SUCCESS)
	// Padding OK so do the encryption
	retVal = RSAEP(&cOut->b, key);
 Exit:
    return retVal;
}

//*** CryptRsaDecrypt()
// This is the entry point for decryption using RSA. Decryption is
// use of the private exponent. The 'padType' parameter determines what
// padding was used.
//
//  Return Type: TPM_RC
//      TPM_RC_SIZE        'cInSize' is not the same as the size of the public
//                          modulus of 'key'; or numeric value of the encrypted
//                          data is greater than the modulus
//      TPM_RC_VALUE       'dOutSize' is not large enough for the result
//      TPM_RC_SCHEME      'padType' is not supported
//
LIB_EXPORT TPM_RC CryptRsaDecrypt(
				  TPM2B*            dOut,    // OUT: the decrypted data
				  TPM2B*            cIn,     // IN: the data to decrypt
				  OBJECT*           key,     // IN: the key to use for decryption
				  TPMT_RSA_DECRYPT* scheme,  // IN: the padding scheme
				  const TPM2B*      label    // IN: in case it is needed for the scheme
				  )
{
    TPM_RC retVal;

    // Make sure that the necessary parameters are provided
    pAssert(cIn != NULL && dOut != NULL && key != NULL);

    // Size is checked to make sure that the encrypted value is the right size
    if(cIn->size != key->publicArea.unique.rsa.t.size)
	ERROR_EXIT(TPM_RC_SIZE);

    TPM_DO_SELF_TEST(scheme->scheme);

    // For others that do padding, do the decryption in place and then
    // go handle the decoding.
    retVal = RSADP(cIn, key);
    if(retVal == TPM_RC_SUCCESS)
	{
	    // Remove padding
	    switch(scheme->scheme)
		{
		  case TPM_ALG_NULL:
		    if (RuntimeProfileRequiresAttributeFlags(&g_RuntimeProfile,	// libtpms added begin
							     RUNTIME_ATTRIBUTE_NO_UNPADDED_ENCRYPTION))
			return TPM_RC_SCHEME;					// libtpms added end
		    if(dOut->size < cIn->size)
			return TPM_RC_VALUE;
		    MemoryCopy2B(dOut, cIn, dOut->size);
		    break;
		  case TPM_ALG_RSAES:
		    retVal = RSAES_Decode(dOut, cIn);
		    break;
		  case TPM_ALG_OAEP:
		    retVal = OaepDecode(dOut, scheme->details.oaep.hashAlg, label, cIn);
		    break;
		  default:
		    retVal = TPM_RC_SCHEME;
		    break;
		}
	}
 Exit:
    return retVal;
}

//*** CryptRsaSign()
// This function is used to generate an RSA signature of the type indicated in
// 'scheme'.
//
//  Return Type: TPM_RC
//      TPM_RC_SCHEME       'scheme' or 'hashAlg' are not supported
//      TPM_RC_VALUE        'hInSize' does not match 'hashAlg' (for RSASSA)
//
LIB_EXPORT TPM_RC CryptRsaSign(TPMT_SIGNATURE* sigOut,
			       OBJECT*         key,  // IN: key to use
			       TPM2B_DIGEST*   hIn,  // IN: the digest to sign
			       RAND_STATE* rand  // IN: the random number generator
			       //      to use (mostly for testing)
			       )
{
    TPM_RC retVal = TPM_RC_SUCCESS;
    UINT16 modSize;

    // parameter checks
    pAssert(sigOut != NULL && key != NULL && hIn != NULL);

    modSize = key->publicArea.unique.rsa.t.size;

    // for all non-null signatures, the size is the size of the key modulus
    sigOut->signature.rsapss.sig.t.size = modSize;

    TPM_DO_SELF_TEST(sigOut->sigAlg);

    switch(sigOut->sigAlg)
	{
	  case TPM_ALG_NULL:
	    sigOut->signature.rsapss.sig.t.size = 0;
	    return TPM_RC_SUCCESS;
	  case TPM_ALG_RSAPSS:
	    retVal = PssEncode(&sigOut->signature.rsapss.sig.b,
			       sigOut->signature.rsapss.hash,
			       &hIn->b,
			       rand);
	    break;
	  case TPM_ALG_RSASSA:
	    retVal = RSASSA_Encode(&sigOut->signature.rsassa.sig.b,
				   sigOut->signature.rsassa.hash,
				   &hIn->b);
	    break;
	  default:
	    retVal = TPM_RC_SCHEME;
	}
    if(retVal == TPM_RC_SUCCESS)
	{
	    // Do the encryption using the private key
	    retVal = RSADP(&sigOut->signature.rsapss.sig.b, key);
	}
    return retVal;
}

//*** CryptRsaValidateSignature()
// This function is used to validate an RSA signature. If the signature is valid
// TPM_RC_SUCCESS is returned. If the signature is not valid, TPM_RC_SIGNATURE is
// returned. Other return codes indicate either parameter problems or fatal errors.
//
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE    the signature does not check
//      TPM_RC_SCHEME       unsupported scheme or hash algorithm
//
LIB_EXPORT TPM_RC CryptRsaValidateSignature(
					    TPMT_SIGNATURE* sig,    // IN: signature
					    OBJECT*         key,    // IN: public modulus
					    TPM2B_DIGEST*   digest  // IN: The digest being validated
					    )
{
    TPM_RC retVal;
    //
    // Fatal programming errors
    pAssert(key != NULL && sig != NULL && digest != NULL);
    switch(sig->sigAlg)
	{
	  case TPM_ALG_RSAPSS:
	  case TPM_ALG_RSASSA:
	    break;
	  default:
	    return TPM_RC_SCHEME;
	}

    // Errors that might be caused by calling parameters
    if(sig->signature.rsassa.sig.t.size != key->publicArea.unique.rsa.t.size)
	ERROR_EXIT(TPM_RC_SIGNATURE);

    TPM_DO_SELF_TEST(sig->sigAlg);

    // Decrypt the block
    retVal = RSAEP(&sig->signature.rsassa.sig.b, key);
    if(retVal == TPM_RC_SUCCESS)
	{
	    switch(sig->sigAlg)
		{
		  case TPM_ALG_RSAPSS:
		    retVal = PssDecode(sig->signature.any.hashAlg,
				       &digest->b,
				       &sig->signature.rsassa.sig.b);
		    break;
		  case TPM_ALG_RSASSA:
		    retVal = RSASSA_Decode(sig->signature.any.hashAlg,
					   &digest->b,
					   &sig->signature.rsassa.sig.b);
		    break;
		  default:
		    return TPM_RC_SCHEME;
		}
	}
 Exit:
    return (retVal != TPM_RC_SUCCESS) ? TPM_RC_SIGNATURE : TPM_RC_SUCCESS;
}
#endif                                 // libtpms added

#  if SIMULATION && USE_RSA_KEY_CACHE
extern int s_rsaKeyCacheEnabled;
int        GetCachedRsaKey(
			   TPMT_PUBLIC* publicArea, TPMT_SENSITIVE* sensitive, RAND_STATE* rand);
#    define GET_CACHED_KEY(publicArea, sensitive, rand)			\
    (s_rsaKeyCacheEnabled && GetCachedRsaKey(publicArea, sensitive, rand))
#  else
#    define GET_CACHED_KEY(key, rand)
#  endif

//*** CryptRsaGenerateKey()
// Generate an RSA key from a provided seed
/*(See part 1 specification)
//  The formulation is:
//      KDFa(hash, seed, label, Name, Counter, bits)
//  Where:
//      hash        the nameAlg from the public template
//      seed        a seed (will be a primary seed for a primary key)
//      label       a distinguishing label including vendor ID and
//                  vendor-assigned part number for the TPM.
//      Name        the nameAlg from the template and the hash of the template
//                  using nameAlg.
//      Counter     a 32-bit integer that is incremented each time the KDF is
//                  called in order to produce a specific key. This value
//                  can be a 32-bit integer in host format and does not need
//                  to be put in canonical form.
//      bits        the number of bits needed for the key.
//  The following process is implemented to find a RSA key pair:
//  1. pick a random number with enough bits from KDFa as a prime candidate
//  2. set the first two significant bits and the least significant bit of the
//     prime candidate
//  3. check if the number is a prime. if not, pick another random number
//  4. Make sure the difference between the two primes are more than 2^104.
//     Otherwise, restart the process for the second prime
//  5. If the counter has reached its maximum but we still can not find a valid
//     RSA key pair, return an internal error. This is an artificial bound.
//     Other implementation may choose a smaller number to indicate how many
//     times they are willing to try.
*/
//  Return Type: TPM_RC
//      TPM_RC_CANCELED     operation was canceled
//      TPM_RC_RANGE        public exponent is not supported
//      TPM_RC_VALUE        could not find a prime using the provided parameters
LIB_EXPORT TPM_RC CryptRsaGenerateKey(
				      TPMT_PUBLIC*    publicArea,
				      TPMT_SENSITIVE* sensitive,
				      OBJECT*         rsaKey,      // libtpms added IN/OUT: The object structure in which the key is created.
				      RAND_STATE*     rand  // IN: if not NULL, the deterministic
				      //     RNG state
				      )
{
    UINT32 i;
    CRYPT_RSA_VAR(bnD);
    CRYPT_RSA_VAR(bnN);
    CRYPT_INT_WORD(bnPubExp);
    UINT32 e = publicArea->parameters.rsaDetail.exponent;
    int    keySizeInBits;
    TPM_RC retVal = TPM_RC_NO_RESULT;
    NEW_PRIVATE_EXPONENT(Z);
    //
    pAssert(ExtMath_IsZero(Z->Q)); // libtpms added: Z->Q must be Zero
    pAssert(publicArea == &rsaKey->publicArea && sensitive == &rsaKey->sensitive); // libtpms added: consistency check

    // Need to make sure that the caller did not specify an exponent that is
    // not supported
    e = publicArea->parameters.rsaDetail.exponent;
    if(e == 0)
	e = RSA_DEFAULT_PUBLIC_EXPONENT;
    else
	{
	    if(e < 65537)
		ERROR_EXIT(TPM_RC_RANGE);
	    // Check that e is prime
	    if(!IsPrimeInt(e))
		ERROR_EXIT(TPM_RC_RANGE);
	}
    ExtMath_SetWord(bnPubExp, e);

    // check for supported key size.
    keySizeInBits = publicArea->parameters.rsaDetail.keyBits;
    if(((keySizeInBits % 1024) != 0)
       || (keySizeInBits > MAX_RSA_KEY_BITS)  // this might be redundant, but...
       || (keySizeInBits == 0))
	ERROR_EXIT(TPM_RC_VALUE);

    // Set the prime size for instrumentation purposes
    INSTRUMENT_SET(PrimeIndex, PRIME_INDEX(keySizeInBits / 2));

#  if SIMULATION && USE_RSA_KEY_CACHE
    if(GET_CACHED_KEY(publicArea, sensitive, rand))
	return TPM_RC_SUCCESS;
#  endif

    // Make sure that key generation has been tested
    TPM_DO_SELF_TEST(TPM_ALG_NULL);
    // Need to initialize the privateExponent structure			// libtpms added begin
    RsaInitializeExponentOld(&rsaKey->privateExponent);
#if USE_OPENSSL_FUNCTIONS_RSA
    if (rand == NULL) {
        retVal = OpenSSLCryptRsaGenerateKey(rsaKey, e, keySizeInBits);
        goto pct;
    }
#endif									// libtpms added end

    // The prime is computed in P. When a new prime is found, Q is checked to
    // see if it is zero.  If so, P is copied to Q and a new P is found.
    // When both P and Q are non-zero, the modulus and
    // private exponent are computed and a trial encryption/decryption is
    // performed.  If the encrypt/decrypt fails, assume that at least one of the
    // primes is composite. Since we don't know which one, set Q to zero and start
    // over and find a new pair of primes.

    for(i = 1; (retVal == TPM_RC_NO_RESULT) && (i != 100); i++)
	{
	    if(_plat__IsCanceled())
		ERROR_EXIT(TPM_RC_CANCELED);

	    if(TpmRsa_GeneratePrimeForRSA(Z->P, keySizeInBits / 2, e, rand)
	       == TPM_RC_FAILURE)
		{
		    retVal = TPM_RC_FAILURE;
		    goto Exit;
		}

	    INSTRUMENT_INC(PrimeCounts[PrimeIndex]);

	    // If this is the second prime, make sure that it differs from the
	    // first prime by at least 2^100
	    if(ExtMath_IsZero(Z->Q))
		{
		    // copy p to q and compute another prime in p
		    ExtMath_Copy(Z->Q, Z->P);
		    continue;
		}
	    // Make sure that the difference is at least 100 bits. Need to do it this
	    // way because the big numbers are only positive values
	    if(ExtMath_UnsignedCmp(Z->P, Z->Q) < 0)
		ExtMath_Subtract(bnD, Z->Q, Z->P);
	    else
		ExtMath_Subtract(bnD, Z->P, Z->Q);
	    if(ExtMath_MostSigBitNum(bnD) < 100)
		continue;

	    //Form the public modulus and set the unique value
	    ExtMath_Multiply(bnN, Z->P, Z->Q);
	    TpmMath_IntTo2B(
			    bnN, &publicArea->unique.rsa.b, (NUMBYTES)BITS_TO_BYTES(keySizeInBits));
	    // Make sure everything came out right. The MSb of the values must be one
	    if(((publicArea->unique.rsa.t.buffer[0] & 0x80) == 0)
	       || (publicArea->unique.rsa.t.size
		   != (NUMBYTES)BITS_TO_BYTES(keySizeInBits)))
		FAIL(FATAL_ERROR_INTERNAL);

	    // Add the prime to the sensitive area		// libtpms added begin
	    TpmMath_IntTo2B(Z->P, &sensitive->sensitive.rsa.b,
			    (NUMBYTES)BITS_TO_BYTES(keySizeInBits) / 2);	// libtpms added end

	    ExtMath_Copy((Crypt_Int*)&rsaKey->privateExponent.Q, Z->Q);	// libtpms added: preserve Q
	    // Make sure that we can form the private exponent values
	    if(ComputePrivateExponent(bnPubExp, Z) != TRUE)
		{
		    // If ComputePrivateExponent could not find an inverse for
		    // Q, then copy P and recompute P. This might
		    // cause both to be recomputed if P is also zero
		    if(ExtMath_IsZero(Z->Q))
			ExtMath_Copy(Z->Q, Z->P);
		    continue;
		}
	    RsaSetExponentOld(&rsaKey->privateExponent, Z);	// libtpms added: preserve dP, dQ, qInv

	    // Pack the private exponent into the sensitive area
	    // PackExponent(&sensitive->sensitive.rsa, Z);	// libtpms changed: never pack
	    // Make sure everything came out right. The MSb of the values must be one
	    if(((publicArea->unique.rsa.t.buffer[0] & 0x80) == 0)
	       || ((sensitive->sensitive.rsa.t.buffer[0] & 0x80) == 0))
		FAIL(FATAL_ERROR_INTERNAL);

	    retVal = TPM_RC_SUCCESS;
	    // Do a trial encryption decryption if this is a signing key
	    if(IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
		{
		    CRYPT_RSA_VAR(temp1);
		    CRYPT_RSA_VAR(temp2);
		    TpmMath_GetRandomInRange(temp1, bnN, rand);

		    // Encrypt with public exponent...
		    ExtMath_ModExp(temp2, temp1, bnPubExp, bnN);
		    // ...  then decrypt with private exponent
		    RsaPrivateKeyOp(temp2, Z);

		    // If the starting and ending values are not the same,
		    // start over )-;
		    if(ExtMath_UnsignedCmp(temp2, temp1) != 0)
			{
			    ExtMath_SetWord(Z->Q, 0);
			    retVal = TPM_RC_NO_RESULT;
			}
		}
	}
 Exit:
    if(retVal == TPM_RC_SUCCESS)
	rsaKey->attributes.privateExp = SET;

#if USE_OPENSSL_FUNCTIONS_RSA			// libtpms added begin
 pct:
#endif
    if(retVal == TPM_RC_SUCCESS &&
       RuntimeProfileRequiresAttributeFlags(&g_RuntimeProfile,
                                            RUNTIME_ATTRIBUTE_PAIRWISE_CONSISTENCY_TEST)) {
	retVal = CryptRSAPairwiseConsistencyTest(rsaKey);
	if (retVal)
	    retVal = TPM_RC_FAILURE;
    }						// libtpms added end
    return retVal;
}

#if USE_OPENSSL_FUNCTIONS_RSA          // libtpms added begin
LIB_EXPORT TPM_RC
CryptRsaEncrypt(
		TPM2B_PUBLIC_KEY_RSA        *cOut,          // OUT: the encrypted data
		TPM2B                       *dIn,           // IN: the data to encrypt
		OBJECT                      *key,           // IN: the key used for encryption
		TPMT_RSA_DECRYPT            *scheme,        // IN: the type of padding and hash
		//     if needed
		const TPM2B                 *label,         // IN: in case it is needed
		RAND_STATE                  *rand           // IN: random number generator
		//     state (mostly for testing)
		)
{
    TPM_RC                       retVal;
    TPM2B_PUBLIC_KEY_RSA         dataIn;
    TPM2B_PUBLIC_KEY_RSA         scratch;
    size_t                       outlen;
    EVP_PKEY                    *pkey = NULL;
    EVP_PKEY_CTX                *ctx = NULL;
    const EVP_MD                *md;
    const char                  *digestname;
    unsigned char               *tmp = NULL;
    //
    // if the input and output buffers are the same, copy the input to a scratch
    // buffer so that things don't get messed up.
    if(dIn == &cOut->b)
	{
	    MemoryCopy2B(&dataIn.b, dIn, sizeof(dataIn.t.buffer));
	    dIn = &dataIn.b;
	}
    // All encryption schemes return the same size of data
    pAssert(sizeof(cOut->t.buffer) >= key->publicArea.unique.rsa.t.size);
    cOut->t.size = key->publicArea.unique.rsa.t.size;
    TPM_DO_SELF_TEST(scheme->scheme);

    retVal = InitOpenSSLRSAPublicKey(key, &pkey);
    if (retVal != TPM_RC_SUCCESS)
        return retVal;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL ||
        EVP_PKEY_encrypt_init(ctx) <= 0)
        ERROR_EXIT(TPM_RC_FAILURE);

    switch(scheme->scheme)
	{
          case TPM_ALG_NULL:  // 'raw' encryption
	    if (RuntimeProfileRequiresAttributeFlags(&g_RuntimeProfile,	// libtpms added begin
						     RUNTIME_ATTRIBUTE_NO_UNPADDED_ENCRYPTION))
		return TPM_RC_SCHEME;					// libtpms added end

	    {
		INT32                 i;
		INT32                 dSize = dIn->size;
		// dIn can have more bytes than cOut as long as the extra bytes
		// are zero. Note: the more significant bytes of a number in a byte
		// buffer are the bytes at the start of the array.
		for(i = 0; (i < dSize) && (dIn->buffer[i] == 0); i++);
		dSize -= i;
		scratch.t.size = cOut->t.size;
		pAssert(scratch.t.size <= sizeof(scratch.t.buffer));
		if(dSize > scratch.t.size)
		    ERROR_EXIT(TPM_RC_VALUE);
		// Pad cOut with zeros if dIn is smaller
		memset(scratch.t.buffer, 0, scratch.t.size - dSize);
		// And copy the rest of the value; value is then right-aligned
		memcpy(&scratch.t.buffer[scratch.t.size - dSize], &dIn->buffer[i], dSize);

		dIn = &scratch.b;
	    }
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0)
                ERROR_EXIT(TPM_RC_FAILURE);
            break;
          case TPM_ALG_RSAES:
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
                ERROR_EXIT(TPM_RC_FAILURE);
            break;
          case TPM_ALG_OAEP:
            digestname = GetDigestNameByHashAlg(scheme->details.oaep.hashAlg);
            if (digestname == NULL)
                ERROR_EXIT(TPM_RC_VALUE);

            md = EVP_get_digestbyname(digestname);
            if (md == NULL ||
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
                EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0)
                ERROR_EXIT(TPM_RC_FAILURE);

            if (label->size > 0) {
                tmp = malloc(label->size);
                if (tmp == NULL)
                    ERROR_EXIT(TPM_RC_FAILURE);
                memcpy(tmp, label->buffer, label->size);
                if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, tmp, label->size) <= 0)
                    ERROR_EXIT(TPM_RC_FAILURE);
            }
            tmp = NULL;
            break;
          default:
            ERROR_EXIT(TPM_RC_SCHEME);
            break;
	}

    outlen = cOut->t.size;

    if (EVP_PKEY_encrypt(ctx, cOut->t.buffer, &outlen,
                         dIn->buffer, dIn->size) <= 0)
        ERROR_EXIT(TPM_RC_FAILURE);

    cOut->t.size = outlen;

 Exit:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    free(tmp);

    return retVal;
}

LIB_EXPORT TPM_RC
CryptRsaDecrypt(
		TPM2B               *dOut,          // OUT: the decrypted data
		TPM2B               *cIn,           // IN: the data to decrypt
		OBJECT              *key,           // IN: the key to use for decryption
		TPMT_RSA_DECRYPT    *scheme,        // IN: the padding scheme
		const TPM2B         *label          // IN: in case it is needed for the scheme
		)
{
    TPM_RC                 retVal;
    EVP_PKEY              *pkey = NULL;
    EVP_PKEY_CTX          *ctx = NULL;
    const EVP_MD          *md = NULL;
    const char            *digestname;
    size_t                 outlen;
    unsigned char         *tmp = NULL;
    unsigned char          buffer[MAX_RSA_KEY_BYTES];

    // Make sure that the necessary parameters are provided
    pAssert(cIn != NULL && dOut != NULL && key != NULL);
    // Size is checked to make sure that the encrypted value is the right size
    if(cIn->size != key->publicArea.unique.rsa.t.size)
        ERROR_EXIT(TPM_RC_SIZE);
    TPM_DO_SELF_TEST(scheme->scheme);

    retVal = InitOpenSSLRSAPrivateKey(key, &pkey);
    if (retVal != TPM_RC_SUCCESS)
        return retVal;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL ||
        EVP_PKEY_decrypt_init(ctx) <= 0)
        ERROR_EXIT(TPM_RC_FAILURE);

    switch(scheme->scheme)
	{
	  case TPM_ALG_NULL:  // 'raw' encryption
	    if (RuntimeProfileRequiresAttributeFlags(&g_RuntimeProfile,
						     RUNTIME_ATTRIBUTE_NO_UNPADDED_ENCRYPTION))
		ERROR_EXIT(TPM_RC_SCHEME);
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0)
                ERROR_EXIT(TPM_RC_FAILURE);
            break;
	  case TPM_ALG_RSAES:
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
                ERROR_EXIT(TPM_RC_FAILURE);
            break;
	  case TPM_ALG_OAEP:
            digestname = GetDigestNameByHashAlg(scheme->details.oaep.hashAlg);
            if (digestname == NULL)
                ERROR_EXIT(TPM_RC_VALUE);

            md = EVP_get_digestbyname(digestname);
            if (md == NULL ||
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
                EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0)
                ERROR_EXIT(TPM_RC_FAILURE);

            if (label->size > 0) {
                tmp = malloc(label->size);
                if (tmp == NULL)
                    ERROR_EXIT(TPM_RC_FAILURE);
                memcpy(tmp, label->buffer, label->size);

                if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, tmp, label->size) <= 0)
                    ERROR_EXIT(TPM_RC_FAILURE);
                tmp = NULL;
            }
            break;
	  default:
            ERROR_EXIT(TPM_RC_SCHEME);
            break;
	}

    /* cannot use cOut->buffer */
    outlen = sizeof(buffer);
    if (EVP_PKEY_decrypt(ctx, buffer, &outlen,
                         cIn->buffer, cIn->size) <= 0)
        ERROR_EXIT(TPM_RC_VALUE);

    if (outlen > dOut->size)
        ERROR_EXIT(TPM_RC_FAILURE);

    memcpy(dOut->buffer, buffer, outlen);
    dOut->size = outlen;

    retVal = TPM_RC_SUCCESS;

 Exit:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    free(tmp);

    return retVal;
}

LIB_EXPORT TPM_RC
CryptRsaSign(
	     TPMT_SIGNATURE      *sigOut,
	     OBJECT              *key,           // IN: key to use
	     TPM2B_DIGEST        *hIn,           // IN: the digest to sign
	     RAND_STATE          *rand           // IN: the random number generator
	     //      to use (mostly for testing)
	     )
{
    TPM_RC                retVal = TPM_RC_SUCCESS;
    UINT16                modSize;
    size_t                outlen;
    int                   padding;
    EVP_PKEY             *pkey = NULL;
    EVP_PKEY_CTX         *ctx = NULL;
    const EVP_MD         *md;
    const char           *digestname;
    TPMI_ALG_HASH         hashAlg;

    // parameter checks
    pAssert(sigOut != NULL && key != NULL && hIn != NULL);
    modSize = key->publicArea.unique.rsa.t.size;
    // for all non-null signatures, the size is the size of the key modulus
    sigOut->signature.rsapss.sig.t.size = modSize;
    TPM_DO_SELF_TEST(sigOut->sigAlg);

    switch(sigOut->sigAlg)
         {
          case TPM_ALG_NULL:
            sigOut->signature.rsapss.sig.t.size = 0;
            return TPM_RC_SUCCESS;
          case TPM_ALG_RSAPSS:
            padding = RSA_PKCS1_PSS_PADDING;
            hashAlg = sigOut->signature.rsapss.hash;
            break;
          case TPM_ALG_RSASSA:
            padding = RSA_PKCS1_PADDING;
            hashAlg = sigOut->signature.rsassa.hash;
            break;
          default:
            ERROR_EXIT(TPM_RC_SCHEME);
         }

    digestname = GetDigestNameByHashAlg(hashAlg);
    if (digestname == NULL)
        ERROR_EXIT(TPM_RC_VALUE);

    md = EVP_get_digestbyname(digestname);
    if (md == NULL)
        ERROR_EXIT(TPM_RC_FAILURE);

    retVal = InitOpenSSLRSAPrivateKey(key, &pkey);
    if (retVal != TPM_RC_SUCCESS)
        return retVal;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL ||
        EVP_PKEY_sign_init(ctx) <= 0)
        ERROR_EXIT(TPM_RC_FAILURE);

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0)
        ERROR_EXIT(TPM_RC_FAILURE);

    /* careful with PSS padding: Use salt length = hash length (-1) if
     *   length(digest) + length(hash-to-sign) + 2 <= modSize
     * otherwise use the max. possible salt length, which is the default (-2)
     * test case: 1024 bit key PSS signing sha512 hash
     */
    if (padding == RSA_PKCS1_PSS_PADDING &&
        EVP_MD_size(md) + hIn->b.size + 2 <= modSize && /* OSSL: RSA_padding_add_PKCS1_PSS_mgf1 */
        EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -1) <= 0)
        ERROR_EXIT(TPM_RC_FAILURE);

    outlen = sigOut->signature.rsapss.sig.t.size;
    if (EVP_PKEY_sign(ctx,
                      sigOut->signature.rsapss.sig.t.buffer, &outlen,
                      hIn->b.buffer, hIn->b.size) <= 0)
        ERROR_EXIT(TPM_RC_FAILURE);

    sigOut->signature.rsapss.sig.t.size = outlen;

 Exit:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return retVal;
}

LIB_EXPORT TPM_RC
CryptRsaValidateSignature(
			  TPMT_SIGNATURE  *sig,           // IN: signature
			  OBJECT          *key,           // IN: public modulus
			  TPM2B_DIGEST    *digest         // IN: The digest being validated
			  )
{
    TPM_RC          retVal;
    int             padding;
    EVP_PKEY       *pkey = NULL;
    EVP_PKEY_CTX   *ctx = NULL;
    const EVP_MD   *md;
    const char     *digestname;

    //
    // Fatal programming errors
    pAssert(key != NULL && sig != NULL && digest != NULL);
    switch(sig->sigAlg)
	{
	  case TPM_ALG_RSAPSS:
	    padding = RSA_PKCS1_PSS_PADDING;
	    break;
	  case TPM_ALG_RSASSA:
	    padding = RSA_PKCS1_PADDING;
	    break;
	  default:
	    return TPM_RC_SCHEME;
	}
    // Errors that might be caused by calling parameters
    if(sig->signature.rsassa.sig.t.size != key->publicArea.unique.rsa.t.size)
	ERROR_EXIT(TPM_RC_SIGNATURE);
    TPM_DO_SELF_TEST(sig->sigAlg);

    retVal = InitOpenSSLRSAPublicKey(key, &pkey);
    if (retVal != TPM_RC_SUCCESS)
        return retVal;

    if (sig->signature.any.hashAlg == TPM_ALG_SHA1 &&		// libtpms added begin
	RuntimeProfileRequiresAttributeFlags(&g_RuntimeProfile,
					     RUNTIME_ATTRIBUTE_NO_SHA1_VERIFICATION))
	ERROR_EXIT(TPM_RC_HASH);				// libtpms added end

    digestname = GetDigestNameByHashAlg(sig->signature.any.hashAlg);
    if (digestname == NULL)
        ERROR_EXIT(TPM_RC_VALUE);

    md = EVP_get_digestbyname(digestname);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (md == NULL || ctx == NULL ||
        EVP_PKEY_verify_init(ctx) <= 0)
        ERROR_EXIT(TPM_RC_FAILURE);

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0)
        ERROR_EXIT(TPM_RC_FAILURE);

    if (EVP_PKEY_verify(ctx,
                        sig->signature.rsassa.sig.t.buffer, sig->signature.rsassa.sig.t.size,
                        digest->t.buffer, digest->t.size) <= 0)
        ERROR_EXIT(TPM_RC_SIGNATURE);

    retVal = TPM_RC_SUCCESS;

 Exit:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return (retVal != TPM_RC_SUCCESS) ? TPM_RC_SIGNATURE : TPM_RC_SUCCESS;
}
#endif // USE_OPENSSL_FUNCTIONS_RSA    libtpms added end

#endif  // ALG_RSA
