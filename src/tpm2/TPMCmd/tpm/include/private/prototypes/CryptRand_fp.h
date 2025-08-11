/********************************************************************************/
/*										*/
/*		DRBG with a behavior according to SP800-90A			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CryptRand_fp.h 1476 2019-06-10 19:32:03Z kgoldman $		*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2019				*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar  4, 2020  Time: 02:36:44PM
 */

#ifndef _CRYPT_RAND_FP_H_
#define _CRYPT_RAND_FP_H_

//*** DRBG_GetEntropy()
// Even though this implementation never fails, it may get blocked
// indefinitely long in the call to get entropy from the platform
// (DRBG_GetEntropy32()).
// This function is only used during instantiation of the DRBG for
// manufacturing and on each start-up after an non-orderly shutdown.
//
//  Return Type: BOOL
//      TRUE(1)         requested entropy returned
//      FALSE(0)        entropy Failure
BOOL DRBG_GetEntropy(UINT32 requiredEntropy,  // IN: requested number of bytes of full
                                              //     entropy
                     BYTE* entropy  // OUT: buffer to return collected entropy
);

//*** IncrementIv()
// This function increments the IV value by 1. It is used by EncryptDRBG().
void IncrementIv(DRBG_IV* iv);

//*** DRBG_Reseed()
// This function is used when reseeding of the DRBG is required. If
// entropy is provided, it is used in lieu of using hardware entropy.
// Note: the provided entropy must be the required size.
//
//  Return Type: BOOL
//      TRUE(1)         reseed succeeded
//      FALSE(0)        reseed failed, probably due to the entropy generation
BOOL DRBG_Reseed(DRBG_STATE* drbgState,        // IN: the state to update
                 DRBG_SEED*  providedEntropy,  // IN: entropy
                 DRBG_SEED*  additionalData    // IN:
);

//*** DRBG_SelfTest()
// This is run when the DRBG is instantiated and at startup.
//
//  Return Type: BOOL
//      TRUE(1)         test OK
//      FALSE(0)        test failed
BOOL DRBG_SelfTest(void);

//*** CryptRandomStir()
// This function is used to cause a reseed. A DRBG_SEED amount of entropy is
// collected from the hardware and then additional data is added.
//
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        failure of the entropy generator
LIB_EXPORT TPM_RC CryptRandomStir(UINT16 additionalDataSize, BYTE* additionalData);

//*** CryptRandomGenerate()
// Generate a 'randomSize' number or random bytes.
LIB_EXPORT UINT16 CryptRandomGenerate(UINT16 randomSize, BYTE* buffer);

//*** DRBG_InstantiateSeededKdf()
// This function is used to instantiate a KDF-based RNG. This is used for derivations.
// This function always returns TRUE.
LIB_EXPORT BOOL DRBG_InstantiateSeededKdf(
    KDF_STATE*   state,    // OUT: buffer to hold the state
    TPM_ALG_ID   hashAlg,  // IN: hash algorithm
    TPM_ALG_ID   kdf,      // IN: the KDF to use
    TPM2B*       seed,     // IN: the seed to use
    const TPM2B* label,    // IN: a label for the generation process.
    TPM2B*       context,  // IN: the context value
    UINT32       limit     // IN: Maximum number of bits from the KDF
);

//*** DRBG_AdditionalData()
// Function to reseed the DRBG with additional entropy. This is normally called
// before computing the protection value of a primary key in the Endorsement
// hierarchy.
LIB_EXPORT void DRBG_AdditionalData(DRBG_STATE* drbgState,  // IN:OUT state to update
                                    TPM2B* additionalData  // IN: value to incorporate
);

//*** DRBG_InstantiateSeeded()
// This function is used to instantiate a random number generator from seed values.
// The nominal use of this generator is to create sequences of pseudo-random
// numbers from a seed value.
//
// Return Type: TPM_RC
//  TPM_RC_FAILURE      DRBG self-test failure
LIB_EXPORT TPM_RC DRBG_InstantiateSeeded(
    DRBG_STATE*  drbgState,  // IN/OUT: buffer to hold the state
    const TPM2B* seed,       // IN: the seed to use
    const TPM2B* purpose,    // IN: a label for the generation process.
    const TPM2B* name,       // IN: name of the object
    const TPM2B* additional, // IN: additional data
    SEED_COMPAT_LEVEL seedCompatLevel// IN: compatibility level (associated with seed); libtpms added
);

//*** CryptRandStartup()
// This function is called when TPM_Startup is executed. This function always returns
// TRUE.
LIB_EXPORT BOOL CryptRandStartup(void);

//**** CryptRandInit()
// This function is called when _TPM_Init is being processed.
//
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure
LIB_EXPORT BOOL CryptRandInit(void);

//*** DRBG_Generate()
// This function generates a random sequence according SP800-90A.
// If 'random' is not NULL, then 'randomSize' bytes of random values are generated.
// If 'random' is NULL or 'randomSize' is zero, then the function returns
// zero without generating any bits or updating the reseed counter.
// This function returns the number of bytes produced which could be less than the
// number requested if the request is too large ("too large" is implementation
// dependent.)
LIB_EXPORT UINT16 DRBG_Generate(
    RAND_STATE* state,
    BYTE*       random,     // OUT: buffer to receive the random values
    UINT16      randomSize  // IN: the number of bytes to generate
);

// libtpms added begin
LIB_EXPORT SEED_COMPAT_LEVEL
DRBG_GetSeedCompatLevel(
               RAND_STATE     *state          // IN
              );
// libtpms added end

//*** DRBG_Instantiate()
// This is CTR_DRBG_Instantiate_algorithm() from [SP 800-90A 10.2.1.3.1].
// This is called when a the TPM DRBG is to be instantiated. This is
// called to instantiate a DRBG used by the TPM for normal
// operations.
//
//  Return Type: BOOL
//      TRUE(1)         instantiation succeeded
//      FALSE(0)        instantiation failed
LIB_EXPORT BOOL DRBG_Instantiate(
    DRBG_STATE* drbgState,       // OUT: the instantiated value
    UINT16      pSize,           // IN: Size of personalization string
    BYTE*       personalization  // IN: The personalization string
);

//*** DRBG_Uninstantiate()
// This is Uninstantiate_function() from [SP 800-90A 9.4].
//
//  Return Type: TPM_RC
//      TPM_RC_VALUE        not a valid state
LIB_EXPORT TPM_RC DRBG_Uninstantiate(
    DRBG_STATE* drbgState  // IN/OUT: working state to erase
);

#endif  // _CRYPT_RAND_FP_H_
