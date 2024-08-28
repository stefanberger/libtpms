/********************************************************************************/
/*										*/
/*		Implementation of cryptographic functions for hashing.		*/
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

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Feb 28, 2020  Time: 03:04:48PM
 */

#ifndef _CRYPT_HASH_FP_H_
#define _CRYPT_HASH_FP_H_

//*** CryptHashInit()
// This function is called by _TPM_Init do perform the initialization operations for
// the library.
BOOL CryptHashInit(void);

//*** CryptHashStartup()
// This function is called by TPM2_Startup(). It checks that the size of the
// HashDefArray is consistent with the HASH_COUNT.
BOOL CryptHashStartup(void);

//*** CryptGetHashDef()
// This function accesses the hash descriptor associated with a hash a
// algorithm. The function returns a pointer to a 'null' descriptor if hashAlg is
// TPM_ALG_NULL or not a defined algorithm.
PHASH_DEF
CryptGetHashDef(TPM_ALG_ID hashAlg);

//*** CryptHashIsValidAlg()
// This function tests to see if an algorithm ID is a valid hash algorithm. If
// flag is true, then TPM_ALG_NULL is a valid hash.
//  Return Type: BOOL
//      TRUE(1)         hashAlg is a valid, implemented hash on this TPM
//      FALSE(0)        hashAlg is not valid for this TPM
BOOL CryptHashIsValidAlg(TPM_ALG_ID hashAlg,  // IN: the algorithm to check
			 BOOL       flag  // IN: TRUE if TPM_ALG_NULL is to be treated
			 //     as a valid hash
			 );

//*** CryptHashGetAlgByIndex()
// This function is used to iterate through the hashes. TPM_ALG_NULL
// is returned for all indexes that are not valid hashes.
// If the TPM implements 3 hashes, then an 'index' value of 0 will
// return the first implemented hash and an 'index' of 2 will return the
// last. All other index values will return TPM_ALG_NULL.
//
//  Return Type: TPM_ALG_ID
// TPM_ALG_xxx         a hash algorithm
// TPM_ALG_NULL        this can be used as a stop value
LIB_EXPORT TPM_ALG_ID CryptHashGetAlgByIndex(UINT32 index  // IN: the index
					     );

//*** CryptHashGetDigestSize()
// Returns the size of the digest produced by the hash. If 'hashAlg' is not a hash
// algorithm, the TPM will FAIL.
//  Return Type: UINT16
//   0       TPM_ALG_NULL
//   > 0     the digest size
//
LIB_EXPORT UINT16 CryptHashGetDigestSize(
					 TPM_ALG_ID hashAlg  // IN: hash algorithm to look up
					 );

//*** CryptHashGetBlockSize()
// Returns the size of the block used by the hash. If 'hashAlg' is not a hash
// algorithm, the TPM will FAIL.
//  Return Type: UINT16
//   0       TPM_ALG_NULL
//   > 0     the digest size
//
LIB_EXPORT UINT16 CryptHashGetBlockSize(
					TPM_ALG_ID hashAlg  // IN: hash algorithm to look up
					);

//*** CryptHashGetOid()
// This function returns a pointer to DER=encoded OID for a hash algorithm. All OIDs
// are full OID values including the Tag (0x06) and length byte.
LIB_EXPORT const BYTE* CryptHashGetOid(TPM_ALG_ID hashAlg);

//***  CryptHashGetContextAlg()
// This function returns the hash algorithm associated with a hash context.
TPM_ALG_ID
CryptHashGetContextAlg(PHASH_STATE state  // IN: the context to check
		       );

//*** CryptHashCopyState
// This function is used to clone a HASH_STATE.
LIB_EXPORT void CryptHashCopyState(HASH_STATE* out,  // OUT: destination of the state
				   const HASH_STATE* in  // IN: source of the state
				   );

//*** CryptHashExportState()
// This function is used to export a hash or HMAC hash state. This function
// would be called when preparing to context save a sequence object.
void CryptHashExportState(
			  PCHASH_STATE internalFmt,       // IN: the hash state formatted for use by
			  //     library
			  PEXPORT_HASH_STATE externalFmt  // OUT: the exported hash state
			  );

//*** CryptHashImportState()
// This function is used to import the hash state. This function
// would be called to import a hash state when the context of a sequence object
// was being loaded.
void CryptHashImportState(
			  PHASH_STATE internalFmt,         // OUT: the hash state formatted for use by
			  //     the library
			  PCEXPORT_HASH_STATE externalFmt  // IN: the exported hash state
			  );

//*** CryptHashStart()
// Functions starts a hash stack
// Start a hash stack and returns the digest size. As a side effect, the
// value of 'stateSize' in hashState is updated to indicate the number of bytes
// of state that were saved. This function calls GetHashServer() and that function
// will put the TPM into failure mode if the hash algorithm is not supported.
//
// This function does not use the sequence parameter. If it is necessary to import
// or export context, this will start the sequence in a local state
// and export the state to the input buffer. Will need to add a flag to the state
// structure to indicate that it needs to be imported before it can be used.
// (BLEH).
//  Return Type: UINT16
//  0           hash is TPM_ALG_NULL
// >0           digest size
LIB_EXPORT UINT16 CryptHashStart(
				 PHASH_STATE hashState,  // OUT: the running hash state
				 TPM_ALG_ID  hashAlg     // IN: hash algorithm
				 );

//*** CryptDigestUpdate()
// Add data to a hash or HMAC, SMAC stack.
//
void CryptDigestUpdate(PHASH_STATE hashState,  // IN: the hash context information
		       UINT32      dataSize,   // IN: the size of data to be added
		       const BYTE* data        // IN: data to be hashed
		       );

//*** CryptHashEnd()
// Complete a hash or HMAC computation. This function will place the smaller of
// 'digestSize' or the size of the digest in 'dOut'. The number of bytes in the
// placed in the buffer is returned. If there is a failure, the returned value
// is <= 0.
//  Return Type: UINT16
//       0      no data returned
//      > 0     the number of bytes in the digest or dOutSize, whichever is smaller
LIB_EXPORT UINT16 CryptHashEnd(PHASH_STATE hashState,  // IN: the state of hash stack
			       UINT32      dOutSize,   // IN: size of digest buffer
			       BYTE*       dOut        // OUT: hash digest
			       );

//*** CryptHashBlock()
// Start a hash, hash a single block, update 'digest' and return the size of
// the results.
//
// The 'digestSize' parameter can be smaller than the digest. If so, only the more
// significant bytes are returned.
//  Return Type: UINT16
//  >= 0        number of bytes placed in 'dOut'
LIB_EXPORT UINT16 CryptHashBlock(TPM_ALG_ID  hashAlg,   // IN: The hash algorithm
				 UINT32      dataSize,  // IN: size of buffer to hash
				 const BYTE* data,      // IN: the buffer to hash
				 UINT32 dOutSize,  // IN: size of the digest buffer
				 BYTE*  dOut       // OUT: digest buffer
				 );

//*** CryptDigestUpdate2B()
// This function updates a digest (hash or HMAC) with a TPM2B.
//
// This function can be used for both HMAC and hash functions so the
// 'digestState' is void so that either state type can be passed.
LIB_EXPORT void CryptDigestUpdate2B(PHASH_STATE  state,  // IN: the digest state
				    const TPM2B* bIn     // IN: 2B containing the data
				    );

//*** CryptHashEnd2B()
// This function is the same as CryptCompleteHash() but the digest is
// placed in a TPM2B. This is the most common use and this is provided
// for specification clarity. 'digest.size' should be set to indicate the number of
// bytes to place in the buffer
//  Return Type: UINT16
//      >=0     the number of bytes placed in 'digest.buffer'
LIB_EXPORT UINT16 CryptHashEnd2B(
				 PHASH_STATE state,  // IN: the hash state
				 P2B         digest  // IN: the size of the buffer Out: requested
				 //     number of bytes
				 );

//*** CryptDigestUpdateInt()
// This function is used to include an integer value to a hash stack. The function
// marshals the integer into its canonical form before calling CryptDigestUpdate().
LIB_EXPORT void CryptDigestUpdateInt(
				     void*  state,    // IN: the state of hash stack
				     UINT32 intSize,  // IN: the size of 'intValue' in bytes
				     UINT64 intValue  // IN: integer value to be hashed
				     );

//*** CryptHmacStart()
// This function is used to start an HMAC using a temp
// hash context. The function does the initialization
// of the hash with the HMAC key XOR iPad and updates the
// HMAC key XOR oPad.
//
// The function returns the number of bytes in a digest produced by 'hashAlg'.
//  Return Type: UINT16
//  >= 0        number of bytes in digest produced by 'hashAlg' (may be zero)
//
LIB_EXPORT UINT16 CryptHmacStart(PHMAC_STATE state,    // IN/OUT: the state buffer
				 TPM_ALG_ID  hashAlg,  // IN: the algorithm to use
				 UINT16      keySize,  // IN: the size of the HMAC key
				 const BYTE* key       // IN: the HMAC key
				 );

//*** CryptHmacEnd()
// This function is called to complete an HMAC. It will finish the current
// digest, and start a new digest. It will then add the oPadKey and the
// completed digest and return the results in dOut. It will not return more
// than dOutSize bytes.
//  Return Type: UINT16
//  >= 0        number of bytes in 'dOut' (may be zero)
LIB_EXPORT UINT16 CryptHmacEnd(PHMAC_STATE state,     // IN: the hash state buffer
			       UINT32      dOutSize,  // IN: size of digest buffer
			       BYTE*       dOut       // OUT: hash digest
			       );

//*** CryptHmacStart2B()
// This function starts an HMAC and returns the size of the digest
// that will be produced.
//
// This function is provided to support the most common use of starting an HMAC
// with a TPM2B key.
//
// The caller must provide a block of memory in which the hash sequence state
// is kept.  The caller should not alter the contents of this buffer until the
// hash sequence is completed or abandoned.
//
//  Return Type: UINT16
//      > 0     the digest size of the algorithm
//      = 0     the hashAlg was TPM_ALG_NULL
LIB_EXPORT UINT16 CryptHmacStart2B(
				   PHMAC_STATE hmacState,  // OUT: the state of HMAC stack. It will be used
				   //     in HMAC update and completion
				   TPMI_ALG_HASH hashAlg,  // IN: hash algorithm
				   P2B           key       // IN: HMAC key
				   );

//*** CryptHmacEnd2B()
//   This function is the same as CryptHmacEnd() but the HMAC result
//   is returned in a TPM2B which is the most common use.
//  Return Type: UINT16
//      >=0     the number of bytes placed in 'digest'
LIB_EXPORT UINT16 CryptHmacEnd2B(
				 PHMAC_STATE hmacState,  // IN: the state of HMAC stack
				 P2B         digest      // OUT: HMAC
				 );

//** Mask and Key Generation Functions
//*** CryptMGF_KDF()
// This function performs MGF1/KDF1 or KDF2 using the selected hash. KDF1 and KDF2 are
// T('n') = T('n'-1) || H('seed' || 'counter') with the difference being that, with
// KDF1, 'counter' starts at 0 but with KDF2, 'counter' starts at 1. The caller
// determines which version by setting the initial value of counter to either 0 or 1.
// Note: Any value that is not 0 is considered to be 1.
//
// This function returns the length of the mask produced which
// could be zero if the digest algorithm is not supported
//  Return Type: UINT16
//      0       hash algorithm was TPM_ALG_NULL
//    > 0       should be the same as 'mSize'
LIB_EXPORT UINT16 CryptMGF_KDF(UINT32 mSize,  // IN: length of the mask to be produced
			       BYTE*  mask,   // OUT: buffer to receive the mask
			       TPM_ALG_ID hashAlg,   // IN: hash to use
			       UINT32     seedSize,  // IN: size of the seed
			       BYTE*      seed,      // IN: seed size
			       UINT32     counter    // IN: counter initial value
			       );

//*** CryptKDFa()
// This function performs the key generation according to Part 1 of the
// TPM specification.
//
// This function returns the number of bytes generated which may be zero.
//
// The 'key' and 'keyStream' pointers are not allowed to be NULL. The other
// pointer values may be NULL. The value of 'sizeInBits' must be no larger
// than (2^18)-1 = 256K bits (32385 bytes).
//
// The 'once' parameter is set to allow incremental generation of a large
// value. If this flag is TRUE, 'sizeInBits' will be used in the HMAC computation
// but only one iteration of the KDF is performed. This would be used for
// XOR obfuscation so that the mask value can be generated in digest-sized
// chunks rather than having to be generated all at once in an arbitrarily
// large buffer and then XORed into the result. If 'once' is TRUE, then
// 'sizeInBits' must be a multiple of 8.
//
// Any error in the processing of this command is considered fatal.
//  Return Type: UINT16
//     0            hash algorithm is not supported or is TPM_ALG_NULL
//    > 0           the number of bytes in the 'keyStream' buffer
LIB_EXPORT UINT16 CryptKDFa(
			    TPM_ALG_ID   hashAlg,       // IN: hash algorithm used in HMAC
			    const TPM2B* key,           // IN: HMAC key
			    const TPM2B* label,         // IN: a label for the KDF
			    const TPM2B* contextU,      // IN: context U
			    const TPM2B* contextV,      // IN: context V
			    UINT32       sizeInBits,    // IN: size of generated key in bits
			    BYTE*        keyStream,     // OUT: key buffer
			    UINT32*      counterInOut,  // IN/OUT: caller may provide the iteration
			    //     counter for incremental operations to
			    //     avoid large intermediate buffers.
			    UINT16 blocks               // IN: If non-zero, this is the maximum number
			    //     of blocks to be returned, regardless
			    //     of sizeInBits
			    );

//*** CryptKDFe()
// This function implements KDFe() as defined in TPM specification part 1.
//
// This function returns the number of bytes generated which may be zero.
//
// The 'Z' and 'keyStream' pointers are not allowed to be NULL. The other
// pointer values may be NULL. The value of 'sizeInBits' must be no larger
// than (2^18)-1 = 256K bits (32385 bytes).
// Any error in the processing of this command is considered fatal.
//  Return Type: UINT16
//     0            hash algorithm is not supported or is TPM_ALG_NULL
//    > 0           the number of bytes in the 'keyStream' buffer
//
LIB_EXPORT UINT16 CryptKDFe(TPM_ALG_ID   hashAlg,  // IN: hash algorithm used in HMAC
			    TPM2B*       Z,        // IN: Z
			    const TPM2B* label,    // IN: a label value for the KDF
			    TPM2B*       partyUInfo,  // IN: PartyUInfo
			    TPM2B*       partyVInfo,  // IN: PartyVInfo
			    UINT32 sizeInBits,  // IN: size of generated key in bits
			    BYTE*  keyStream    // OUT: key buffer
			    );

#endif  // _CRYPT_HASH_FP_H_
