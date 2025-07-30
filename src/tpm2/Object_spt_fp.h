/********************************************************************************/
/*										*/
/*			  Object Command Support   				*/
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
 *  Date: Mar  7, 2020  Time: 07:06:44PM
 */

#ifndef _OBJECT_SPT_FP_H_
#define _OBJECT_SPT_FP_H_

//*** AdjustAuthSize()
// This function will validate that the input authValue is no larger than the
// digestSize for the nameAlg. It will then pad with zeros to the size of the
// digest.
BOOL AdjustAuthSize(TPM2B_AUTH*   auth,    // IN/OUT: value to adjust
                    TPMI_ALG_HASH nameAlg  // IN:
);

//*** AreAttributesForParent()
// This function is called by create, load, and import functions.
//
// Note: The 'isParent' attribute is SET when an object is loaded and it has
// attributes that are suitable for a parent object.
//  Return Type: BOOL
//      TRUE(1)         properties are those of a parent
//      FALSE(0)        properties are not those of a parent
BOOL ObjectIsParent(OBJECT* parentObject  // IN: parent handle
);

//*** CreateChecks()
// Attribute checks that are unique to creation.
// If parentObject is not NULL, then this function checks the object's
// attributes as an Ordinary or Derived Object with the given parent.
// If parentObject is NULL, and primaryHandle is not 0, then this function
// checks the object's attributes as a Primary Object in the given hierarchy.
// If parentObject is NULL, and primaryHandle is 0, then this function checks
// the object's attributes as an External Object.
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES       sensitiveDataOrigin is not consistent with the
//                              object type
//      other                   returns from PublicAttributesValidation()
TPM_RC
CreateChecks(OBJECT*           parentObject,
             TPMI_RH_HIERARCHY primaryHierarchy,
             TPMT_PUBLIC*      publicArea,
             UINT16            sensitiveDataSize);

//*** SchemeChecks
// This function is called by TPM2_LoadExternal() and PublicAttributesValidation().
// This function validates the schemes in the public area of an object.
//  Return Type: TPM_RC
//      TPM_RC_HASH         non-duplicable storage key and its parent have different
//                          name algorithm
//      TPM_RC_KDF          incorrect KDF specified for decrypting keyed hash object
//      TPM_RC_KEY          invalid key size values in an asymmetric key public area
//      TPM_RCS_SCHEME       inconsistent attributes 'decrypt', 'sign', 'restricted'
//                          and key's scheme ID; or hash algorithm is inconsistent
//                          with the scheme ID for keyed hash object
//      TPM_RC_SYMMETRIC    a storage key with no symmetric algorithm specified; or
//                          non-storage key with symmetric algorithm different from
//                          TPM_ALG_NULL
TPM_RC
SchemeChecks(OBJECT*      parentObject,  // IN: parent (null if primary seed)
             TPMT_PUBLIC* publicArea     // IN: public area of the object
);

//*** PublicAttributesValidation()
// This function validates the values in the public area of an object.
// This function is used in the processing of TPM2_Create, TPM2_CreatePrimary,
// TPM2_CreateLoaded(), TPM2_Load(),  TPM2_Import(), and TPM2_LoadExternal().
// For TPM2_Import() this is only used if the new parent has fixedTPM SET. For
// TPM2_LoadExternal(), this is not used for a public-only key.
// If parentObject is not NULL, then primaryHandle is not used.
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES   'fixedTPM', 'fixedParent', or 'encryptedDuplication'
//                          attributes are inconsistent between themselves or with
//                          those of the parent object;
//                          inconsistent 'restricted', 'decrypt' and 'sign'
//                          attributes;
//                          attempt to inject sensitive data for an asymmetric key;
//                          attempt to create a symmetric cipher key that is not
//                          a decryption key
//      TPM_RC_HASH         nameAlg is TPM_ALG_NULL
//      TPM_RC_SIZE         'authPolicy' size does not match digest size of the name
//                          algorithm in 'publicArea'
//   other                  returns from SchemeChecks()
TPM_RC
PublicAttributesValidation(
    // IN: input parent object (if ordinary or derived object; NULL otherwise)
    OBJECT* parentObject,
    // IN: hierarchy (if primary object; 0 otherwise)
    TPMI_RH_HIERARCHY primaryHierarchy,
    // IN: public area of the object
    TPMT_PUBLIC* publicArea);

//*** FillInCreationData()
// Fill in creation data for an object.
//  Return Type: void
void FillInCreationData(
    TPMI_DH_OBJECT       parentHandle,   // IN: handle of parent
    TPMI_ALG_HASH        nameHashAlg,    // IN: name hash algorithm
    TPML_PCR_SELECTION*  creationPCR,    // IN: PCR selection
    TPM2B_DATA*          outsideData,    // IN: outside data
    TPM2B_CREATION_DATA* outCreation,    // OUT: creation data for output
    TPM2B_DIGEST*        creationDigest  // OUT: creation digest
);

//*** GetSeedForKDF()
// Get a seed for KDF.  The KDF for encryption and HMAC key use the same seed.
const TPM2B* GetSeedForKDF(OBJECT* protector  // IN: the protector handle
);

//*** ProduceOuterWrap()
// This function produce outer wrap for a buffer containing the sensitive data.
// It requires the sensitive data being marshaled to the outerBuffer, with the
// leading bytes reserved for integrity hash.  If iv is used, iv space should
// be reserved at the beginning of the buffer.  It assumes the sensitive data
// starts at address (outerBuffer + integrity size @).
// This function:
//  a) adds IV before sensitive area if required;
//  b) encrypts sensitive data with IV or a NULL IV as required;
//  c) adds HMAC integrity at the beginning of the buffer; and
//  d) returns the total size of blob with outer wrap.
UINT16
ProduceOuterWrap(OBJECT* protector,   // IN: The handle of the object that provides
                                      //     protection.  For object, it is parent
                                      //     handle. For credential, it is the handle
                                      //     of encrypt object.
                 TPM2B*     name,     // IN: the name of the object
                 TPM_ALG_ID hashAlg,  // IN: hash algorithm for outer wrap
                 TPM2B*     seed,     // IN: an external seed may be provided for
                                      //     duplication blob. For non duplication
                                      //     blob, this parameter should be NULL
                 BOOL   useIV,        // IN: indicate if an IV is used
                 UINT16 dataSize,     // IN: the size of sensitive data, excluding the
                                      //     leading integrity buffer size or the
                                      //     optional iv size
                 BYTE* outerBuffer    // IN/OUT: outer buffer with sensitive data in
                                      //     it
);

//*** UnwrapOuter()
// This function remove the outer wrap of a blob containing sensitive data
// This function:
//  a) checks integrity of outer blob; and
//  b) decrypts the outer blob.
//
//  Return Type: TPM_RC
//      TPM_RCS_INSUFFICIENT     error during sensitive data unmarshaling
//      TPM_RCS_INTEGRITY        sensitive data integrity is broken
//      TPM_RCS_SIZE             error during sensitive data unmarshaling
//      TPM_RCS_VALUE            IV size for CFB does not match the encryption
//                               algorithm block size
TPM_RC
UnwrapOuter(OBJECT* protector,   // IN: The object that provides
                                 //     protection.  For object, it is parent
                                 //     handle. For credential, it is the
                                 //     encrypt object.
            TPM2B*     name,     // IN: the name of the object
            TPM_ALG_ID hashAlg,  // IN: hash algorithm for outer wrap
            TPM2B*     seed,     // IN: an external seed may be provided for
                                 //     duplication blob. For non duplication
                                 //     blob, this parameter should be NULL.
            BOOL   useIV,        // IN: indicates if an IV is used
            UINT16 dataSize,     // IN: size of sensitive data in outerBuffer,
                                 //     including the leading integrity buffer
                                 //     size, and an optional iv area
            BYTE* outerBuffer    // IN/OUT: sensitive data
);

//*** SensitiveToPrivate()
// This function prepare the private blob for off the chip storage
// This function:
//  a) marshals TPM2B_SENSITIVE structure into the buffer of TPM2B_PRIVATE
//  b) applies encryption to the sensitive area; and
//  c) applies outer integrity computation.
void SensitiveToPrivate(
    TPMT_SENSITIVE* sensitive,  // IN: sensitive structure
    TPM2B_NAME*     name,       // IN: the name of the object
    OBJECT*         parent,     // IN: The parent object
    TPM_ALG_ID      nameAlg,    // IN: hash algorithm in public area.  This
                                //     parameter is used when parentHandle is
                                //     NULL, in which case the object is
                                //     temporary.
    TPM2B_PRIVATE* outPrivate   // OUT: output private structure
);

//*** PrivateToSensitive()
// Unwrap a input private area.  Check the integrity, decrypt and retrieve data
// to a sensitive structure.
// This function:
//  a) checks the integrity HMAC of the input private area;
//  b) decrypts the private buffer; and
//  c) unmarshals TPMT_SENSITIVE structure into the buffer of TPMT_SENSITIVE.
//  Return Type: TPM_RC
//      TPM_RCS_INTEGRITY       if the private area integrity is bad
//      TPM_RC_SENSITIVE        unmarshal errors while unmarshaling TPMS_ENCRYPT
//                              from input private
//      TPM_RCS_SIZE            error during sensitive data unmarshaling
//      TPM_RCS_VALUE           outer wrapper does not have an iV of the correct
//                              size
TPM_RC
PrivateToSensitive(TPM2B*     inPrivate,  // IN: input private structure
                   TPM2B*     name,       // IN: the name of the object
                   OBJECT*    parent,     // IN: parent object
                   TPM_ALG_ID nameAlg,    // IN: hash algorithm in public area.  It is
                   //     passed separately because we only pass
                   //     name, rather than the whole public area
                   //     of the object.  This parameter is used in
                   //     the following two cases: 1. primary
                   //     objects. 2. duplication blob with inner
                   //     wrap.  In other cases, this parameter
                   //     will be ignored
                   TPMT_SENSITIVE* sensitive  // OUT: sensitive structure
);

//*** SensitiveToDuplicate()
// This function prepare the duplication blob from the sensitive area.
// This function:
//  a) marshals TPMT_SENSITIVE structure into the buffer of TPM2B_PRIVATE;
//  b) applies inner wrap to the sensitive area if required; and
//  c) applies outer wrap if required.
void SensitiveToDuplicate(
    TPMT_SENSITIVE* sensitive,    // IN: sensitive structure
    TPM2B*          name,         // IN: the name of the object
    OBJECT*         parent,       // IN: The new parent object
    TPM_ALG_ID      nameAlg,      // IN: hash algorithm in public area. It
                                  //     is passed separately because we
                                  //     only pass name, rather than the
                                  //     whole public area of the object.
    TPM2B* seed,                  // IN: the external seed. If external
                                  //     seed is provided with size of 0,
                                  //     no outer wrap should be applied
                                  //     to duplication blob.
    TPMT_SYM_DEF_OBJECT* symDef,  // IN: Symmetric key definition. If the
                                  //     symmetric key algorithm is NULL,
                                  //     no inner wrap should be applied.
    TPM2B_DATA* innerSymKey,      // IN/OUT: a symmetric key may be
                                  //     provided to encrypt the inner
                                  //     wrap of a duplication blob. May
                                  //     be generated here if needed.
    TPM2B_PRIVATE* outPrivate     // OUT: output private structure
);

//*** DuplicateToSensitive()
// Unwrap a duplication blob.  Check the integrity, decrypt and retrieve data
// to a sensitive structure.
// This function:
//  a) checks the integrity HMAC of the input private area;
//  b) decrypts the private buffer; and
//  c) unmarshals TPMT_SENSITIVE structure into the buffer of TPMT_SENSITIVE.
//
//  Return Type: TPM_RC
//      TPM_RC_INSUFFICIENT      unmarshaling sensitive data from 'inPrivate' failed
//      TPM_RC_INTEGRITY         'inPrivate' data integrity is broken
//      TPM_RC_SIZE              unmarshaling sensitive data from 'inPrivate' failed
TPM_RC
DuplicateToSensitive(
    TPM2B*     inPrivate,         // IN: input private structure
    TPM2B*     name,              // IN: the name of the object
    OBJECT*    parent,            // IN: the parent
    TPM_ALG_ID nameAlg,           // IN: hash algorithm in public area.
    TPM2B*     seed,              // IN: an external seed may be provided.
                                  //     If external seed is provided with
                                  //     size of 0, no outer wrap is
                                  //     applied
    TPMT_SYM_DEF_OBJECT* symDef,  // IN: Symmetric key definition. If the
                                  //     symmetric key algorithm is NULL,
                                  //     no inner wrap is applied
    TPM2B* innerSymKey,           // IN: a symmetric key may be provided
                                  //     to decrypt the inner wrap of a
                                  //     duplication blob.
    TPMT_SENSITIVE* sensitive     // OUT: sensitive structure
);

//*** SecretToCredential()
// This function prepare the credential blob from a secret (a TPM2B_DIGEST)
// This function:
//  a) marshals TPM2B_DIGEST structure into the buffer of TPM2B_ID_OBJECT;
//  b) encrypts the private buffer, excluding the leading integrity HMAC area;
//  c) computes integrity HMAC and append to the beginning of the buffer; and
//  d) sets the total size of TPM2B_ID_OBJECT buffer.
void SecretToCredential(TPM2B_DIGEST*    secret,      // IN: secret information
                        TPM2B*           name,        // IN: the name of the object
                        TPM2B*           seed,        // IN: an external seed.
                        OBJECT*          protector,   // IN: the protector
                        TPM2B_ID_OBJECT* outIDObject  // OUT: output credential
);

//*** CredentialToSecret()
// Unwrap a credential.  Check the integrity, decrypt and retrieve data
// to a TPM2B_DIGEST structure.
// This function:
//  a) checks the integrity HMAC of the input credential area;
//  b) decrypts the credential buffer; and
//  c) unmarshals TPM2B_DIGEST structure into the buffer of TPM2B_DIGEST.
//
//  Return Type: TPM_RC
//      TPM_RC_INSUFFICIENT      error during credential unmarshaling
//      TPM_RC_INTEGRITY         credential integrity is broken
//      TPM_RC_SIZE              error during credential unmarshaling
//      TPM_RC_VALUE             IV size does not match the encryption algorithm
//                               block size
TPM_RC
CredentialToSecret(TPM2B*        inIDObject,  // IN: input credential blob
                   TPM2B*        name,        // IN: the name of the object
                   TPM2B*        seed,        // IN: an external seed.
                   OBJECT*       protector,   // IN: the protector
                   TPM2B_DIGEST* secret       // OUT: secret information
);

//*** MemoryRemoveTrailingZeros()
// This function is used to adjust the length of an authorization value.
// It adjusts the size of the TPM2B so that it does not include octets
// at the end of the buffer that contain zero.
//
// This function returns the number of non-zero octets in the buffer.
UINT16
MemoryRemoveTrailingZeros(TPM2B_AUTH* auth  // IN/OUT: value to adjust
);

//*** SetLabelAndContext()
// This function sets the label and context for a derived key. It is possible
// that 'label' or 'context' can end up being an Empty Buffer.
TPM_RC
SetLabelAndContext(TPMS_DERIVE* labelContext,       // IN/OUT: the recovered label and
                                                    //      context
                   TPM2B_SENSITIVE_DATA* sensitive  // IN: the sensitive data
);

//*** UnmarshalToPublic()
// Support function to unmarshal the template. This is used because the
// Input may be a TPMT_TEMPLATE and that structure does not have the same
// size as a TPMT_PUBLIC because of the difference between the 'unique' and
// 'seed' fields.
//
// If 'derive' is not NULL, then the 'seed' field is assumed to contain
// a 'label' and 'context' that are unmarshaled into 'derive'.
TPM_RC
UnmarshalToPublic(TPMT_PUBLIC*    tOut,  // OUT: output
                  TPM2B_TEMPLATE* tIn,   // IN:
                  BOOL derivation,       // IN: indicates if this is for a derivation
                  TPMS_DERIVE* labelContext  // OUT: label and context if derivation
);

#if 0 /* libtpms added */
//*** ObjectSetExternal()
// Set the external attributes for an object.
void ObjectSetExternal(OBJECT* object);
#endif /* libtpms added */

#endif  // _OBJECT_SPT_FP_H_
