/********************************************************************************/
/*										*/
/*			     Object Commands					*/
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

#include "Tpm.h"
#include "Load_fp.h"
#if CC_Load  // Conditional expansion of this file
#include "Object_spt_fp.h"

/*(See part 3 specification)
// Load an ordinary or temporary object
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES       'inPulblic' attributes are not allowed with selected
//                              parent
//      TPM_RC_BINDING          'inPrivate' and 'inPublic' are not
//                              cryptographically bound
//      TPM_RC_HASH             incorrect hash selection for signing key or
//                              the 'nameAlg' for 'inPublic' is not valid
//      TPM_RC_INTEGRITY        HMAC on 'inPrivate' was not valid
//      TPM_RC_KDF              KDF selection not allowed
//      TPM_RC_KEY              the size of the object's 'unique' field is not
//                              consistent with the indicated size in the object's
//                              parameters
//      TPM_RC_OBJECT_MEMORY    no available object slot
//      TPM_RC_SCHEME           the signing scheme is not valid for the key
//      TPM_RC_SENSITIVE        the 'inPrivate' did not unmarshal correctly
//      TPM_RC_SIZE             'inPrivate' missing, or 'authPolicy' size for
//                              'inPublic' or is not valid
//      TPM_RC_SYMMETRIC        symmetric algorithm not provided when required
//      TPM_RC_TYPE             'parentHandle' is not a storage key, or the object
//                              to load is a storage key but its parameters do not
//                              match the parameters of the parent.
//      TPM_RC_VALUE            decryption failure
TPM_RC
TPM2_Load(
	  Load_In         *in,            // IN: input parameter list
	  Load_Out        *out            // OUT: output parameter list
	  )
{
    TPM_RC                   result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE           sensitive = {0}; // libtpms changed (valgrind)
    OBJECT                  *parentObject;
    OBJECT                  *newObject;
    // Input Validation
    // Don't get invested in loading if there is no place to put it.
    newObject = FindEmptyObjectSlot(&out->objectHandle);
    if(newObject == NULL)
	return TPM_RC_OBJECT_MEMORY;
    if(in->inPrivate.t.size == 0)
	return TPM_RCS_SIZE + RC_Load_inPrivate;
    parentObject = HandleToObject(in->parentHandle);
    pAssert_RC(parentObject != NULL);
    // Is the object that is being used as the parent actually a parent.
    if(!ObjectIsParent(parentObject))
	return TPM_RCS_TYPE + RC_Load_parentHandle;
    // Compute the name of object. If there isn't one, it is because the nameAlg is
    // not valid.
    PublicMarshalAndComputeName(&in->inPublic.publicArea, &out->name);
    if(out->name.t.size == 0)
	return TPM_RCS_HASH + RC_Load_inPublic;
    // Retrieve sensitive data.
    result = PrivateToSensitive(&in->inPrivate.b, &out->name.b, parentObject,
				in->inPublic.publicArea.nameAlg,
				&sensitive);
    if(result != TPM_RC_SUCCESS)
	return RcSafeAddToResult(result, RC_Load_inPrivate);
    // Internal Data Update
    // Load and validate object
    result = ObjectLoad(newObject, parentObject,
			&in->inPublic.publicArea, &sensitive,
			RC_Load_inPublic, RC_Load_inPrivate,
			&out->name);
    if(result == TPM_RC_SUCCESS)
	{
	    // Set the common OBJECT attributes for a loaded object.
	    ObjectSetLoadedAttributes(newObject, in->parentHandle,
	                              parentObject->seedCompatLevel); // libtpms added
	}
    return result;
}
#endif // CC_Load
#include "Tpm.h"
#include "LoadExternal_fp.h"
#if CC_LoadExternal  // Conditional expansion of this file
#include "Object_spt_fp.h"
TPM_RC
TPM2_LoadExternal(
		  LoadExternal_In     *in,            // IN: input parameter list
		  LoadExternal_Out    *out            // OUT: output parameter list
		  )
{
    TPM_RC               result;
    OBJECT              *object;
    TPMT_SENSITIVE      *sensitive = NULL;
    // Input Validation
    // Don't get invested in loading if there is no place to put it.
    object = FindEmptyObjectSlot(&out->objectHandle);
    if(object == NULL)
	return TPM_RC_OBJECT_MEMORY;
    // If the hierarchy to be associated with this object is turned off, the object
    // cannot be loaded.
    if(!HierarchyIsEnabled(in->hierarchy))
	return TPM_RCS_HIERARCHY + RC_LoadExternal_hierarchy;
    // For loading an object with both public and sensitive
    if(in->inPrivate.size != 0)
	{
	    // An external object with a sensitive area can only be loaded in the
	    // NULL hierarchy
	    if(in->hierarchy != TPM_RH_NULL)
		return TPM_RCS_HIERARCHY + RC_LoadExternal_hierarchy;
	    // An external object with a sensitive area must have fixedTPM == CLEAR
	    // fixedParent == CLEAR so that it does not appear to be a key created by
	    // this TPM.
	    if(IS_ATTRIBUTE(in->inPublic.publicArea.objectAttributes, TPMA_OBJECT, fixedTPM)
	       || IS_ATTRIBUTE(in->inPublic.publicArea.objectAttributes, TPMA_OBJECT,
			       fixedParent)
	       || IS_ATTRIBUTE(in->inPublic.publicArea.objectAttributes, TPMA_OBJECT,
			       restricted))
		return TPM_RCS_ATTRIBUTES + RC_LoadExternal_inPublic;
	    // Have sensitive point to something other than NULL so that object
	    // initialization will load the sensitive part too
	    sensitive = &in->inPrivate.sensitiveArea;
	}
    // Need the name to initialize the object structure
    PublicMarshalAndComputeName(&in->inPublic.publicArea, &out->name);
    // Load and validate key
    result = ObjectLoad(object, NULL,
			&in->inPublic.publicArea, sensitive,
			RC_LoadExternal_inPublic, RC_LoadExternal_inPrivate,
			&out->name);
    if(result == TPM_RC_SUCCESS)
	{
	    object->attributes.external = SET;
	    // Set the common OBJECT attributes for a loaded object.
	    ObjectSetLoadedAttributes(object, in->hierarchy,
                                      // if anything can be derived from an external object,
                                      // we make sure it always uses the old algorithm
				      SEED_COMPAT_LEVEL_ORIGINAL); // libtpms added
	}
    return result;
}
#endif // CC_LoadExternal
#include "Tpm.h"
#include "ReadPublic_fp.h"
#if CC_ReadPublic  // Conditional expansion of this file
TPM_RC
TPM2_ReadPublic(
		ReadPublic_In   *in,            // IN: input parameter list
		ReadPublic_Out  *out            // OUT: output parameter list
		)
{
    OBJECT                  *object = HandleToObject(in->objectHandle);
    // Input Validation
    // Can not read public area of a sequence object
    if(ObjectIsSequence(object))
	return TPM_RC_SEQUENCE;

    // deliberately after ObjectIsSequence in case ObjectInSequence decides a
    // null object is a non-fatal error
    pAssert_RC(object != NULL);

    // Command Output
    out->outPublic.publicArea = object->publicArea;
    out->name = object->name;
    out->qualifiedName = object->qualifiedName;
    return TPM_RC_SUCCESS;
}
#endif // CC_ReadPublic
#include "Tpm.h"
#include "ActivateCredential_fp.h"
#if CC_ActivateCredential  // Conditional expansion of this file
#include "Object_spt_fp.h"
TPM_RC
TPM2_ActivateCredential(
			ActivateCredential_In   *in,            // IN: input parameter list
			ActivateCredential_Out  *out            // OUT: output parameter list
			)
{
    TPM_RC                   result = TPM_RC_SUCCESS;
    OBJECT                  *object;            // decrypt key
    OBJECT                  *activateObject;    // key associated with credential
    TPM2B_DATA               data;          // credential data
    // Input Validation
    // Get decrypt key pointer
    object = HandleToObject(in->keyHandle);
    // Get certificated object pointer
    activateObject = HandleToObject(in->activateHandle);
    // input decrypt key must be an asymmetric, restricted decryption key
    if(!CryptIsAsymAlgorithm(object->publicArea.type)
       || !IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, decrypt)
       || !IS_ATTRIBUTE(object->publicArea.objectAttributes,
			TPMA_OBJECT, restricted))
	return TPM_RCS_TYPE + RC_ActivateCredential_keyHandle;
    // Command output
    // Decrypt input credential data via asymmetric decryption.  A
    // TPM_RC_VALUE, TPM_RC_KEY or unmarshal errors may be returned at this
    // point
    result = CryptSecretDecrypt(object, NULL, IDENTITY_STRING, &in->secret, &data);
    if(result != TPM_RC_SUCCESS)
	{
	    if(result == TPM_RC_KEY)
		return TPM_RC_FAILURE;
	    return RcSafeAddToResult(result, RC_ActivateCredential_secret);
	}
    // this assertion is deliberately late, after other validation has happened
    // soas to not change existing behavior of the function
    pAssert_RC(activateObject != NULL);

    // Retrieve secret data.  A TPM_RC_INTEGRITY error or unmarshal
    // errors may be returned at this point
    result = CredentialToSecret(&in->credentialBlob.b,
				&activateObject->name.b,
				&data.b,
				object,
				&out->certInfo);
    if(result != TPM_RC_SUCCESS)
	return RcSafeAddToResult(result, RC_ActivateCredential_credentialBlob);
    return TPM_RC_SUCCESS;
}
#endif // CC_ActivateCredential
#include "Tpm.h"
#include "Unseal_fp.h"
#if CC_Unseal  // Conditional expansion of this file
TPM_RC
TPM2_Unseal(
	    Unseal_In           *in,
	    Unseal_Out          *out
	    )
{
    OBJECT                  *object;
    // Input Validation
    // Get pointer to loaded object
    object = HandleToObject(in->itemHandle);
    pAssert_RC(object != NULL);

    // Input handle must be a data object
    if(object->publicArea.type != TPM_ALG_KEYEDHASH)
	return TPM_RCS_TYPE + RC_Unseal_itemHandle;
    if(IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, decrypt)
       || IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, sign)
       || IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, restricted))
	return TPM_RCS_ATTRIBUTES + RC_Unseal_itemHandle;
    // Command Output
    // Copy data
    out->outData = object->sensitive.sensitive.bits;
    return TPM_RC_SUCCESS;
}
#endif // CC_Unseal

