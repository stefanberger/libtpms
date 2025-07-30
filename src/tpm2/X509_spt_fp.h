/********************************************************************************/
/*										*/
/*			X509 Support 		 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: X509_spt_fp.h 1490 2019-07-26 21:13:22Z kgoldman $		*/
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
/*  (c) Copyright IBM Corp. and others, 2019.					*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Nov 14, 2019  Time: 05:57:02PM
 */

#ifndef _X509_SPT_FP_H_
#define _X509_SPT_FP_H_

//*** X509FindExtensionByOID()
// This will search a list of X509 extensions to find an extension with the
// requested OID. If the extension is found, the output context ('ctx') is set up
// to point to the OID in the extension.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure (could be catastrophic)
BOOL X509FindExtensionByOID(ASN1UnmarshalContext* ctxIn,  // IN: the context to search
                            ASN1UnmarshalContext* ctx,  // OUT: the extension context
                            const BYTE*           OID   // IN: oid to search for
);

//*** X509GetExtensionBits()
// This function will extract a bit field from an extension. If the extension doesn't
// contain a bit string, it will fail.
// Return Type: BOOL
//  TRUE(1)         success
//  FALSE(0)        failure
UINT32
X509GetExtensionBits(ASN1UnmarshalContext* ctx, UINT32* value);

//***X509ProcessExtensions()
// This function is used to process the TPMA_OBJECT and KeyUsage extensions. It is not
// in the CertifyX509.c code because it makes the code harder to follow.
// Return Type: TPM_RC
//      TPM_RCS_ATTRIBUTES      the attributes of object are not consistent with
//                              the extension setting
//      TPM_RC_VALUE            problem parsing the extensions
TPM_RC
X509ProcessExtensions(
    OBJECT* object,       // IN: The object with the attributes to
                          //      check
    stringRef* extension  // IN: The start and length of the extensions
);

//*** X509AddSigningAlgorithm()
// This creates the singing algorithm data.
// Return Type: INT16
//  > 0                 number of octets added
// <= 0                 failure
INT16
X509AddSigningAlgorithm(
    ASN1MarshalContext* ctx, OBJECT* signKey, TPMT_SIG_SCHEME* scheme);

//*** X509AddPublicKey()
// This function will add the publicKey description to the DER data. If fillPtr is
// NULL, then no data is transferred and this function will indicate if the TPM
// has the values for DER-encoding of the public key.
//  Return Type: INT16
//      > 0         number of octets added
//      == 0        failure
INT16
X509AddPublicKey(ASN1MarshalContext* ctx, OBJECT* object);

//*** X509PushAlgorithmIdentifierSequence()
// The function adds the algorithm identifier sequence.
//  Return Type: INT16
//      > 0         number of bytes added
//     == 0         failure
INT16
X509PushAlgorithmIdentifierSequence(ASN1MarshalContext* ctx, const BYTE* OID);

#endif  // _X509_SPT_FP_H_
