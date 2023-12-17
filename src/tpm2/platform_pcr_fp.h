/********************************************************************************/
/*										*/
/*						     				*/
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

#ifndef _PLATFORM_PCR_FP_H_
#define _PLATFORM_PCR_FP_H_

#include "BaseTypes.h"
#include "TpmTypes.h"
#include "pcrstruct.h"

// return the number of PCRs the platform recognizes for GetPcrInitializationAttributes.
// PCRs are numbered starting at zero.
// Note: The TPM Library will enter failure mode if this number doesn't match
// IMPLEMENTATION_PCR.
UINT32 _platPcr__NumberOfPcrs(void);

// return the initialization attributes of a given PCR.
// pcrNumber expected to be in [0, _platPcr__NumberOfPcrs)
// returns the attributes for PCR[0] if the requested pcrNumber is out of range.
// Note this returns a structure by-value, which is fast because the structure is
// a bitfield.
PCR_Attributes _platPcr__GetPcrInitializationAttributes(UINT32 pcrNumber);

// Fill a given buffer with the PCR initialization value for a particular PCR and hash
// combination, and return its length.  If the platform doesn't have a value, then
// the result size is expected to be zero, and the rfunction will return TPM_RC_PCR.
// If a valid is not available, then the core TPM library will ignore the value and
// treat it as non-existant and provide a default.
// If the buffer is not large enough for a pcr consistent with pcrAlg, then the
// platform will return TPM_RC_FAILURE.
TPM_RC _platPcr__GetInitialValueForPcr(
				       UINT32     pcrNumber,        // IN: PCR to be initialized
				       TPM_ALG_ID pcrAlg,           // IN: Algorithm of the PCR Bank being initialized
				       BYTE       startupLocality,  // IN: locality where startup is being called from
				       BYTE*      pcrBuffer,        // OUT: buffer to put PCR initialization value into
				       uint16_t   bufferSize,       // IN: maximum size of value buffer can hold
				       uint16_t*  pcrLength);  // OUT: size of initialization value returned in pcrBuffer

// should the given PCR algorithm default to active in a new TPM?
BOOL _platPcr_IsPcrBankDefaultActive(TPM_ALG_ID pcrAlg);

#endif  // _PLATFORM_PCR_FP_H_
