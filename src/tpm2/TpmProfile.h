/********************************************************************************/
/*										*/
/*	Constants Reflecting a Particular TPM Implementation (e.g. PC Client)	*/
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
/*  (c) Copyright IBM Corp. and others, 2019 - 2023				*/
/*										*/
/********************************************************************************/

// FOR LIBTPMS: DO NOT EDIT THIS or INCLUDED FILES!
// ANY MODIFICATION WILL LEAD TO AN UNSUPPORTED CONFIGURATION

// The primary configuration file that collects all configuration options for a
// TPM build.
#ifndef _TPM_PROFILE_H_
#define _TPM_PROFILE_H_

#include "TpmBuildSwitches.h"
#include "TpmProfile_Common.h"
#include "TpmProfile_CommandList.h"
#include "TpmProfile_Misc.h"

// Table 0:7 - Defines for Implementation Values

#ifdef TPM_POSIX                       // libtpms added begin
# include <openssl/bn.h>
# ifdef THIRTY_TWO_BIT
#  define RADIX_BITS                     32
# endif
# ifdef SIXTY_FOUR_BIT_LONG
#  define RADIX_BITS                     64
# endif
# ifndef RADIX_BITS
#  error Need to determine RADIX_BITS value
# endif
#endif
#ifdef TPM_WINDOWS
#define  RADIX_BITS                      32
#endif                                 // libtpms added end

#ifndef HASH_LIB
#define HASH_LIB                        Ossl
#endif
#ifndef SYM_LIB
#define SYM_LIB                         Ossl
#endif
#ifndef MATH_LIB
#define MATH_LIB                        Ossl
#endif

#endif  // _TPM_PROFILE_H_
