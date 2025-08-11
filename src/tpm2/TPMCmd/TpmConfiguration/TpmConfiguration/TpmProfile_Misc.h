/********************************************************************************/
/*										*/
/*						*/
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
/*  (c) Copyright IBM Corp. and others, 2023				  	*/
/*										*/
/********************************************************************************/

// Misc profile settings that don't currently have a better home.
// These are rarely changed, but available for vendor customization.

#ifndef _TPM_PROFILE_MISC_H_
#define _TPM_PROFILE_MISC_H_

// YES & NO defined by TpmBuildSwitches.h
#if(YES != 1 || NO != 0)
#  error YES or NO incorrectly set
#endif

// clang-format off
// clang-format off to preserve horizontal spacing
#define IMPLEMENTATION_PCR         24
#define PLATFORM_PCR               24
#define DRTM_PCR                   17
#define HCRTM_PCR                  0
#define NUM_LOCALITIES             5
#define MAX_HANDLE_NUM             3
#define MAX_ACTIVE_SESSIONS        64
#define MAX_LOADED_SESSIONS        3
#define MAX_SESSION_NUM            3
#define MAX_LOADED_OBJECTS         3
#define MIN_EVICT_OBJECTS          7	/* libtpms: for PC client */
#define NUM_POLICY_PCR_GROUP       1
#define NUM_AUTHVALUE_PCR_GROUP    1
//#define MAX_CONTEXT_SIZE           2168
#define MAX_CONTEXT_SIZE           2680	/* libtpms: changed for RSA-3072 */
#define MAX_DIGEST_BUFFER          1024
#define MAX_NV_INDEX_SIZE          2048
#define MAX_NV_BUFFER_SIZE         1024
#define MAX_CAP_BUFFER             1024
/* libtmps: 65 OBJECTs in USER NVRAM expanded by 704 bytes due to size
 * increase of OBJECT from 2048 bit RSA keys to 3072 bit by 704 bytes*/
#define NV_MEMORY_SIZE                  (128 * 1024 + 65 * 704)  /* libtpms changed */
#define MIN_COUNTER_INDICES        8
#define NUM_STATIC_PCR             16
#define MAX_ALG_LIST_SIZE          64
#define PRIMARY_SEED_SIZE          64 /* libtpms: 64 per define USE_SPEC_COMPLIANT_PROOFS */
#define CONTEXT_ENCRYPT_ALGORITHM  AES
#define NV_CLOCK_UPDATE_INTERVAL   12 /* libtpms: keep old value */
#define NUM_POLICY_PCR             1

#define ORDERLY_BITS               8
#define MAX_SYM_DATA               128
#define MAX_RNG_ENTROPY_SIZE       64
#define RAM_INDEX_SPACE            512
#define ENABLE_PCR_NO_INCREMENT    YES

#define SIZE_OF_X509_SERIAL_NUMBER 20

// amount of space the platform can provide in PERSISTENT_DATA during
// manufacture
#define PERSISTENT_DATA_PLATFORM_SPACE  0	/* libtpms: changed from '16' */

// structure padding space for these structures.  Used if a
// particular configuration needs them to be aligned to a
// specific size
#define ORDERLY_DATA_PADDING            0
#define STATE_CLEAR_DATA_PADDING        0
#define STATE_RESET_DATA_PADDING        0

// configuration values that may vary by SIMULATION/DEBUG
#if SIMULATION && DEBUG
// This forces the use of a smaller context slot size. This reduction reduces the
// range of the epoch allowing the tester to force the epoch to occur faster than
// the normal production size
#  define CONTEXT_SLOT UINT8
#  error SIMULATION & DEBUG is not supported /* libtpms: added */
#else
#  define CONTEXT_SLOT UINT16		/* libtpms: changed from UINT8 in v0.9.0 */
#endif

#endif  // _TPM_PROFILE_MISC_H_
