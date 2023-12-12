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

//** Introduction
// This file defines error codes used in failure macros in the TPM Core Library.
// This file is part of TpmConfiguration because the Platform library can add error
// codes of it's own, and ultimately the specific error codes are a vendor decision
// because TPM2_GetTestResult returns manufacturer-defined data in failure mode.
// The only thing in this file that must be consistent with a vendor's implementation
// are the _names_ of error codes used by the core library.  Even the values can
// change and are only a suggestion.

#ifndef _TPMPROFILE_ERRORCODES_H
#define _TPMPROFILE_ERRORCODES_H

// turn off clang-format because alignment doesn't persist across comments
// with current settings
// clang-format off

#define FATAL_ERROR_ALLOCATION       (1)
#define FATAL_ERROR_DIVIDE_ZERO      (2)
#define FATAL_ERROR_INTERNAL         (3)
#define FATAL_ERROR_PARAMETER        (4)
#define FATAL_ERROR_ENTROPY          (5)
#define FATAL_ERROR_SELF_TEST        (6)
#define FATAL_ERROR_CRYPTO           (7)
#define FATAL_ERROR_NV_UNRECOVERABLE (8)

// indicates that the TPM has been re-manufactured after an
// unrecoverable NV error
#define FATAL_ERROR_REMANUFACTURED   (9)
#define FATAL_ERROR_DRBG             (10)
#define FATAL_ERROR_MOVE_SIZE        (11)
#define FATAL_ERROR_COUNTER_OVERFLOW (12)
#define FATAL_ERROR_SUBTRACT         (13)
#define FATAL_ERROR_MATHLIBRARY      (14)
// end of codes defined through v1.52

// leave space for numbers that may have been used by vendors or platforms.
// Ultimately this file and these ranges are only a suggestion because
// TPM2_GetTestResult returns manufacturer-defined data in failure mode.
// Reserve 15-499
#define FATAL_ERROR_RESERVED_START   (15)
#define FATAL_ERROR_RESERVED_END     (499)

// Additional error codes defined by TPM library:
#define FATAL_ERROR_ASSERT           (500)
// Platform library violated interface contract.
#define FATAL_ERROR_PLATFORM         (600)

// Test/Simulator errors 1000+
#define FATAL_ERROR_FORCED           (1000)

#endif  // _TPMPROFILE_ERRORCODES_H
