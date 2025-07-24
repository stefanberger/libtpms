/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: NVReserved_fp.h 1476 2019-06-10 19:32:03Z kgoldman $			*/
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
 *  Date: Apr  2, 2019  Time: 04:23:27PM
 */

#ifndef _NV_RESERVED_FP_H_
#define _NV_RESERVED_FP_H_

#include "NVMarshal.h" /* libtpms added */

//*** NvCheckState()
// Function to check the NV state by accessing the platform-specific function
// to get the NV state.  The result state is registered in s_NvIsAvailable
// that will be reported by NvIsAvailable.
//
// This function is called at the beginning of ExecuteCommand before any potential
// check of g_NvStatus.
void NvCheckState(void);

//*** NvCommit
// This is a wrapper for the platform function to commit pending NV writes.
BOOL NvCommit(void);

//*** NvPowerOn()
//  This function is called at _TPM_Init to initialize the NV environment.
//  Return Type: BOOL
//      TRUE(1)         all NV was initialized
//      FALSE(0)        the NV containing saved state had an error and
//                      TPM2_Startup(CLEAR) is required
BOOL NvPowerOn(void);

//*** NvManufacture()
// This function initializes the NV system at pre-install time.
//
// This function should only be called in a manufacturing environment or in a
// simulation.
//
// The layout of NV memory space is an implementation choice.
void NvManufacture(void);

//*** NvRead()
// This function is used to move reserved data from NV memory to RAM.
void NvRead(void*  outBuffer,  // OUT: buffer to receive data
            UINT32 nvOffset,   // IN: offset in NV of value
            UINT32 size        // IN: size of the value to read
);

//*** NvWrite()
// This function is used to post reserved data for writing to NV memory. Before
// the TPM completes the operation, the value will be written.
BOOL NvWrite(UINT32 nvOffset,  // IN: location in NV to receive data
             UINT32 size,      // IN: size of the data to move
             void*  inBuffer   // IN: location containing data to write
);

//*** NvUpdatePersistent()
// This function is used to update a value in the PERSISTENT_DATA structure and
// commits the value to NV.
void NvUpdatePersistent(
    UINT32 offset,  // IN: location in PERMANENT_DATA to be updated
    UINT32 size,    // IN: size of the value
    void*  buffer   // IN: the new data
);

//*** NvClearPersistent()
// This function is used to clear a persistent data entry and commit it to NV
void NvClearPersistent(UINT32 offset,  // IN: the offset in the PERMANENT_DATA
                                       //     structure to be cleared (zeroed)
                       UINT32 size     // IN: number of bytes to clear
);

//*** NvReadPersistent()
// This function reads persistent data to the RAM copy of the 'gp' structure.
void NvReadPersistent(void);

#endif  // _NV_RESERVED_FP_H_
