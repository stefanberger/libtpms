/********************************************************************************/
/*										*/
/*			Performs the manufacturing of the TPM			*/
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

#ifndef _MANUFACTURE_FP_H_
#define _MANUFACTURE_FP_H_

//*** TPM_Manufacture()
// This function initializes the TPM values in preparation for the TPM's first
// use. This function will fail if previously called. The TPM can be re-manufactured
// by calling TPM_Teardown() first and then calling this function again.
// NV must be enabled first (typically with NvPowerOn() via _TPM_Init)
//
// return type: int
//      -2          NV System not available
//      -1          FAILURE - System is incorrectly compiled.
//      0           success
//      1           manufacturing process previously performed
// returns
#define MANUF_NV_NOT_READY   (-2)
#define MANUF_INVALID_CONFIG (-1)
#define MANUF_OK             0
#define MANUF_ALREADY_DONE   1
// params
#define MANUF_FIRST_TIME    1
#define MANUF_REMANUFACTURE 0
LIB_EXPORT int TPM_Manufacture(
			       int firstTime, // IN: indicates if this is the first call from
			       //     main()
			       const char     *profile	// libtpms added
			       );

//*** TPM_TearDown()
// This function prepares the TPM for re-manufacture. It should not be implemented
// in anything other than a simulated TPM.
//
// In this implementation, all that is needs is to stop the cryptographic units
// and set a flag to indicate that the TPM can be re-manufactured. This should
// be all that is necessary to start the manufacturing process again.
//  Return Type: int
//      0        success
//      1        TPM not previously manufactured
#define TEARDOWN_OK          0
#define TEARDOWN_NOTHINGDONE 1
LIB_EXPORT int TPM_TearDown(void);

//*** TpmEndSimulation()
// This function is called at the end of the simulation run. It is used to provoke
// printing of any statistics that might be needed.
LIB_EXPORT void TpmEndSimulation(void);

#endif  // _MANUFACTURE_FP_H_

