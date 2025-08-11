/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CryptSelfTest_fp.h 1490 2019-07-26 21:13:22Z kgoldman $			*/
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
/*  (c) Copyright IBM Corp. and others, 2016					*/
/*										*/
/********************************************************************************/

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar  4, 2020  Time: 02:36:44PM
 */

#ifndef _CRYPT_SELF_TEST_FP_H_
#define _CRYPT_SELF_TEST_FP_H_

//*** CryptSelfTest()
// This function is called to start/complete a full self-test.
// If 'fullTest' is NO, then only the untested algorithms will be run. If
// 'fullTest' is YES, then 'g_untestedDecryptionAlgorithms' is reinitialized and then
// all tests are run.
// This implementation of the reference design does not support processing outside
// the framework of a TPM command. As a consequence, this command does not
// complete until all tests are done. Since this can take a long time, the TPM
// will check after each test to see if the command is canceled. If so, then the
// TPM will returned TPM_RC_CANCELLED. To continue with the self-tests, call
// TPM2_SelfTest(fullTest == No) and the TPM will complete the testing.
//  Return Type: TPM_RC
//      TPM_RC_CANCELED        if the command is canceled
LIB_EXPORT
TPM_RC
CryptSelfTest(TPMI_YES_NO fullTest  // IN: if full test is required
);

//*** CryptIncrementalSelfTest()
// This function is used to perform an incremental self-test. This implementation
// will perform the toTest values before returning. That is, it assumes that the
// TPM cannot perform background tasks between commands.
//
// This command may be canceled. If it is, then there is no return result.
// However, this command can be run again and the incremental progress will not
// be lost.
//  Return Type: TPM_RC
//      TPM_RC_CANCELED         processing of this command was canceled
//      TPM_RC_TESTING          if toTest list is not empty
//      TPM_RC_VALUE            an algorithm in the toTest list is not implemented
TPM_RC
CryptIncrementalSelfTest(TPML_ALG* toTest,   // IN: list of algorithms to be tested
                         TPML_ALG* toDoList  // OUT: list of algorithms needing test
);

//*** CryptInitializeToTest()
// This function will initialize the data structures for testing all the
// algorithms. This should not be called unless CryptAlgsSetImplemented() has
// been called
void CryptInitializeToTest(void);

//*** CryptTestAlgorithm()
// Only point of contact with the actual self tests. If a self-test fails, there
// is no return and the TPM goes into failure mode.
// The call to TestAlgorithm uses an algorithm selector and a bit vector. When the
// test is run, the corresponding bit in 'toTest' and in 'g_toTest' is CLEAR. If
// 'toTest' is NULL, then only the bit in 'g_toTest' is CLEAR.
// There is a special case for the call to TestAlgorithm(). When 'alg' is
// ALG_ERROR, TestAlgorithm() will CLEAR any bit in 'toTest' for which it has
// no test. This allows the knowledge about which algorithms have test to be
// accessed through the interface that provides the test.
//  Return Type: TPM_RC
//      TPM_RC_CANCELED     test was canceled
LIB_EXPORT
TPM_RC
CryptTestAlgorithm(TPM_ALG_ID alg, ALGORITHM_VECTOR* toTest);

#endif  // _CRYPT_SELF_TEST_FP_H_
