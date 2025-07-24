/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: ExecCommand_fp.h 1490 2019-07-26 21:13:22Z kgoldman $			*/
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
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _EXEC_COMMAND_FP_H_
#define _EXEC_COMMAND_FP_H_

//** ExecuteCommand()
//
// The function performs the following steps.
//
//  a)  Parses the command header from input buffer.
//  b)  Calls ParseHandleBuffer() to parse the handle area of the command.
//  c)  Validates that each of the handles references a loaded entity.
//  d)  Calls ParseSessionBuffer () to:
//      1)  unmarshal and parse the session area;
//      2)  check the authorizations; and
//      3)  when necessary, decrypt a parameter.
//  e)  Calls CommandDispatcher() to:
//      1)  unmarshal the command parameters from the command buffer;
//      2)  call the routine that performs the command actions; and
//      3)  marshal the responses into the response buffer.
//  f)  If any error occurs in any of the steps above create the error response
//      and return.
//  g)  Calls BuildResponseSession() to:
//      1)  when necessary, encrypt a parameter
//      2)  build the response authorization sessions
//      3)  update the audit sessions and nonces
//  h)  Calls BuildResponseHeader() to complete the construction of the response.
//
// 'responseSize' is set by the caller to the maximum number of bytes available in
// the output buffer. ExecuteCommand will adjust the value and return the number
// of bytes placed in the buffer.
//
// 'response' is also set by the caller to indicate the buffer into which
//  ExecuteCommand is to place the response.
//
//  'request' and 'response' may point to the same buffer
//
// Note: As of February, 2016, the failure processing has been moved to the
// platform-specific code. When the TPM code encounters an unrecoverable failure, it
// will SET g_inFailureMode and call _plat__Fail(). That function should not return
// but may call ExecuteCommand().
//
LIB_EXPORT void ExecuteCommand(
    uint32_t        requestSize,   // IN: command buffer size
    unsigned char*  request,       // IN: command buffer
    uint32_t*       responseSize,  // IN/OUT: response buffer size
    unsigned char** response       // IN/OUT: response buffer
);

#endif  // _EXEC_COMMAND_FP_H_
