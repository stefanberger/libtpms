/********************************************************************************/
/*										*/
/*			     ExecCommand					*/
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

//** Introduction
//
// This file contains the entry function ExecuteCommand() which provides the main
// control flow for TPM command execution.

//** Includes

#include "Tpm.h"
#include "Marshal.h"
// TODO_RENAME_INC_FOLDER:platform_interface refers to the TPM_CoreLib platform interface
#include "ExecCommand_fp.h"	// libtpms changed

// Uncomment this next #include if doing static command/response buffer sizing
// #include "CommandResponseSizes_fp.h"

#define TPM_HAVE_TPM2_DECLARATIONS
#include "tpm_library_intern.h"  // libtpms added

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
)
{
    // Command local variables
    UINT32  commandSize;
    COMMAND command;

    // Response local variables
    UINT32 maxResponse = *responseSize;
    TPM_RC result;  // return code for the command

    /* check for an unreasonably large command size, since it's cast to a signed integer later */
    if (requestSize > INT32_MAX) {
	result = TPM_RC_SUCCESS;
	goto Cleanup;
    }
    // This next function call is used in development to size the command and response
    // buffers. The values printed are the sizes of the internal structures and
    // not the sizes of the canonical forms of the command response structures. Also,
    // the sizes do not include the tag, command.code, requestSize, or the authorization
    // fields.
    //CommandResponseSizes();
    // Set flags for NV access state. This should happen before any other
    // operation that may require a NV write. Note, that this needs to be done
    // even when in failure mode. Otherwise, g_updateNV would stay SET while in
    // Failure mode and the NV would be written on each call.
    g_updateNV     = UT_NONE;
    g_clearOrderly = FALSE;
    if(g_inFailureMode)
    {
        // Do failure mode processing
        TpmFailureMode(requestSize, request, responseSize, response);
        return;
    }
    // Query platform to get the NV state.  The result state is saved internally
    // and will be reported by NvIsAvailable(). The reference code requires that
    // accessibility of NV does not change during the execution of a command.
    // Specifically, if NV is available when the command execution starts and then
    // is not available later when it is necessary to write to NV, then the TPM
    // will go into failure mode.
    NvCheckState();

    // Due to the limitations of the simulation, TPM clock must be explicitly
    // synchronized with the system clock whenever a command is received.
    // This function call is not necessary in a hardware TPM. However, taking
    // a snapshot of the hardware timer at the beginning of the command allows
    // the time value to be consistent for the duration of the command execution.
    TimeUpdateToCurrent();

    // Any command through this function will unceremoniously end the
    // _TPM_Hash_Data/_TPM_Hash_End sequence.
    if(g_DRTMHandle != TPM_RH_UNASSIGNED)
        ObjectTerminateEvent();

    // Get command buffer size and command buffer.
    command.tag = 0;				// libtpms added: Coverity
    command.parameterBuffer = request;
    command.parameterSize   = requestSize;

    // Parse command header: tag, commandSize and command.code.
    // First parse the tag. The unmarshaling routine will validate
    // that it is either TPM_ST_SESSIONS or TPM_ST_NO_SESSIONS.
    result = TPMI_ST_COMMAND_TAG_Unmarshal(
        &command.tag, &command.parameterBuffer, &command.parameterSize);
    if(result != TPM_RC_SUCCESS)
        goto Cleanup;
    // Unmarshal the commandSize indicator.
    result = UINT32_Unmarshal(
        &commandSize, &command.parameterBuffer, &command.parameterSize);
    if(result != TPM_RC_SUCCESS)
        goto Cleanup;
    // On a TPM that receives bytes on a port, the number of bytes that were
    // received on that port is requestSize it must be identical to commandSize.
    // In addition, commandSize must not be larger than MAX_COMMAND_SIZE allowed
    // by the implementation. The check against MAX_COMMAND_SIZE may be redundant
    // as the input processing (the function that receives the command bytes and
    // places them in the input buffer) would likely have the input truncated when
    // it reaches MAX_COMMAND_SIZE, and requestSize would not equal commandSize.
    if(commandSize != requestSize || commandSize > MAX_COMMAND_SIZE)
    {
        result = TPM_RC_COMMAND_SIZE;
        goto Cleanup;
    }
    // Unmarshal the command code.
    result = TPM_CC_Unmarshal(
        &command.code, &command.parameterBuffer, &command.parameterSize);
    if(result != TPM_RC_SUCCESS)
        goto Cleanup;
    // Check to see if the command is implemented.
    command.index = CommandCodeToCommandIndex(command.code);
    if(UNIMPLEMENTED_COMMAND_INDEX == command.index)
    {
        result = TPM_RC_COMMAND_CODE;
        goto Cleanup;
    }
#if FIELD_UPGRADE_IMPLEMENTED == YES
    // If the TPM is in FUM, then the only allowed command is
    // TPM_CC_FieldUpgradeData.
    if(IsFieldUgradeMode() && (command.code != TPM_CC_FieldUpgradeData))
    {
        result = TPM_RC_UPGRADE;
        goto Cleanup;
    }
    else
#endif
        // Excepting FUM, the TPM only accepts TPM2_Startup() after
        // _TPM_Init. After getting a TPM2_Startup(), TPM2_Startup()
        // is no longer allowed.
        if((!TPMIsStarted() && command.code != TPM_CC_Startup)
           || (TPMIsStarted() && command.code == TPM_CC_Startup))
        {
            result = TPM_RC_INITIALIZE;
            goto Cleanup;
        }
    // Start regular command process.
    NvIndexCacheInit();
    // Parse Handle buffer.
    result = ParseHandleBuffer(&command);
    if(result != TPM_RC_SUCCESS)
        goto Cleanup;
    // All handles in the handle area are required to reference TPM-resident
    // entities.
    result = EntityGetLoadStatus(&command);
    if(result != TPM_RC_SUCCESS)
        goto Cleanup;
    // Authorization session handling for the command.
    ClearCpRpHashes(&command);
    if(command.tag == TPM_ST_SESSIONS)
    {
        // Find out session buffer size.
        result = UINT32_Unmarshal((UINT32*)&command.authSize,
                                  &command.parameterBuffer,
                                  &command.parameterSize);
        if(result != TPM_RC_SUCCESS)
            goto Cleanup;
        // Perform sanity check on the unmarshaled value. If it is smaller than
        // the smallest possible session or larger than the remaining size of
        // the command, then it is an error. NOTE: This check could pass but the
        // session size could still be wrong. That will be determined after the
        // sessions are unmarshaled.
        if(command.authSize < 9 || command.authSize > command.parameterSize)
        {
            result = TPM_RC_SIZE;
            goto Cleanup;
        }
        command.parameterSize -= command.authSize;

        // The actions of ParseSessionBuffer() are described in the introduction.
        // As the sessions are parsed command.parameterBuffer is advanced so, on a
        // successful return, command.parameterBuffer should be pointing at the
        // first byte of the parameters.
        result = ParseSessionBuffer(&command);
        if(result != TPM_RC_SUCCESS)
            goto Cleanup;
    }
    else
    {
        command.authSize = 0;
        // The command has no authorization sessions.
        // If the command requires authorizations, then CheckAuthNoSession() will
        // return an error.
        result = CheckAuthNoSession(&command);
        if(result != TPM_RC_SUCCESS)
            goto Cleanup;
    }
    // Set up the response buffer pointers. CommandDispatch will marshal the
    // response parameters starting at the address in command.responseBuffer.
    //*response = MemoryGetResponseBuffer(command.index);
    // leave space for the command header
    command.responseBuffer = *response + STD_RESPONSE_HEADER;

    // leave space for the parameter size field if needed
    if(command.tag == TPM_ST_SESSIONS)
        command.responseBuffer += sizeof(UINT32);
    if(IsHandleInResponse(command.index))
        command.responseBuffer += sizeof(TPM_HANDLE);

    // CommandDispatcher returns a response handle buffer and a response parameter
    // buffer if it succeeds. It will also set the parameterSize field in the
    // buffer if the tag is TPM_RC_SESSIONS.
    result = CommandDispatcher(&command);
    if(result != TPM_RC_SUCCESS)
        goto Cleanup;

    // Build the session area at the end of the parameter area.
    result = BuildResponseSession(&command);
    if(result != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }

Cleanup:
    if(g_clearOrderly == TRUE && NV_IS_ORDERLY)
    {
#if USE_DA_USED
        gp.orderlyState = g_daUsed ? SU_DA_USED_VALUE : SU_NONE_VALUE;
#else
        gp.orderlyState = SU_NONE_VALUE;
#endif
        NV_SYNC_PERSISTENT(orderlyState);
    }
    // This implementation loads an "evict" object to a transient object slot in
    // RAM whenever an "evict" object handle is used in a command so that the
    // access to any object is the same. These temporary objects need to be
    // cleared from RAM whether the command succeeds or fails.
    ObjectCleanupEvict();

    // The parameters and sessions have been marshaled. Now tack on the header and
    // set the sizes
    BuildResponseHeader(&command, *response, result);

    // Try to commit all the writes to NV if any NV write happened during this
    // command execution. This check should be made for both succeeded and failed
    // commands, because a failed one may trigger a NV write in DA logic as well.
    // This is the only place in the command execution path that may call the NV
    // commit. If the NV commit fails, the TPM should be put in failure mode.
    if((g_updateNV != UT_NONE) && !g_inFailureMode)
    {
        if(g_updateNV == UT_ORDERLY)
            NvUpdateIndexOrderlyData();
        if(!NvCommit())
            FAIL(FATAL_ERROR_INTERNAL);
        g_updateNV = UT_NONE;
    }
    pAssert((UINT32)command.parameterSize <= maxResponse);

    // Clear unused bits in response buffer.
    MemorySet(*response + *responseSize, 0, maxResponse - *responseSize);

    // as a final act, and not before, update the response size.
    *responseSize = (UINT32)command.parameterSize;

    return;
}
