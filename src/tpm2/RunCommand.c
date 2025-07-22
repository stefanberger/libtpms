// SPDX-License-Identifier: BSD-2-Clause

//**Introduction
// This module provides the platform specific entry and fail processing. The
// _plat__RunCommand() function is used to call to ExecuteCommand() in the TPM code.
// This function does whatever processing is necessary to set up the platform
// in anticipation of the call to the TPM including settup for error processing.
//
// The _plat__Fail() function is called when there is a failure in the TPM. The TPM
// code will have set the flag to indicate that the TPM is in failure mode.
// This call will then recursively call ExecuteCommand in order to build the
// failure mode response. When ExecuteCommand() returns to _plat__Fail(), the
// platform will do some platform specific operation to return to the environment in
// which the TPM is executing. For a simulator, setjmp/longjmp is used. For an OS,
// a system exit to the OS would be appropriate.

//** Includes and locals
#include "Platform.h"
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>

jmp_buf s_jumpBuffer;

// The following extern globals are copied here from Global.h to avoid including all of Tpm.h here.
// TODO: Improve the interface by which these values are shared.
extern BOOL g_inFailureMode;  // Indicates that the TPM is in failure mode
#if ALLOW_FORCE_FAILURE_MODE
extern BOOL g_forceFailureMode;  // flag to force failure mode during test
#endif
#if FAIL_TRACE
// The name of the function that triggered failure mode.
extern const char* s_failFunctionName;
#endif  // FAIL_TRACE
extern UINT32 s_failFunction;
extern UINT32 s_failLine;
extern UINT32 s_failCode;

//** Functions

//***_plat__RunCommand()
// This version of RunCommand will set up a jum_buf and call ExecuteCommand(). If
// the command executes without failing, it will return and RunCommand will return.
// If there is a failure in the command, then _plat__Fail() is called and it will
// longjump back to RunCommand which will call ExecuteCommand again. However, this
// time, the TPM will be in failure mode so ExecuteCommand will simply build
// a failure response and return.
LIB_EXPORT void _plat__RunCommand(
    uint32_t        requestSize,   // IN: command buffer size
    unsigned char*  request,       // IN: command buffer
    uint32_t*       responseSize,  // IN/OUT: response buffer size
    unsigned char** response       // IN/OUT: response buffer
)
{
    setjmp(s_jumpBuffer);
    ExecuteCommand(requestSize, request, responseSize, response);
}

//***_plat__Fail()
// This is the platform depended failure exit for the TPM.
LIB_EXPORT NORETURN void _plat__Fail(void)
{

#if ALLOW_FORCE_FAILURE_MODE
    // The simulator asserts during unexpected (i.e., un-forced) failure modes.
    if(!g_forceFailureMode)
    {
        fprintf(stderr, "Unexpected failure mode (code %d) in ", s_failCode);
#  if FAIL_TRACE
        fprintf(stderr, "function '%s' (line %d)\n", s_failFunctionName, s_failLine);
#  else   // FAIL_TRACE
        fprintf(stderr, "location code 0x%0x\n", s_locationCode);
#  endif  // FAIL_TRACE
        assert(FALSE);
    }

    // Clear the forced-failure mode flag for next time.
    g_forceFailureMode = FALSE;
#endif  // ALLOW_FORCE_FAILURE_MODE

    longjmp(&s_jumpBuffer[0], 1);
}
