/********************************************************************************/
/*										*/
/*			 NV read and write access methods			*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2024				*/
/*										*/
/********************************************************************************/

//** Description
//
//    This file contains the NV read and write access methods.  This implementation
//    uses RAM/file and does not manage the RAM/file as NV blocks.
//    The implementation may become more sophisticated over time.
//

//** Includes and Local
#include <memory.h>
#include <string.h>
#include <assert.h>
#include "Platform.h"
/* libtpms added begin */
#include "NVMarshal.h"
#include "LibtpmsCallbacks.h"
#include <errno.h>
#define TPM_HAVE_TPM2_DECLARATIONS
#include "tpm_library_intern.h"
/* libtpms added end */

#if FILE_BACKED_NV
#  include <stdio.h>
static FILE* s_NvFile           = NULL;
static int   s_NeedsManufacture = FALSE;
#endif

//**Functions

#if FILE_BACKED_NV
const char* s_NvFilePath = "NVChip";

//*** NvFileOpen()
// This function opens the file used to hold the NV image.
//  Return Type: int
//  >= 0        success
//  -1          error
static int NvFileOpen(const char* mode)
{
    // Try to open an exist NVChip file for read/write
#  if defined _MSC_VER && 1
    if(fopen_s(&s_NvFile, s_NvFilePath, mode) != 0)
	{
	    s_NvFile = NULL;
	}
#  else
    s_NvFile = fopen(s_NvFilePath, mode);
#  endif
    return (s_NvFile == NULL) ? -1 : 0;
}

//*** NvFileCommit()
// Write all of the contents of the NV image to a file.
//  Return Type: int
//      TRUE(1)         success
//      FALSE(0)        failure
static int NvFileCommit(void)
{
    int OK;
    // If NV file is not available, return failure
    if(s_NvFile == NULL)
	return 1;
    // Write RAM data to NV
    fseek(s_NvFile, 0, SEEK_SET);
    OK = (NV_MEMORY_SIZE == fwrite(s_NV, 1, NV_MEMORY_SIZE, s_NvFile));
    OK = OK && (0 == fflush(s_NvFile));
    assert(OK);
    return OK;
}

//*** NvFileSize()
// This function gets the size of the NV file and puts the file pointer where desired
// using the seek method values. SEEK_SET => beginning; SEEK_CUR => current position
// and SEEK_END => to the end of the file.
static long NvFileSize(int leaveAt)
{
    int	 irc;	/* kgold, added return code checks */
    long fileSize;
    long filePos;
    //
    assert(NULL != s_NvFile);

    filePos = ftell(s_NvFile);  // libtpms changed begin
    if (filePos < 0)
        return -1;              // libtpms changed end

    int fseek_result = fseek(s_NvFile, 0, SEEK_END);
    NOT_REFERENCED(fseek_result);  // Fix compiler warning for NDEBUG
    assert(fseek_result == 0);
    fileSize = ftell(s_NvFile);
    assert(fileSize >= 0);
    switch(leaveAt)
	{
	  case SEEK_SET:
	    filePos = 0;
	    /* fall through */
	  case SEEK_CUR:
	    irc = fseek(s_NvFile, filePos, SEEK_SET);
	    assert(irc == 0);
	    break;
	  case SEEK_END:
	    break;
	  default:
	    assert(FALSE);
	    break;
	}
    return fileSize;
}
#endif

#if 0 /* libtpms added */
//*** _plat__NvErrors()
// This function is used by the simulator to set the error flags in the NV
// subsystem to simulate an error in the NV loading process
LIB_EXPORT void _plat__NvErrors(int recoverable, int unrecoverable)
{
    s_NV_unrecoverable = unrecoverable;
    s_NV_recoverable   = recoverable;
}
#endif /* libtpms added */

//***_plat__NVEnable()
// Enable NV memory.
//
// This version just pulls in data from a file. In a real TPM, with NV on chip,
// this function would verify the integrity of the saved context. If the NV
// memory was not on chip but was in something like RPMB, the NV state would be
// read in, decrypted and integrity checked.
//
// The recovery from an integrity failure depends on where the error occurred. It
// it was in the state that is discarded by TPM Reset, then the error is
// recoverable if the TPM is reset. Otherwise, the TPM must go into failure mode.
//  Return Type: int
//      0           if success
//      > 0         if receive recoverable error
//      <0          if unrecoverable error
#define NV_ENABLE_SUCCESS 0
#define NV_ENABLE_FAILED  (-1)
LIB_EXPORT int _plat__NVEnable(
			       void*  platParameter,  // platform specific parameter
			       size_t paramSize       // size of parameter. If size == 0, then
			       // parameter is a sizeof(void*) scalar and should
			       // be cast to an integer (intptr_t), not dereferenced.
			       )
{
    NOT_REFERENCED(platParameter);  // to keep compiler quiet
    NOT_REFERENCED(paramSize);      // to keep compiler quiet
#ifdef TPM_LIBTPMS_CALLBACKS
    int ret;
#endif
    //
    // Start assuming everything is OK
    s_NV_unrecoverable = FALSE;
    s_NV_recoverable = FALSE;

#ifdef TPM_LIBTPMS_CALLBACKS
    ret = libtpms_plat__NVEnable();
    if (ret != LIBTPMS_CALLBACK_FALLTHROUGH)
        return ret;
#endif /* TPM_LIBTPMS_CALLBACKS */
    return _plat__NVEnable_NVChipFile(platParameter);
}

int
_plat__NVEnable_NVChipFile(
		void            *platParameter  // IN: platform specific parameters
		)
{
    NOT_REFERENCED(platParameter);          // to keep compiler quiet
    //
    // Start assuming everything is OK
    s_NV_unrecoverable = FALSE;
    s_NV_recoverable   = FALSE;
#if FILE_BACKED_NV
    if(s_NvFile != NULL)
	return NV_ENABLE_SUCCESS;
    // Initialize all the bytes in the ram copy of the NV
    _plat__NvMemoryClear(0, NV_MEMORY_SIZE);

    // If the file exists
    if(NvFileOpen("r+b") >= 0)
	{
	    long fileSize = NvFileSize(SEEK_SET);  // get the file size and leave the
	    // file pointer at the start
	    //
	    // If the size is right, read the data
	    if(NV_MEMORY_SIZE == fileSize)
		{
		    s_NeedsManufacture = fread(s_NV, 1, NV_MEMORY_SIZE, s_NvFile)
					 != NV_MEMORY_SIZE;
		    if (s_NeedsManufacture) {			// libtpms changes start: set s_NV_unrecoverable on error
		        s_NV_unrecoverable = TRUE;
		        TPMLIB_LogTPM2Error("Could not read NVChip file: %s\n",
			                    strerror(errno));	// libtpms changes end
		    }
		}
	    else
		{
		    NvFileCommit();  // for any other size, initialize it
		    s_NeedsManufacture = TRUE;
		}
	}
    // If NVChip file does not exist, try to create it for read/write.
    else if(NvFileOpen("w+b") >= 0)
	{
	    NvFileCommit();  // Initialize the file
	    s_NeedsManufacture = TRUE;
	}
    assert(NULL != s_NvFile);  // Just in case we are broken for some reason.
#endif
    // NV contents have been initialized and the error checks have been performed. For
    // simulation purposes, use the signaling interface to indicate if an error is
    // to be simulated and the type of the error.
    if(s_NV_unrecoverable)
	return NV_ENABLE_FAILED;
    s_NvIsAvailable = TRUE;
    return s_NV_recoverable;
}

//***_plat__NVDisable()
// Disable NV memory
LIB_EXPORT void _plat__NVDisable(
				 void*  platParameter,  // platform specific parameter
				 size_t paramSize       // size of parameter. If size == 0, then
				 // parameter is a sizeof(void*) scalar and should
				 // be cast to an integer (intptr_t), not dereferenced.
				 )
{
    NOT_REFERENCED(paramSize);  // to keep compiler quiet
    int delete = ((intptr_t)platParameter != 0)
		 ? TRUE
		 : FALSE;  // IN: If TRUE (!=0), delete the NV contents.

#ifdef TPM_LIBTPMS_CALLBACKS
    int ret = libtpms_plat__NVDisable();
    if (ret != LIBTPMS_CALLBACK_FALLTHROUGH)
        return;
#endif /* TPM_LIBTPMS_CALLBACKS */

#if FILE_BACKED_NV
    if(NULL != s_NvFile)
	{
	    fclose(s_NvFile);  // Close NV file
	    // Alternative to deleting the file is to set its size to 0. This will not
	    // match the NV size so the TPM will need to be remanufactured.
	    if(delete)
		{
		    // Open for writing at the start. Sets the size to zero.
		    if(NvFileOpen("w") >= 0)
			{
			    fflush(s_NvFile);
			    fclose(s_NvFile);
			}
		}
	}
    s_NvFile = NULL;  // Set file handle to NULL
#endif
    s_NvIsAvailable = FALSE;
    return;
}

//***_plat__GetNvReadyState()
// Check if NV is available
//  Return Type: int
//      0               NV is available
//      1               NV is not available due to write failure
//      2               NV is not available due to rate limit
LIB_EXPORT int _plat__GetNvReadyState(void)
{
    int retVal = NV_READY;

#ifdef TPM_LIBTPMS_CALLBACKS
    if (libtpms_plat__IsNvAvailable() == 1)
        return NV_READY;
#endif /* TPM_LIBTPMS_CALLBACKS */

    if(!s_NvIsAvailable)
	retVal = NV_WRITEFAILURE;
#if FILE_BACKED_NV
    else
	retVal = (s_NvFile == NULL);
#endif
    return retVal;
}

//***_plat__NvMemoryRead()
// Function: Read a chunk of NV memory
//  Return Type: int
//      TRUE(1)         offset and size is within available NV size
//      FALSE(0)        otherwise; also trigger failure mode
LIB_EXPORT int _plat__NvMemoryRead(unsigned int startOffset,  // IN: read start
				   unsigned int size,  // IN: size of bytes to read
				   void*        data   // OUT: data buffer
				   )
{
    assert(startOffset + size <= NV_MEMORY_SIZE);
    if(startOffset + size <= NV_MEMORY_SIZE)
	{
	    memcpy(data, &s_NV[startOffset], size);  // Copy data from RAM
	    return TRUE;
	}
    return FALSE;
}

//*** _plat__NvGetChangedStatus()
// This function checks to see if the NV is different from the test value. This is
// so that NV will not be written if it has not changed.
//  Return Type: int
//      NV_HAS_CHANGED(1)       the NV location is different from the test value
//      NV_IS_SAME(0)           the NV location is the same as the test value
//      NV_INVALID_LOCATION(-1) the NV location is invalid; also triggers failure mode
LIB_EXPORT int _plat__NvGetChangedStatus(
					 unsigned int startOffset,  // IN: read start
					 unsigned int size,         // IN: size of bytes to read
					 void*        data          // IN: data buffer
					 )
{
    assert(startOffset + size <= NV_MEMORY_SIZE);
    if(startOffset + size <= NV_MEMORY_SIZE)
	{
	    return (memcmp(&s_NV[startOffset], data, size) != 0);
	}
    // the NV location is invalid; the assert above should have triggered failure
    // mode
    return NV_INVALID_LOCATION;
}

//***_plat__NvMemoryWrite()
// This function is used to update NV memory. The "write" is to a memory copy of
// NV. At the end of the current command, any changes are written to
// the actual NV memory.
// NOTE: A useful optimization would be for this code to compare the current
// contents of NV with the local copy and note the blocks that have changed. Then
// only write those blocks when _plat__NvCommit() is called.
//  Return Type: int
//      TRUE(1)         offset and size is within available NV size
//      FALSE(0)        otherwise; also trigger failure mode
LIB_EXPORT int _plat__NvMemoryWrite(unsigned int startOffset,  // IN: write start
				    unsigned int size,  // IN: size of bytes to write
				    void*        data   // OUT: data buffer
				    )
{
    assert(startOffset + size <= NV_MEMORY_SIZE);
    if(startOffset + size <= NV_MEMORY_SIZE)
	{
	    memcpy(&s_NV[startOffset], data, size);  // Copy the data to the NV image
	    return TRUE;
	}
    return FALSE;
}

//***_plat__NvMemoryClear()
// Function is used to set a range of NV memory bytes to an implementation-dependent
// value. The value represents the erase state of the memory.
LIB_EXPORT int _plat__NvMemoryClear(unsigned int startOffset,  // IN: clear start
				    unsigned int size  // IN: number of bytes to clear
				    )
{
    assert(startOffset + size <= NV_MEMORY_SIZE);
    if(startOffset + size <= NV_MEMORY_SIZE)
	{
	    // In this implementation, assume that the erase value for NV is all 1s
	    memset(&s_NV[startOffset], 0xff, size);
	    return TRUE;
	}
    return FALSE;
}

//***_plat__NvMemoryMove()
// Function: Move a chunk of NV memory from source to destination
//      This function should ensure that if there overlap, the original data is
//      copied before it is written
LIB_EXPORT int _plat__NvMemoryMove(unsigned int sourceOffset,  // IN: source offset
				   unsigned int destOffset,  // IN: destination offset
				   unsigned int size  // IN: size of data being moved
				   )
{
    assert(sourceOffset + size <= NV_MEMORY_SIZE);
    assert(destOffset + size <= NV_MEMORY_SIZE);
    if(sourceOffset + size <= NV_MEMORY_SIZE && destOffset + size <= NV_MEMORY_SIZE)
	{
	    memmove(&s_NV[destOffset], &s_NV[sourceOffset], size);  // Move data in RAM
#if 1    /* libtpms added begin */
	    if (destOffset > sourceOffset)
	        memset(&s_NV[sourceOffset], 0, destOffset-sourceOffset);
	    else
	        memset(&s_NV[destOffset+size], 0, sourceOffset-destOffset);
#endif   /* libtpms added end */
	    return TRUE;
	}
    return FALSE;
}

//***_plat__NvCommit()
// This function writes the local copy of NV to NV for permanent store. It will write
// NV_MEMORY_SIZE bytes to NV. If a file is use, the entire file is written.
//  Return Type: int
//  0       NV write success
//  non-0   NV write fail
LIB_EXPORT int _plat__NvCommit(void)
{
#ifdef TPM_LIBTPMS_CALLBACKS
    int ret = libtpms_plat__NvCommit();
    if (ret != LIBTPMS_CALLBACK_FALLTHROUGH)
        return ret;
#endif /* TPM_LIBTPMS_CALLBACKS */

#if FILE_BACKED_NV
    return (NvFileCommit() ? 0 : 1);
#else
    return 0;
#endif
}

//***_plat__TearDown
// notify platform that TPM_TearDown was called so platform can cleanup or
// zeroize anything in the Platform.  This should zeroize NV as well.
#if 0			// libtpms: added
LIB_EXPORT void _plat__TearDown(void)
{
#if FILE_BACKED_NV
    // remove(s_NvFilePath);
#endif
}
#endif			// libtpms: added

//***_plat__SetNvAvail()
// Set the current NV state to available.  This function is for testing purpose
// only.  It is not part of the platform NV logic
LIB_EXPORT void _plat__SetNvAvail(void)
{
    s_NvIsAvailable = TRUE;
    return;
}
#if 0 /* libtpms added */

//***_plat__ClearNvAvail()
// Set the current NV state to unavailable.  This function is for testing purpose
// only.  It is not part of the platform NV logic
LIB_EXPORT void _plat__ClearNvAvail(void)
{
    s_NvIsAvailable = FALSE;
    return;
}

//*** _plat__NVNeedsManufacture()
// This function is used by the simulator to determine when the TPM's NV state
// needs to be manufactured.
LIB_EXPORT int _plat__NVNeedsManufacture(void)
{
#if FILE_BACKED_NV
    return s_NeedsManufacture;
#else
    return FALSE;
#endif
}
#endif /* libtpms added */
