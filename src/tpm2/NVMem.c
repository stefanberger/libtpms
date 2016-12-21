/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: NVMem.c 809 2016-11-16 18:31:54Z kgoldman $			*/
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

/* C.6 NVMem.c */
/* C.6.1. Introduction */
/* This file contains the NV read and write access methods.  This implementation uses RAM/file and
   does not manage the RAM/file as NV blocks. The implementation may become more sophisticated over
   time. */
/* C.6.2. Includes */
#include <memory.h>
#include <string.h>
#include <assert.h>
#include "PlatformData.h"
#include "Platform_fp.h"
/* C.6.3. Functions */
/* C.6.3.1. _plat__NvErrors() */
/* This function is used by the simulator to set the error flags in the NV subsystem to simulate an
   error in the NV loading process */
LIB_EXPORT void
_plat__NvErrors(
		int              recoverable,
		int            unrecoverable
		)
{
    s_NV_unrecoverable = unrecoverable;
    s_NV_recoverable = recoverable;
}
/* C.6.3.2. _plat__NVEnable() */
/* Enable NV memory. */
/* This version just pulls in data from a file. In a real TPM, with NV on chip, this function would
   verify the integrity of the saved context. If the NV memory was not on chip but was in something
   like RPMB, the NV state would be read in, decrypted and integrity checked. */
/* The recovery from an integrity failure depends on where the error occurred. It it was in the
   state that is discarded by TPM Reset, then the error is recoverable if the TPM is
   reset. Otherwise, the TPM must go into failure mode. */
/* Return Values Meaning */
/* 0 if success */
/* > 0 if receive recoverable error */
/* <0 if unrecoverable error */
LIB_EXPORT int
_plat__NVEnable(
		void            *platParameter  // IN: platform specific parameters
		)
{
    NOT_REFERENCED(platParameter);          // to keep compiler quiet
    // Start assuming everything is OK
    s_NV_unrecoverable = FALSE;
    s_NV_recoverable = FALSE;
#ifdef FILE_BACKED_NV
    if(s_NVFile != NULL)
	return 0;
    // Try to open an exist NVChip file for read/write
#if defined _MSC_VER && 1
    if(0 != fopen_s(&s_NVFile, "NVChip", "r+b"))
	s_NVFile = NULL;
#else
    s_NVFile = fopen("NVChip", "r+b");
#endif
    if(NULL != s_NVFile)
	{
	    // See if the NVChip file is empty
	    fseek(s_NVFile, 0, SEEK_END);
	    if(0 == ftell(s_NVFile))
		s_NVFile = NULL;
	}
    if(s_NVFile == NULL)
	{
	    // Initialize all the byte in the new file to 0
	    memset(s_NV, 0, NV_MEMORY_SIZE);
	    // If NVChip file does not exist, try to create it for read/write
#if defined _MSC_VER && 1
	    if(0 != fopen_s(&s_NVFile, "NVChip", "w+b"))
		s_NVFile = NULL;
#else
	    s_NVFile = fopen("NVChip", "w+b");
#endif
	    if(s_NVFile != NULL)
		{
		    // Start initialize at the end of new file
		    fseek(s_NVFile, 0, SEEK_END);
		    // Write 0s to NVChip file
		    fwrite(s_NV, 1, NV_MEMORY_SIZE, s_NVFile);
		}
	}
    else
	{
	    // If NVChip file exist, assume the size is correct
	    fseek(s_NVFile, 0, SEEK_END);
	    assert(ftell(s_NVFile) == NV_MEMORY_SIZE);
	    // read NV file data to memory
	    fseek(s_NVFile, 0, SEEK_SET);
	    fread(s_NV, NV_MEMORY_SIZE, 1, s_NVFile);
	}
#endif
    // NV contents have been read and the error checks have been performed. For
    // simulation purposes, use the signaling interface to indicate if an error is
    // to be simulated and the type of the error.
    if(s_NV_unrecoverable)
	return -1;
    return s_NV_recoverable;
}
/* C.6.3.3. _plat__NVDisable() */
/* Disable NV memory */
LIB_EXPORT void
_plat__NVDisable(
		 void
		 )
{
#ifdef  FILE_BACKED_NV
    assert(s_NVFile != NULL);
    // Close NV file
    fclose(s_NVFile);
    // Set file handle to NULL
    s_NVFile = NULL;
#endif
    return;
}
/* C.6.3.4. _plat__IsNvAvailable() */
/* Check if NV is available */
/* Return Values Meaning */
/* 0 NV is available */
/* 1 NV is not available due to write failure */
/* 2 NV is not available due to rate limit */
LIB_EXPORT int
_plat__IsNvAvailable(
		     void
		     )
{
    // NV is not available if the TPM is in failure mode
    if(!s_NvIsAvailable)
	return 1;
#ifdef FILE_BACKED_NV
    if(s_NVFile == NULL)
	return 1;
#endif
    return 0;
}
/* C.6.3.5. _plat__NvMemoryRead() */
/* Function: Read a chunk of NV memory */
LIB_EXPORT void
_plat__NvMemoryRead(
		    unsigned int     startOffset,   // IN: read start
		    unsigned int     size,          // IN: size of bytes to read
		    void            *data           // OUT: data buffer
		    )
{
    assert(startOffset + size <= NV_MEMORY_SIZE);
    // Copy data from RAM
    memcpy(data, &s_NV[startOffset], size);
    return;
}
/* C.6.3.6. _plat__NvIsDifferent() */
/* This function checks to see if the NV is different from the test value. This is so that NV will
   not be written if it has not changed. */
/* Return Values Meaning */
/* TRUE(1) the NV location is different from the test value */
/* FALSE(0) the NV location is the same as the test value */
LIB_EXPORT int
_plat__NvIsDifferent(
		     unsigned int     startOffset,   // IN: read start
		     unsigned int     size,          // IN: size of bytes to read
		     void            *data           // IN: data buffer
		     )
{
    return (memcmp(&s_NV[startOffset], data, size) != 0);
}
/* C.6.3.7. _plat__NvMemoryWrite() */
/* This function is used to update NV memory. The write is to a memory copy of NV. At the end of the
   current command, any changes are written to the actual NV memory. */
/* NOTE: A useful optimization would be for this code to compare the current contents of NV with the
   local copy and note the blocks that have changed. Then only write those blocks when
   _plat__NvCommit() is called. */
LIB_EXPORT void
_plat__NvMemoryWrite(
		     unsigned int     startOffset,   // IN: write start
		     unsigned int     size,          // IN: size of bytes to write
		     void            *data           // OUT: data buffer
		     )
{
    assert(startOffset + size <= NV_MEMORY_SIZE);
    // Copy the data to the NV image
    memcpy(&s_NV[startOffset], data, size);
}
/* C.6.3.8. _plat__NvMemoryClear() */
/* Function is used to set a range of NV memory bytes to an implementation-dependent value. The
   value represents the erase state of the memory. */
LIB_EXPORT void
_plat__NvMemoryClear(
		     unsigned int     start,         // IN: clear start
		     unsigned int     size           // IN: number of bytes to clear
		     )
{
    assert(start + size <= NV_MEMORY_SIZE);
    // In this implementation, assume that the errase value for NV is all 1s
    memset(&s_NV[start], 0xff, size);
}
/* C.6.3.9. _plat__NvMemoryMove() */
/* Function: Move a chunk of NV memory from source to destination This function should ensure that
   if there overlap, the original data is copied before it is written */
LIB_EXPORT void
_plat__NvMemoryMove(
		    unsigned int     sourceOffset,  // IN: source offset
		    unsigned int     destOffset,    // IN: destination offset
		    unsigned int     size           // IN: size of data being moved
		    )
{
    assert(sourceOffset + size <= NV_MEMORY_SIZE);
    assert(destOffset + size <= NV_MEMORY_SIZE);
    // Move data in RAM
    memmove(&s_NV[destOffset], &s_NV[sourceOffset], size);
    return;
}
/* C.6.3.10. _plat__NvCommit() */
/* Update NV chip */
/* Return Values Meaning */
/* 0 NV write success */
/* non-0 NV write fail */
LIB_EXPORT int
_plat__NvCommit(
		void
		)
{
#ifdef FILE_BACKED_NV
    // If NV file is not available, return failure
    if(s_NVFile == NULL)
	return 1;
    // Write RAM data to NV
    fseek(s_NVFile, 0, SEEK_SET);
    fwrite(s_NV, 1, NV_MEMORY_SIZE, s_NVFile);
    return 0;
#else
    return 0;
#endif
}
/* C.6.3.11. _plat__SetNvAvail() */
/* Set the current NV state to available.  This function is for testing purpose only.  It is not
   part of the platform NV logic */
LIB_EXPORT void
_plat__SetNvAvail(
		  void
		  )
{
    s_NvIsAvailable = TRUE;
    return;
}
/* C.6.3.12. _plat__ClearNvAvail() */
/* Set the current NV state to unavailable.  This function is for testing purpose only.  It is not
   part of the platform NV logic */
LIB_EXPORT void
_plat__ClearNvAvail(
		    void
		    )
{
    s_NvIsAvailable = FALSE;
    return;
}
