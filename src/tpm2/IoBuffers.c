/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: IoBuffers.c 809 2016-11-16 18:31:54Z kgoldman $			*/
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

/* 9.7 IoBuffers.c */
/* 9.7.1 Includes and Data Definitions */
/* This definition allows this module to see the values that are private to this module but kept in
   Global.c for ease of state migration. */
#define IO_BUFFER_C
#include "Tpm.h"
#include "IoBuffers_fp.h"
/* These buffers are set aside to hold command and response values. In this implementation, it is
   not guaranteed that the code will stop accessing the s_actionInputBuffer before starting to put
   values in the s_actionOutputBuffer so different buffers are required. */
/* 9.7.1.1 MemoryGetActionInputBuffer() */
/* This function returns the address of the buffer into which the command parameters will be
   unmarshaled in preparation for calling the command actions. */
BYTE *
MemoryGetActionInputBuffer(
			   UINT32           size           // Size, in bytes, required for the input
			   // unmarshaling
			   )
{
    pAssert(size <= sizeof(s_actionInputBuffer));
    // In this implementation, a static buffer is set aside for the command action
    // input buffer.
    memset(s_actionInputBuffer, 0, size);
    return (BYTE *)&s_actionInputBuffer[0];
}
/* 9.7.1.2 MemoryGetActionOutputBuffer() */
/* This function returns the address of the buffer into which the command action code places its
   output values. */
void *
MemoryGetActionOutputBuffer(
			    UINT32           size           // required size of the buffer
			    )
{
    pAssert(size < sizeof(s_actionOutputBuffer));
    // In this implementation, a static buffer is set aside for the command action
    // output buffer.
    memset(s_actionOutputBuffer, 0, size);
    return s_actionOutputBuffer;
}
/* 9.7.1.3 IsLabelProperlyFormatted() */
/* This function checks that a label is a null-terminated string. */
/* NOTE: this function is here because there was no better place for it. */
/* Return Values Meaning */
/* FALSE string is not null terminated */
/* TRUE string is null terminated */
#ifndef INLINE_FUNCTIONS
BOOL
IsLabelProperlyFormatted(
			 TPM2B           *x
			 )
{
    return (((x)->size == 0) || ((x)->buffer[(x)->size - 1] == 0));
}
#endif // INLINE_FUNCTIONS
