/********************************************************************************/
/*										*/
/*			Debug Helper			.	 		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: DebugHelpers.c 1528 2019-11-20 20:31:43Z kgoldman $		*/
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
/*  (c) Copyright IBM Corp. and others, 2019					*/
/*										*/
/********************************************************************************/

/* C.13	DebugHelpers.c */
/* C.13.1.	Description */
/* This file contains the NV read and write access methods. This implementation uses RAM/file and
   does not manage the RAM/file as NV blocks. The implementation may become more sophisticated over
   time. */
/* C.13.2.	Includes and Local */
#include    <stdio.h>
#include    <time.h>
#include "Platform.h"
#include "DebugHelpers_fp.h"

#if CERTIFYX509_DEBUG
FILE                *fDebug = NULL;
const char       *debugFileName = "DebugFile.txt";

static FILE *
fileOpen(
	 const char       *fn,
	 const char       *mode
	 )
{
    FILE        *f;
#   if defined _MSC_VER
    if(fopen_s(&f, fn, mode) != 0)
	f = NULL;
#   else
    f = fopen(fn, mode);
#   endif
    return f;
}
/* C.13.2.1.	DebugFileOpen() */
/* This function opens the file used to hold the debug data. */
/* Return Value	Meaning */
/* 0	success */
/* != 0	error */
int
DebugFileOpen(
	      void
	      )
{
    time_t	t = time(NULL);
    //
    // Get current date and time.
#   if defined _MSC_VER
    char                 timeString[100];
    ctime_s(timeString, (size_t)sizeof(timeString), &t);
#   else
    char                *timeString;
    timeString = ctime(&t);
#   endif
    // Try to open the debug file
    fDebug = fileOpen(debugFileName, "w");
    if(fDebug)
	{
	    fprintf(fDebug, "%s\n", timeString);
	    fclose(fDebug);
	    return 0;
	}
    return -1;
}

void
DebugFileClose(
	       void
	       )
{
    if(fDebug)
	fclose(fDebug);
}
void
DebugDumpBuffer(
		int             size,
		unsigned char   *buf,
		const char      *identifier
		)
{
    int             i;
    //
    FILE *fDebug = fileOpen(debugFileName, "a");
    if(!fDebug)
	return;
    if(identifier)
	fprintf(fDebug, "%s\n", identifier);
    if(buf)
	{
	    for(i = 0; i < size; i++)
		{
		    if(((i % 16) == 0) && (i))
			fprintf(fDebug, "\n");
		    fprintf(fDebug, " %02X", buf[i]);
		}
	    if((size % 16) != 0)
		fprintf(fDebug, "\n");
	}
    fclose(fDebug);
}

#endif // CERTIFYX509_DEBUG
