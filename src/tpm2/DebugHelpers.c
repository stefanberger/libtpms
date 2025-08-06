// SPDX-License-Identifier: BSD-2-Clause

//** Description
//
//    This file contains the NV read and write access methods.  This implementation
//    uses RAM/file and does not manage the RAM/file as NV blocks.
//    The implementation may become more sophisticated over time.
//

//** Includes and Local
#include <stdio.h>
#include <time.h>
#include "Platform.h"

#if CERTIFYX509_DEBUG

const char* debugFileName = "DebugFile.txt";

//*** fileOpen()
// This exists to allow use of the 'safe' version of fopen() with a MS runtime.
static FILE* fileOpen(const char* fn, const char* mode)
{
    FILE* f;
#  if defined _MSC_VER
    if(fopen_s(&f, fn, mode) != 0)
        f = NULL;
#  else
    f = fopen(fn, mode);
#  endif
    return f;
}

//*** DebugFileInit()
// This function initializes the file containing the debug data with the time of the
// file creation.
//  Return Type: int
//   0              success
//  != 0            error
int DebugFileInit(void)
{
    FILE*  f = NULL;
    time_t t = time(NULL);
//
// Get current date and time.
#  if defined _MSC_VER
    char timeString[100];
    ctime_s(timeString, (size_t)sizeof(timeString), &t);
#  else
    char* timeString;
    timeString = ctime(&t);
#  endif
    // Try to open the debug file
    f = fileOpen(debugFileName, "w");
    if(f)
    {
        // Initialize the contents with the time.
        fprintf(f, "%s\n", timeString);
        fclose(f);
        return 0;
    }
    return -1;
}

//*** DebugDumpBuffer()
void DebugDumpBuffer(int size, unsigned char* buf, const char* identifier)
{
    int i;
    //
    FILE* f = fileOpen(debugFileName, "a");
    if(!f)
        return;
    if(identifier)
        fprintf(f, "%s\n", identifier);
    if(buf)
    {
        for(i = 0; i < size; i++)
        {
            if(((i % 16) == 0) && (i))
                fprintf(f, "\n");
            fprintf(f, " %02X", buf[i]);
        }
        if((size % 16) != 0)
            fprintf(f, "\n");
    }
    fclose(f);
}

#endif  // CERTIFYX509_DEBUG
