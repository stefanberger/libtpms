/********************************************************************************/
/*										*/
/*						*/
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
/*  (c) Copyright IBM Corp. and others, 2023				  	*/
/*										*/
/********************************************************************************/

// system headers for the simulator, both Windows and Linux

#ifndef _SIMULATOR_SYSHEADERS_H_
#define _SIMULATOR_SYSHEADERS_H_
// include the system headers silencing warnings that occur with /Wall
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef TPM_WINDOWS
#ifdef _MSC_VER
#  pragma warning(push, 3)
// C4668 is supposed to be level 4, but this is still necessary to suppress the
// error.  We don't want to suppress it globally because the same error can
// happen in the TPM code and it shouldn't be ignored in those cases because it
// generally means a configuration header is missing.
//
// X is not defined as a preprocessor macro, assuming 0 for #if
#  pragma warning(disable : 4668)
#endif
#  include <windows.h>
#  include <winsock.h>
#ifdef _MSC_VER
#  pragma warning(pop)
#endif
typedef int socklen_t;
#elif defined(__unix__) || defined(__APPLE__)
#  include <unistd.h>
#  include <errno.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <pthread.h>
// simulate certain windows APIs
#  define ZeroMemory(ptr, sz) (memset((ptr), 0, (sz)))
#  define closesocket(x)      close(x)
#  define INVALID_SOCKET      (-1)
#  define SOCKET_ERROR        (-1)
#  define WSAGetLastError()   (errno)
#  define WSAEADDRINUSE       EADDRINUSE
#  define INT_PTR             intptr_t
typedef int SOCKET;
#  define _strcmpi            strcasecmp
#else
#  error "Unsupported platform."
#endif  // _MSC_VER
#endif  // _SIMULATOR_SYSHEADERS_H_
