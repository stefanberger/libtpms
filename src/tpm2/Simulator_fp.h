/********************************************************************************/
/*										*/
/*			     				*/
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

/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar  4, 2020  Time: 02:36:45PM
 */

#ifndef _SIMULATOR_FP_H_
#define _SIMULATOR_FP_H_

//** From TcpServer.c

#ifdef _MSC_VER
#elif defined(__unix__) || defined(__APPLE__)
#endif

#if 0					// libtpms: added
//*** PlatformServer()
// This function processes incoming platform requests.
bool PlatformServer(SOCKET s);

//*** PlatformSvcRoutine()
// This function is called to set up the socket interfaces to listen for
// commands.
int  PlatformSvcRoutine(LPVOID port);

//*** PlatformSignalService()
// This function starts a new thread waiting for platform signals.
// Platform signals are processed one at a time in the order in which they are
// received.
// If PickPorts is true, the server finds the next available port if the specified
// port was unavailable.
int PlatformSignalService(int *PortNumberPlatform);

//*** RegularCommandService()
// This function services regular commands.
// If PickPorts is true, the server finds the next available port if the specified
// port was unavailable.
int RegularCommandService(int *PortNumber);

//*** StartTcpServer()
// This is the main entry-point to the TCP server.  The server listens on the port
// specified.
// If PickPorts is true, the server finds the next available port if the specified
// port was unavailable.
//
// Note that there is no way to specify the network interface in this implementation.
int StartTcpServer(int *PortNumber, int *PortNumberPlatform);


//*** ReadBytes()
// This function reads the indicated number of bytes ('NumBytes') into buffer
// from the indicated socket.
bool ReadBytes(SOCKET s, char* buffer, int NumBytes);

//*** WriteBytes()
// This function will send the indicated number of bytes ('NumBytes') to the
// indicated socket
bool WriteBytes(SOCKET s, char* buffer, int NumBytes);

//*** WriteUINT32()
// Send 4 byte integer
bool WriteUINT32(SOCKET s, uint32_t val);

//*** ReadUINT32()
// Function to read 4 byte integer from socket.
bool ReadUINT32(SOCKET s, uint32_t* val);

//*** ReadVarBytes()
// Get a uint32-length-prepended binary array.  Note that the 4-byte length is
// in network byte order (big-endian).
bool ReadVarBytes(SOCKET s, char* buffer, uint32_t* BytesReceived, int MaxLen);

//*** WriteVarBytes()
// Send a UINT32-length-prepended binary array.  Note that the 4-byte length is
// in network byte order (big-endian).
bool WriteVarBytes(SOCKET s, char* buffer, int BytesToSend);

//*** TpmServer()
// Processing incoming TPM command requests using the protocol / interface
// defined above.
bool TpmServer(SOCKET s);
#endif 					// libtpms: added

//** From TPMCmdp.c

#ifdef _MSC_VER
#elif defined(__unix__) || defined(__APPLE__)
#endif

//*** Signal_PowerOn()
// This function processes a power-on indication. Among other things, it
// calls the _TPM_Init() handler.
void _rpc__Signal_PowerOn(bool isReset);

//*** Signal_Restart()
// This function processes the clock restart indication. All it does is call
// the platform function.
void _rpc__Signal_Restart(void);

//***Signal_PowerOff()
// This function processes the power off indication. Its primary function is
// to set a flag indicating that the next power on indication should cause
// _TPM_Init() to be called.
void _rpc__Signal_PowerOff(void);

#if 0 /* libtpms added */
//*** _rpc__ForceFailureMode()
// This function is used to debug the Failure Mode logic of the TPM. It will set
// a flag in the TPM code such that the next call to TPM2_SelfTest() will result
// in a failure, putting the TPM into Failure Mode.
void _rpc__ForceFailureMode(void);

//*** _rpc__Signal_PhysicalPresenceOn()
// This function is called to simulate activation of the physical presence "pin".
void _rpc__Signal_PhysicalPresenceOn(void);

//*** _rpc__Signal_PhysicalPresenceOff()
// This function is called to simulate deactivation of the physical presence "pin".
void _rpc__Signal_PhysicalPresenceOff(void);

//*** _rpc__Signal_Hash_Start()
// This function is called to simulate a _TPM_Hash_Start event. It will call
//
void _rpc__Signal_Hash_Start(void);

//*** _rpc__Signal_Hash_Data()
// This function is called to simulate a _TPM_Hash_Data event.
void _rpc__Signal_Hash_Data(_IN_BUFFER input);

//*** _rpc__Signal_HashEnd()
// This function is called to simulate a _TPM_Hash_End event.
void _rpc__Signal_HashEnd(void);

#endif /* libtpms added */
//*** _rpc__Send_Command()
// This is the interface to the TPM code.
//  Return Type: void
void _rpc__Send_Command(
			unsigned char locality, _IN_BUFFER request, _OUT_BUFFER* response);

//*** _rpc__Signal_CancelOn()
// This function is used to turn on the indication to cancel a command in process.
// An executing command is not interrupted. The command code may periodically check
// this indication to see if it should abort the current command processing and
// returned TPM_RC_CANCELLED.
void _rpc__Signal_CancelOn(void);

//*** _rpc__Signal_CancelOff()
// This function is used to turn off the indication to cancel a command in process.
void _rpc__Signal_CancelOff(void);

//*** _rpc__Signal_NvOn()
// In a system where the NV memory used by the TPM is not within the TPM, the
// NV may not always be available. This function turns on the indicator that
// indicates that NV is available.
void _rpc__Signal_NvOn(void);

#if 0 /* libtpms added */
//*** _rpc__Signal_NvOff()
// This function is used to set the indication that NV memory is no
// longer available.
void _rpc__Signal_NvOff(void);

//*** _rpc__RsaKeyCacheControl()
// This function is used to enable/disable the use of the RSA key cache during
// simulation.
void _rpc__RsaKeyCacheControl(int state);

//*** _rpc__ACT_GetSignaled()
// This function is used to count the ACT second tick.
bool _rpc__ACT_GetSignaled(uint32_t actHandle);

//*** _rpc__SetTpmFirmwareHash()
// This function is used to modify the firmware's hash during simulation.
void _rpc__SetTpmFirmwareHash(uint32_t hash);

//*** _rpc__SetTpmFirmwareSvn()
// This function is used to modify the firmware's SVN during simulation.
void _rpc__SetTpmFirmwareSvn(uint16_t svn);

//** From TPMCmds.c

//*** main()
// This is the main entry point for the simulator.
// It registers the interface and starts listening for clients
int main(int argc, char* argv[]);

#endif /* libtpms added */
/* libtpms added begin */
void _rpc__Signal_SetTPMEstablished(void);
bool _rpc__Signal_GetTPMEstablished(void);
void _rpc__Signal_ResetTPMEstablished(void);
bool _rpc__Signal_IsPowerOn(void);
/* libtpms added end */

#endif  // _SIMULATOR_FP_H_
