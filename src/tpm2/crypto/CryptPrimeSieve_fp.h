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
 *  Date: Aug 30, 2019  Time: 02:11:54PM
 */

#ifndef _CRYPT_PRIME_SIEVE_FP_H_
#define _CRYPT_PRIME_SIEVE_FP_H_

#if RSA_KEY_SIEVE

//*** RsaAdjustPrimeLimit()
// This used during the sieve process. The iterator for getting the
// next prime (RsaNextPrime()) will return primes until it hits the
// limit (primeLimit) set up by this function. This causes the sieve
// process to stop when an appropriate number of primes have been
// sieved.
LIB_EXPORT void RsaAdjustPrimeLimit(uint32_t requestedPrimes,
				    SEED_COMPAT_LEVEL seedCompatLevel	// libtpms added
				    );

//*** RsaNextPrime()
// This the iterator used during the sieve process. The input is the
// last prime returned (or any starting point) and the output is the
// next higher prime. The function returns 0 when the primeLimit is
// reached.
LIB_EXPORT uint32_t RsaNextPrime(uint32_t lastPrime);

//*** FindNthSetBit()
// This function finds the nth SET bit in a bit array. The 'n' parameter is
// between 1 and the number of bits in the array (always a multiple of 8).
// If called when the array does not have n bits set, it will return -1
//  Return Type: unsigned int
//      <0      no bit is set or no bit with the requested number is set
//      >=0    the number of the bit in the array that is the nth set
LIB_EXPORT int FindNthSetBit(
			     const UINT16 aSize,  // IN: the size of the array to check
			     const BYTE*  a,      // IN: the array to check
			     const UINT32 n       // IN, the number of the SET bit
			     );

//*** PrimeSieve()
// This function does a prime sieve over the input 'field' which has as its
// starting address the value in bnN. Since this initializes the Sieve
// using a precomputed field with the bits associated with 3, 5 and 7 already
// turned off, the value of pnN may need to be adjusted by a few counts to allow
// the precomputed field to be used without modification.
//
// To get better performance, one could address the issue of developing the
// composite numbers. When the size of the prime gets large, the time for doing
// the divisions goes up, noticeably. It could be better to develop larger composite
// numbers even if they need to be Crypt_Int*'s themselves. The object would be to
// reduce the number of times that the large prime is divided into a few large
// divides and then use smaller divides to get to the final 16 bit (or smaller)
// remainders.
LIB_EXPORT UINT32 PrimeSieve(Crypt_Int* bnN,    // IN/OUT: number to sieve
			     UINT32 fieldSize,  // IN: size of the field area in bytes
			     BYTE*  field       // IN: field
			     );
#  ifdef SIEVE_DEBUG

//***SetFieldSize()
// Function to set the field size used for prime generation. Used for tuning.
LIB_EXPORT uint32_t SetFieldSize(uint32_t newFieldSize);
#  endif  // SIEVE_DEBUG

//*** PrimeSelectWithSieve()
// This function will sieve the field around the input prime candidate. If the
// sieve field is not empty, one of the one bits in the field is chosen for testing
// with Miller-Rabin. If the value is prime, 'pnP' is updated with this value
// and the function returns success. If this value is not prime, another
// pseudo-random candidate is chosen and tested. This process repeats until
// all values in the field have been checked. If all bits in the field have
// been checked and none is prime, the function returns FALSE and a new random
// value needs to be chosen.
//  Return Type: TPM_RC
//      TPM_RC_FAILURE      TPM in failure mode, probably due to entropy source
//      TPM_RC_SUCCESS      candidate is probably prime
//      TPM_RC_NO_RESULT    candidate is not prime and couldn't find and alternative
//                          in the field
LIB_EXPORT TPM_RC PrimeSelectWithSieve(
				       Crypt_Int*  candidate,  // IN/OUT: The candidate to filter
				       UINT32      e,          // IN: the exponent
				       RAND_STATE* rand        // IN: the random number generator state
				       );
#  if RSA_INSTRUMENT

//*** PrintTuple()
char* PrintTuple(UINT32* i);

//*** RsaSimulationEnd()
void RsaSimulationEnd(void);

//*** GetSieveStats()
LIB_EXPORT void GetSieveStats(
			      uint32_t* trials, uint32_t* emptyFields, uint32_t* averageBits);
#  endif
#endif  // RSA_KEY_SIEVE
#if !RSA_INSTRUMENT

//*** RsaSimulationEnd()
// Stub for call when not doing instrumentation.
void RsaSimulationEnd(void);
#endif

#endif  // _CRYPT_PRIME_SIEVE_FP_H_
