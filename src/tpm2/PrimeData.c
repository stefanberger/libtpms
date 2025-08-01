/********************************************************************************/
/*										*/
/*		Product of all of the Primes up to 1000	     			*/
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

#include "Tpm.h"

// This table is the product of all of the primes up to 1000.
// Checking to see if there is a GCD between a prime candidate
// and this number will eliminate many prime candidates from
// consideration before running Miller-Rabin on the result.

const CRYPT_INT_BUF(smallprimecomp, 43 * RADIX_BITS) s_CompositeOfSmallPrimes_ =
    {44, 44, {0x2ED42696, 0x2BBFA177, 0x4820594F, 0xF73F4841, 0xBFAC313A, 0xCAC3EB81,
              0xF6F26BF8, 0x7FAB5061, 0x59746FB7, 0xF71377F6, 0x3B19855B, 0xCBD03132,
              0xBB92EF1B, 0x3AC3152C, 0xE87C8273, 0xC0AE0E69, 0x74A9E295, 0x448CCE86,
              0x63CA1907, 0x8A0BF944, 0xF8CC3BE0, 0xC26F0AF5, 0xC501C02F, 0x6579441A,
              0xD1099CDA, 0x6BC76A00, 0xC81A3228, 0xBFB1AB25, 0x70FA3841, 0x51B3D076,
              0xCC2359ED, 0xD9EE0769, 0x75E47AF0, 0xD45FF31E, 0x52CCE4F6, 0x04DBC891,
              0x96658ED2, 0x1753EFE5, 0x3AE4A5A6, 0x8FD4A97F, 0x8B15E7EB, 0x0243C3E1,
              0xE0F0C31D, 0x0000000B}};

const Crypt_Int* s_CompositeOfSmallPrimes =
    (const Crypt_Int*)&s_CompositeOfSmallPrimes_;

// This table contains a bit for each of the odd values between 1 and 2^16 + 1.
// This table allows fast checking of the primes in that range.
// Don't change the size of this table unless you are prepared to do redo
// IsPrimeInt().

const uint32_t      s_LastPrimeInTable = 65537;
const uint32_t      s_PrimeTableSize   = 4097;
const uint32_t      s_PrimesInTable    = 6542;
const unsigned char s_PrimeTable[] =
    {0x6e, 0xcb, 0xb4, 0x64, 0x9a, 0x12, 0x6d, 0x81, 0x32, 0x4c, 0x4a, 0x86, 0x0d,
     0x82, 0x96, 0x21, 0xc9, 0x34, 0x04, 0x5a, 0x20, 0x61, 0x89, 0xa4, 0x44, 0x11,
     0x86, 0x29, 0xd1, 0x82, 0x28, 0x4a, 0x30, 0x40, 0x42, 0x32, 0x21, 0x99, 0x34,
     0x08, 0x4b, 0x06, 0x25, 0x42, 0x84, 0x48, 0x8a, 0x14, 0x05, 0x42, 0x30, 0x6c,
     0x08, 0xb4, 0x40, 0x0b, 0xa0, 0x08, 0x51, 0x12, 0x28, 0x89, 0x04, 0x65, 0x98,
     0x30, 0x4c, 0x80, 0x96, 0x44, 0x12, 0x80, 0x21, 0x42, 0x12, 0x41, 0xc9, 0x04,
     0x21, 0xc0, 0x32, 0x2d, 0x98, 0x00, 0x00, 0x49, 0x04, 0x08, 0x81, 0x96, 0x68,
     0x82, 0xb0, 0x25, 0x08, 0x22, 0x48, 0x89, 0xa2, 0x40, 0x59, 0x26, 0x04, 0x90,
     0x06, 0x40, 0x43, 0x30, 0x44, 0x92, 0x00, 0x69, 0x10, 0x82, 0x08, 0x08, 0xa4,
     0x0d, 0x41, 0x12, 0x60, 0xc0, 0x00, 0x24, 0xd2, 0x22, 0x61, 0x08, 0x84, 0x04,
     0x1b, 0x82, 0x01, 0xd3, 0x10, 0x01, 0x02, 0xa0, 0x44, 0xc0, 0x22, 0x60, 0x91,
     0x14, 0x0c, 0x40, 0xa6, 0x04, 0xd2, 0x94, 0x20, 0x09, 0x94, 0x20, 0x52, 0x00,
     0x08, 0x10, 0xa2, 0x4c, 0x00, 0x82, 0x01, 0x51, 0x10, 0x08, 0x8b, 0xa4, 0x25,
     0x9a, 0x30, 0x44, 0x81, 0x10, 0x4c, 0x03, 0x02, 0x25, 0x52, 0x80, 0x08, 0x49,
     0x84, 0x20, 0x50, 0x32, 0x00, 0x18, 0xa2, 0x40, 0x11, 0x24, 0x28, 0x01, 0x84,
     0x01, 0x01, 0xa0, 0x41, 0x0a, 0x12, 0x45, 0x00, 0x36, 0x08, 0x00, 0x26, 0x29,
     0x83, 0x82, 0x61, 0xc0, 0x80, 0x04, 0x10, 0x10, 0x6d, 0x00, 0x22, 0x48, 0x58,
     0x26, 0x0c, 0xc2, 0x10, 0x48, 0x89, 0x24, 0x20, 0x58, 0x20, 0x45, 0x88, 0x24,
     0x00, 0x19, 0x02, 0x25, 0xc0, 0x10, 0x68, 0x08, 0x14, 0x01, 0xca, 0x32, 0x28,
     0x80, 0x00, 0x04, 0x4b, 0x26, 0x00, 0x13, 0x90, 0x60, 0x82, 0x80, 0x25, 0xd0,
     0x00, 0x01, 0x10, 0x32, 0x0c, 0x43, 0x86, 0x21, 0x11, 0x00, 0x08, 0x43, 0x24,
     0x04, 0x48, 0x10, 0x0c, 0x90, 0x92, 0x00, 0x43, 0x20, 0x2d, 0x00, 0x06, 0x09,
     0x88, 0x24, 0x40, 0xc0, 0x32, 0x09, 0x09, 0x82, 0x00, 0x53, 0x80, 0x08, 0x80,
     0x96, 0x41, 0x81, 0x00, 0x40, 0x48, 0x10, 0x48, 0x08, 0x96, 0x48, 0x58, 0x20,
     0x29, 0xc3, 0x80, 0x20, 0x02, 0x94, 0x60, 0x92, 0x00, 0x20, 0x81, 0x22, 0x44,
     0x10, 0xa0, 0x05, 0x40, 0x90, 0x01, 0x49, 0x20, 0x04, 0x0a, 0x00, 0x24, 0x89,
     0x34, 0x48, 0x13, 0x80, 0x2c, 0xc0, 0x82, 0x29, 0x00, 0x24, 0x45, 0x08, 0x00,
     0x08, 0x98, 0x36, 0x04, 0x52, 0x84, 0x04, 0xd0, 0x04, 0x00, 0x8a, 0x90, 0x44,
     0x82, 0x32, 0x65, 0x18, 0x90, 0x00, 0x0a, 0x02, 0x01, 0x40, 0x02, 0x28, 0x40,
     0xa4, 0x04, 0x92, 0x30, 0x04, 0x11, 0x86, 0x08, 0x42, 0x00, 0x2c, 0x52, 0x04,
     0x08, 0xc9, 0x84, 0x60, 0x48, 0x12, 0x09, 0x99, 0x24, 0x44, 0x00, 0x24, 0x00,
     0x03, 0x14, 0x21, 0x00, 0x10, 0x01, 0x1a, 0x32, 0x05, 0x88, 0x20, 0x40, 0x40,
     0x06, 0x09, 0xc3, 0x84, 0x40, 0x01, 0x30, 0x60, 0x18, 0x02, 0x68, 0x11, 0x90,
     0x0c, 0x02, 0xa2, 0x04, 0x00, 0x86, 0x29, 0x89, 0x14, 0x24, 0x82, 0x02, 0x41,
     0x08, 0x80, 0x04, 0x19, 0x80, 0x08, 0x10, 0x12, 0x68, 0x42, 0xa4, 0x04, 0x00,
     0x02, 0x61, 0x10, 0x06, 0x0c, 0x10, 0x00, 0x01, 0x12, 0x10, 0x20, 0x03, 0x94,
     0x21, 0x42, 0x12, 0x65, 0x18, 0x94, 0x0c, 0x0a, 0x04, 0x28, 0x01, 0x14, 0x29,
     0x0a, 0xa4, 0x40, 0xd0, 0x00, 0x40, 0x01, 0x90, 0x04, 0x41, 0x20, 0x2d, 0x40,
     0x82, 0x48, 0xc1, 0x20, 0x00, 0x10, 0x30, 0x01, 0x08, 0x24, 0x04, 0x59, 0x84,
     0x24, 0x00, 0x02, 0x29, 0x82, 0x00, 0x61, 0x58, 0x02, 0x48, 0x81, 0x16, 0x48,
     0x10, 0x00, 0x21, 0x11, 0x06, 0x00, 0xca, 0xa0, 0x40, 0x02, 0x00, 0x04, 0x91,
     0xb0, 0x00, 0x42, 0x04, 0x0c, 0x81, 0x06, 0x09, 0x48, 0x14, 0x25, 0x92, 0x20,
     0x25, 0x11, 0xa0, 0x00, 0x0a, 0x86, 0x0c, 0xc1, 0x02, 0x48, 0x00, 0x20, 0x45,
     0x08, 0x32, 0x00, 0x98, 0x06, 0x04, 0x13, 0x22, 0x00, 0x82, 0x04, 0x48, 0x81,
     0x14, 0x44, 0x82, 0x12, 0x24, 0x18, 0x10, 0x40, 0x43, 0x80, 0x28, 0xd0, 0x04,
     0x20, 0x81, 0x24, 0x64, 0xd8, 0x00, 0x2c, 0x09, 0x12, 0x08, 0x41, 0xa2, 0x00,
     0x00, 0x02, 0x41, 0xca, 0x20, 0x41, 0xc0, 0x10, 0x01, 0x18, 0xa4, 0x04, 0x18,
     0xa4, 0x20, 0x12, 0x94, 0x20, 0x83, 0xa0, 0x40, 0x02, 0x32, 0x44, 0x80, 0x04,
     0x00, 0x18, 0x00, 0x0c, 0x40, 0x86, 0x60, 0x8a, 0x00, 0x64, 0x88, 0x12, 0x05,
     0x01, 0x82, 0x00, 0x4a, 0xa2, 0x01, 0xc1, 0x10, 0x61, 0x09, 0x04, 0x01, 0x88,
     0x00, 0x60, 0x01, 0xb4, 0x40, 0x08, 0x06, 0x01, 0x03, 0x80, 0x08, 0x40, 0x94,
     0x04, 0x8a, 0x20, 0x29, 0x80, 0x02, 0x0c, 0x52, 0x02, 0x01, 0x42, 0x84, 0x00,
     0x80, 0x84, 0x64, 0x02, 0x32, 0x48, 0x00, 0x30, 0x44, 0x40, 0x22, 0x21, 0x00,
     0x02, 0x08, 0xc3, 0xa0, 0x04, 0xd0, 0x20, 0x40, 0x18, 0x16, 0x40, 0x40, 0x00,
     0x28, 0x52, 0x90, 0x08, 0x82, 0x14, 0x01, 0x18, 0x10, 0x08, 0x09, 0x82, 0x40,
     0x0a, 0xa0, 0x20, 0x93, 0x80, 0x08, 0xc0, 0x00, 0x20, 0x52, 0x00, 0x05, 0x01,
     0x10, 0x40, 0x11, 0x06, 0x0c, 0x82, 0x00, 0x00, 0x4b, 0x90, 0x44, 0x9a, 0x00,
     0x28, 0x80, 0x90, 0x04, 0x4a, 0x06, 0x09, 0x43, 0x02, 0x28, 0x00, 0x34, 0x01,
     0x18, 0x00, 0x65, 0x09, 0x80, 0x44, 0x03, 0x00, 0x24, 0x02, 0x82, 0x61, 0x48,
     0x14, 0x41, 0x00, 0x12, 0x28, 0x00, 0x34, 0x08, 0x51, 0x04, 0x05, 0x12, 0x90,
     0x28, 0x89, 0x84, 0x60, 0x12, 0x10, 0x49, 0x10, 0x26, 0x40, 0x49, 0x82, 0x00,
     0x91, 0x10, 0x01, 0x0a, 0x24, 0x40, 0x88, 0x10, 0x4c, 0x10, 0x04, 0x00, 0x50,
     0xa2, 0x2c, 0x40, 0x90, 0x48, 0x0a, 0xb0, 0x01, 0x50, 0x12, 0x08, 0x00, 0xa4,
     0x04, 0x09, 0xa0, 0x28, 0x92, 0x02, 0x00, 0x43, 0x10, 0x21, 0x02, 0x20, 0x41,
     0x81, 0x32, 0x00, 0x08, 0x04, 0x0c, 0x52, 0x00, 0x21, 0x49, 0x84, 0x20, 0x10,
     0x02, 0x01, 0x81, 0x10, 0x48, 0x40, 0x22, 0x01, 0x01, 0x84, 0x69, 0xc1, 0x30,
     0x01, 0xc8, 0x02, 0x44, 0x88, 0x00, 0x0c, 0x01, 0x02, 0x2d, 0xc0, 0x12, 0x61,
     0x00, 0xa0, 0x00, 0xc0, 0x30, 0x40, 0x01, 0x12, 0x08, 0x0b, 0x20, 0x00, 0x80,
     0x94, 0x40, 0x01, 0x84, 0x40, 0x00, 0x32, 0x00, 0x10, 0x84, 0x00, 0x0b, 0x24,
     0x00, 0x01, 0x06, 0x29, 0x8a, 0x84, 0x41, 0x80, 0x10, 0x08, 0x08, 0x94, 0x4c,
     0x03, 0x80, 0x01, 0x40, 0x96, 0x40, 0x41, 0x20, 0x20, 0x50, 0x22, 0x25, 0x89,
     0xa2, 0x40, 0x40, 0xa4, 0x20, 0x02, 0x86, 0x28, 0x01, 0x20, 0x21, 0x4a, 0x10,
     0x08, 0x00, 0x14, 0x08, 0x40, 0x04, 0x25, 0x42, 0x02, 0x21, 0x43, 0x10, 0x04,
     0x92, 0x00, 0x21, 0x11, 0xa0, 0x4c, 0x18, 0x22, 0x09, 0x03, 0x84, 0x41, 0x89,
     0x10, 0x04, 0x82, 0x22, 0x24, 0x01, 0x14, 0x08, 0x08, 0x84, 0x08, 0xc1, 0x00,
     0x09, 0x42, 0xb0, 0x41, 0x8a, 0x02, 0x00, 0x80, 0x36, 0x04, 0x49, 0xa0, 0x24,
     0x91, 0x00, 0x00, 0x02, 0x94, 0x41, 0x92, 0x02, 0x01, 0x08, 0x06, 0x08, 0x09,
     0x00, 0x01, 0xd0, 0x16, 0x28, 0x89, 0x80, 0x60, 0x00, 0x00, 0x68, 0x01, 0x90,
     0x0c, 0x50, 0x20, 0x01, 0x40, 0x80, 0x40, 0x42, 0x30, 0x41, 0x00, 0x20, 0x25,
     0x81, 0x06, 0x40, 0x49, 0x00, 0x08, 0x01, 0x12, 0x49, 0x00, 0xa0, 0x20, 0x18,
     0x30, 0x05, 0x01, 0xa6, 0x00, 0x10, 0x24, 0x28, 0x00, 0x02, 0x20, 0xc8, 0x20,
     0x00, 0x88, 0x12, 0x0c, 0x90, 0x92, 0x00, 0x02, 0x26, 0x01, 0x42, 0x16, 0x49,
     0x00, 0x04, 0x24, 0x42, 0x02, 0x01, 0x88, 0x80, 0x0c, 0x1a, 0x80, 0x08, 0x10,
     0x00, 0x60, 0x02, 0x94, 0x44, 0x88, 0x00, 0x69, 0x11, 0x30, 0x08, 0x12, 0xa0,
     0x24, 0x13, 0x84, 0x00, 0x82, 0x00, 0x65, 0xc0, 0x10, 0x28, 0x00, 0x30, 0x04,
     0x03, 0x20, 0x01, 0x11, 0x06, 0x01, 0xc8, 0x80, 0x00, 0xc2, 0x20, 0x08, 0x10,
     0x82, 0x0c, 0x13, 0x02, 0x0c, 0x52, 0x06, 0x40, 0x00, 0xb0, 0x61, 0x40, 0x10,
     0x01, 0x98, 0x86, 0x04, 0x10, 0x84, 0x08, 0x92, 0x14, 0x60, 0x41, 0x80, 0x41,
     0x1a, 0x10, 0x04, 0x81, 0x22, 0x40, 0x41, 0x20, 0x29, 0x52, 0x00, 0x41, 0x08,
     0x34, 0x60, 0x10, 0x00, 0x28, 0x01, 0x10, 0x40, 0x00, 0x84, 0x08, 0x42, 0x90,
     0x20, 0x48, 0x04, 0x04, 0x52, 0x02, 0x00, 0x08, 0x20, 0x04, 0x00, 0x82, 0x0d,
     0x00, 0x82, 0x40, 0x02, 0x10, 0x05, 0x48, 0x20, 0x40, 0x99, 0x00, 0x00, 0x01,
     0x06, 0x24, 0xc0, 0x00, 0x68, 0x82, 0x04, 0x21, 0x12, 0x10, 0x44, 0x08, 0x04,
     0x00, 0x40, 0xa6, 0x20, 0xd0, 0x16, 0x09, 0xc9, 0x24, 0x41, 0x02, 0x20, 0x0c,
     0x09, 0x92, 0x40, 0x12, 0x00, 0x00, 0x40, 0x00, 0x09, 0x43, 0x84, 0x20, 0x98,
     0x02, 0x01, 0x11, 0x24, 0x00, 0x43, 0x24, 0x00, 0x03, 0x90, 0x08, 0x41, 0x30,
     0x24, 0x58, 0x20, 0x4c, 0x80, 0x82, 0x08, 0x10, 0x24, 0x25, 0x81, 0x06, 0x41,
     0x09, 0x10, 0x20, 0x18, 0x10, 0x44, 0x80, 0x10, 0x00, 0x4a, 0x24, 0x0d, 0x01,
     0x94, 0x28, 0x80, 0x30, 0x00, 0xc0, 0x02, 0x60, 0x10, 0x84, 0x0c, 0x02, 0x00,
     0x09, 0x02, 0x82, 0x01, 0x08, 0x10, 0x04, 0xc2, 0x20, 0x68, 0x09, 0x06, 0x04,
     0x18, 0x00, 0x00, 0x11, 0x90, 0x08, 0x0b, 0x10, 0x21, 0x82, 0x02, 0x0c, 0x10,
     0xb6, 0x08, 0x00, 0x26, 0x00, 0x41, 0x02, 0x01, 0x4a, 0x24, 0x21, 0x1a, 0x20,
     0x24, 0x80, 0x00, 0x44, 0x02, 0x00, 0x2d, 0x40, 0x02, 0x00, 0x8b, 0x94, 0x20,
     0x10, 0x00, 0x20, 0x90, 0xa6, 0x40, 0x13, 0x00, 0x2c, 0x11, 0x86, 0x61, 0x01,
     0x80, 0x41, 0x10, 0x02, 0x04, 0x81, 0x30, 0x48, 0x48, 0x20, 0x28, 0x50, 0x80,
     0x21, 0x8a, 0x10, 0x04, 0x08, 0x10, 0x09, 0x10, 0x10, 0x48, 0x42, 0xa0, 0x0c,
     0x82, 0x92, 0x60, 0xc0, 0x20, 0x05, 0xd2, 0x20, 0x40, 0x01, 0x00, 0x04, 0x08,
     0x82, 0x2d, 0x82, 0x02, 0x00, 0x48, 0x80, 0x41, 0x48, 0x10, 0x00, 0x91, 0x04,
     0x04, 0x03, 0x84, 0x00, 0xc2, 0x04, 0x68, 0x00, 0x00, 0x64, 0xc0, 0x22, 0x40,
     0x08, 0x32, 0x44, 0x09, 0x86, 0x00, 0x91, 0x02, 0x28, 0x01, 0x00, 0x64, 0x48,
     0x00, 0x24, 0x10, 0x90, 0x00, 0x43, 0x00, 0x21, 0x52, 0x86, 0x41, 0x8b, 0x90,
     0x20, 0x40, 0x20, 0x08, 0x88, 0x04, 0x44, 0x13, 0x20, 0x00, 0x02, 0x84, 0x60,
     0x81, 0x90, 0x24, 0x40, 0x30, 0x00, 0x08, 0x10, 0x08, 0x08, 0x02, 0x01, 0x10,
     0x04, 0x20, 0x43, 0xb4, 0x40, 0x90, 0x12, 0x68, 0x01, 0x80, 0x4c, 0x18, 0x00,
     0x08, 0xc0, 0x12, 0x49, 0x40, 0x10, 0x24, 0x1a, 0x00, 0x41, 0x89, 0x24, 0x4c,
     0x10, 0x00, 0x04, 0x52, 0x10, 0x09, 0x4a, 0x20, 0x41, 0x48, 0x22, 0x69, 0x11,
     0x14, 0x08, 0x10, 0x06, 0x24, 0x80, 0x84, 0x28, 0x00, 0x10, 0x00, 0x40, 0x10,
     0x01, 0x08, 0x26, 0x08, 0x48, 0x06, 0x28, 0x00, 0x14, 0x01, 0x42, 0x84, 0x04,
     0x0a, 0x20, 0x00, 0x01, 0x82, 0x08, 0x00, 0x82, 0x24, 0x12, 0x04, 0x40, 0x40,
     0xa0, 0x40, 0x90, 0x10, 0x04, 0x90, 0x22, 0x40, 0x10, 0x20, 0x2c, 0x80, 0x10,
     0x28, 0x43, 0x00, 0x04, 0x58, 0x00, 0x01, 0x81, 0x10, 0x48, 0x09, 0x20, 0x21,
     0x83, 0x04, 0x00, 0x42, 0xa4, 0x44, 0x00, 0x00, 0x6c, 0x10, 0xa0, 0x44, 0x48,
     0x80, 0x00, 0x83, 0x80, 0x48, 0xc9, 0x00, 0x00, 0x00, 0x02, 0x05, 0x10, 0xb0,
     0x04, 0x13, 0x04, 0x29, 0x10, 0x92, 0x40, 0x08, 0x04, 0x44, 0x82, 0x22, 0x00,
     0x19, 0x20, 0x00, 0x19, 0x20, 0x01, 0x81, 0x90, 0x60, 0x8a, 0x00, 0x41, 0xc0,
     0x02, 0x45, 0x10, 0x04, 0x00, 0x02, 0xa2, 0x09, 0x40, 0x10, 0x21, 0x49, 0x20,
     0x01, 0x42, 0x30, 0x2c, 0x00, 0x14, 0x44, 0x01, 0x22, 0x04, 0x02, 0x92, 0x08,
     0x89, 0x04, 0x21, 0x80, 0x10, 0x05, 0x01, 0x20, 0x40, 0x41, 0x80, 0x04, 0x00,
     0x12, 0x09, 0x40, 0xb0, 0x64, 0x58, 0x32, 0x01, 0x08, 0x90, 0x00, 0x41, 0x04,
     0x09, 0xc1, 0x80, 0x61, 0x08, 0x90, 0x00, 0x9a, 0x00, 0x24, 0x01, 0x12, 0x08,
     0x02, 0x26, 0x05, 0x82, 0x06, 0x08, 0x08, 0x00, 0x20, 0x48, 0x20, 0x00, 0x18,
     0x24, 0x48, 0x03, 0x02, 0x00, 0x11, 0x00, 0x09, 0x00, 0x84, 0x01, 0x4a, 0x10,
     0x01, 0x98, 0x00, 0x04, 0x18, 0x86, 0x00, 0xc0, 0x00, 0x20, 0x81, 0x80, 0x04,
     0x10, 0x30, 0x05, 0x00, 0xb4, 0x0c, 0x4a, 0x82, 0x29, 0x91, 0x02, 0x28, 0x00,
     0x20, 0x44, 0xc0, 0x00, 0x2c, 0x91, 0x80, 0x40, 0x01, 0xa2, 0x00, 0x12, 0x04,
     0x09, 0xc3, 0x20, 0x00, 0x08, 0x02, 0x0c, 0x10, 0x22, 0x04, 0x00, 0x00, 0x2c,
     0x11, 0x86, 0x00, 0xc0, 0x00, 0x00, 0x12, 0x32, 0x40, 0x89, 0x80, 0x40, 0x40,
     0x02, 0x05, 0x50, 0x86, 0x60, 0x82, 0xa4, 0x60, 0x0a, 0x12, 0x4d, 0x80, 0x90,
     0x08, 0x12, 0x80, 0x09, 0x02, 0x14, 0x48, 0x01, 0x24, 0x20, 0x8a, 0x00, 0x44,
     0x90, 0x04, 0x04, 0x01, 0x02, 0x00, 0xd1, 0x12, 0x00, 0x0a, 0x04, 0x40, 0x00,
     0x32, 0x21, 0x81, 0x24, 0x08, 0x19, 0x84, 0x20, 0x02, 0x04, 0x08, 0x89, 0x80,
     0x24, 0x02, 0x02, 0x68, 0x18, 0x82, 0x44, 0x42, 0x00, 0x21, 0x40, 0x00, 0x28,
     0x01, 0x80, 0x45, 0x82, 0x20, 0x40, 0x11, 0x80, 0x0c, 0x02, 0x00, 0x24, 0x40,
     0x90, 0x01, 0x40, 0x20, 0x20, 0x50, 0x20, 0x28, 0x19, 0x00, 0x40, 0x09, 0x20,
     0x08, 0x80, 0x04, 0x60, 0x40, 0x80, 0x20, 0x08, 0x30, 0x49, 0x09, 0x34, 0x00,
     0x11, 0x24, 0x24, 0x82, 0x00, 0x41, 0xc2, 0x00, 0x04, 0x92, 0x02, 0x24, 0x80,
     0x00, 0x0c, 0x02, 0xa0, 0x00, 0x01, 0x06, 0x60, 0x41, 0x04, 0x21, 0xd0, 0x00,
     0x01, 0x01, 0x00, 0x48, 0x12, 0x84, 0x04, 0x91, 0x12, 0x08, 0x00, 0x24, 0x44,
     0x00, 0x12, 0x41, 0x18, 0x26, 0x0c, 0x41, 0x80, 0x00, 0x52, 0x04, 0x20, 0x09,
     0x00, 0x24, 0x90, 0x20, 0x48, 0x18, 0x02, 0x00, 0x03, 0xa2, 0x09, 0xd0, 0x14,
     0x00, 0x8a, 0x84, 0x25, 0x4a, 0x00, 0x20, 0x98, 0x14, 0x40, 0x00, 0xa2, 0x05,
     0x00, 0x00, 0x00, 0x40, 0x14, 0x01, 0x58, 0x20, 0x2c, 0x80, 0x84, 0x00, 0x09,
     0x20, 0x20, 0x91, 0x02, 0x08, 0x02, 0xb0, 0x41, 0x08, 0x30, 0x00, 0x09, 0x10,
     0x00, 0x18, 0x02, 0x21, 0x02, 0x02, 0x00, 0x00, 0x24, 0x44, 0x08, 0x12, 0x60,
     0x00, 0xb2, 0x44, 0x12, 0x02, 0x0c, 0xc0, 0x80, 0x40, 0xc8, 0x20, 0x04, 0x50,
     0x20, 0x05, 0x00, 0xb0, 0x04, 0x0b, 0x04, 0x29, 0x53, 0x00, 0x61, 0x48, 0x30,
     0x00, 0x82, 0x20, 0x29, 0x00, 0x16, 0x00, 0x53, 0x22, 0x20, 0x43, 0x10, 0x48,
     0x00, 0x80, 0x04, 0xd2, 0x00, 0x40, 0x00, 0xa2, 0x44, 0x03, 0x80, 0x29, 0x00,
     0x04, 0x08, 0xc0, 0x04, 0x64, 0x40, 0x30, 0x28, 0x09, 0x84, 0x44, 0x50, 0x80,
     0x21, 0x02, 0x92, 0x00, 0xc0, 0x10, 0x60, 0x88, 0x22, 0x08, 0x80, 0x00, 0x00,
     0x18, 0x84, 0x04, 0x83, 0x96, 0x00, 0x81, 0x20, 0x05, 0x02, 0x00, 0x45, 0x88,
     0x84, 0x00, 0x51, 0x20, 0x20, 0x51, 0x86, 0x41, 0x4b, 0x94, 0x00, 0x80, 0x00,
     0x08, 0x11, 0x20, 0x4c, 0x58, 0x80, 0x04, 0x03, 0x06, 0x20, 0x89, 0x00, 0x05,
     0x08, 0x22, 0x05, 0x90, 0x00, 0x40, 0x00, 0x82, 0x09, 0x50, 0x00, 0x00, 0x00,
     0xa0, 0x41, 0xc2, 0x20, 0x08, 0x00, 0x16, 0x08, 0x40, 0x26, 0x21, 0xd0, 0x90,
     0x08, 0x81, 0x90, 0x41, 0x00, 0x02, 0x44, 0x08, 0x10, 0x0c, 0x0a, 0x86, 0x09,
     0x90, 0x04, 0x00, 0xc8, 0xa0, 0x04, 0x08, 0x30, 0x20, 0x89, 0x84, 0x00, 0x11,
     0x22, 0x2c, 0x40, 0x00, 0x08, 0x02, 0xb0, 0x01, 0x48, 0x02, 0x01, 0x09, 0x20,
     0x04, 0x03, 0x04, 0x00, 0x80, 0x02, 0x60, 0x42, 0x30, 0x21, 0x4a, 0x10, 0x44,
     0x09, 0x02, 0x00, 0x01, 0x24, 0x00, 0x12, 0x82, 0x21, 0x80, 0xa4, 0x20, 0x10,
     0x02, 0x04, 0x91, 0xa0, 0x40, 0x18, 0x04, 0x00, 0x02, 0x06, 0x69, 0x09, 0x00,
     0x05, 0x58, 0x02, 0x01, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x03, 0x92, 0x20,
     0x00, 0x34, 0x01, 0xc8, 0x20, 0x48, 0x08, 0x30, 0x08, 0x42, 0x80, 0x20, 0x91,
     0x90, 0x68, 0x01, 0x04, 0x40, 0x12, 0x02, 0x61, 0x00, 0x12, 0x08, 0x01, 0xa0,
     0x00, 0x11, 0x04, 0x21, 0x48, 0x04, 0x24, 0x92, 0x00, 0x0c, 0x01, 0x84, 0x04,
     0x00, 0x00, 0x01, 0x12, 0x96, 0x40, 0x01, 0xa0, 0x41, 0x88, 0x22, 0x28, 0x88,
     0x00, 0x44, 0x42, 0x80, 0x24, 0x12, 0x14, 0x01, 0x42, 0x90, 0x60, 0x1a, 0x10,
     0x04, 0x81, 0x10, 0x48, 0x08, 0x06, 0x29, 0x83, 0x02, 0x40, 0x02, 0x24, 0x64,
     0x80, 0x10, 0x05, 0x80, 0x10, 0x40, 0x02, 0x02, 0x08, 0x42, 0x84, 0x01, 0x09,
     0x20, 0x04, 0x50, 0x00, 0x60, 0x11, 0x30, 0x40, 0x13, 0x02, 0x04, 0x81, 0x00,
     0x09, 0x08, 0x20, 0x45, 0x4a, 0x10, 0x61, 0x90, 0x26, 0x0c, 0x08, 0x02, 0x21,
     0x91, 0x00, 0x60, 0x02, 0x04, 0x00, 0x02, 0x00, 0x0c, 0x08, 0x06, 0x08, 0x48,
     0x84, 0x08, 0x11, 0x02, 0x00, 0x80, 0xa4, 0x00, 0x5a, 0x20, 0x00, 0x88, 0x04,
     0x04, 0x02, 0x00, 0x09, 0x00, 0x14, 0x08, 0x49, 0x14, 0x20, 0xc8, 0x00, 0x04,
     0x91, 0xa0, 0x40, 0x59, 0x80, 0x00, 0x12, 0x10, 0x00, 0x80, 0x80, 0x65, 0x00,
     0x00, 0x04, 0x00, 0x80, 0x40, 0x19, 0x00, 0x21, 0x03, 0x84, 0x60, 0xc0, 0x04,
     0x24, 0x1a, 0x12, 0x61, 0x80, 0x80, 0x08, 0x02, 0x04, 0x09, 0x42, 0x12, 0x20,
     0x08, 0x34, 0x04, 0x90, 0x20, 0x01, 0x01, 0xa0, 0x00, 0x0b, 0x00, 0x08, 0x91,
     0x92, 0x40, 0x02, 0x34, 0x40, 0x88, 0x10, 0x61, 0x19, 0x02, 0x00, 0x40, 0x04,
     0x25, 0xc0, 0x80, 0x68, 0x08, 0x04, 0x21, 0x80, 0x22, 0x04, 0x00, 0xa0, 0x0c,
     0x01, 0x84, 0x20, 0x41, 0x00, 0x08, 0x8a, 0x00, 0x20, 0x8a, 0x00, 0x48, 0x88,
     0x04, 0x04, 0x11, 0x82, 0x08, 0x40, 0x86, 0x09, 0x49, 0xa4, 0x40, 0x00, 0x10,
     0x01, 0x01, 0xa2, 0x04, 0x50, 0x80, 0x0c, 0x80, 0x00, 0x48, 0x82, 0xa0, 0x01,
     0x18, 0x12, 0x41, 0x01, 0x04, 0x48, 0x41, 0x00, 0x24, 0x01, 0x00, 0x00, 0x88,
     0x14, 0x00, 0x02, 0x00, 0x68, 0x01, 0x20, 0x08, 0x4a, 0x22, 0x08, 0x83, 0x80,
     0x00, 0x89, 0x04, 0x01, 0xc2, 0x00, 0x00, 0x00, 0x34, 0x04, 0x00, 0x82, 0x28,
     0x02, 0x02, 0x41, 0x4a, 0x90, 0x05, 0x82, 0x02, 0x09, 0x80, 0x24, 0x04, 0x41,
     0x00, 0x01, 0x92, 0x80, 0x28, 0x01, 0x14, 0x00, 0x50, 0x20, 0x4c, 0x10, 0xb0,
     0x04, 0x43, 0xa4, 0x21, 0x90, 0x04, 0x01, 0x02, 0x00, 0x44, 0x48, 0x00, 0x64,
     0x08, 0x06, 0x00, 0x42, 0x20, 0x08, 0x02, 0x92, 0x01, 0x4a, 0x00, 0x20, 0x50,
     0x32, 0x25, 0x90, 0x22, 0x04, 0x09, 0x00, 0x08, 0x11, 0x80, 0x21, 0x01, 0x10,
     0x05, 0x00, 0x32, 0x08, 0x88, 0x94, 0x08, 0x08, 0x24, 0x0d, 0xc1, 0x80, 0x40,
     0x0b, 0x20, 0x40, 0x18, 0x12, 0x04, 0x00, 0x22, 0x40, 0x10, 0x26, 0x05, 0xc1,
     0x82, 0x00, 0x01, 0x30, 0x24, 0x02, 0x22, 0x41, 0x08, 0x24, 0x48, 0x1a, 0x00,
     0x25, 0xd2, 0x12, 0x28, 0x42, 0x00, 0x04, 0x40, 0x30, 0x41, 0x00, 0x02, 0x00,
     0x13, 0x20, 0x24, 0xd1, 0x84, 0x08, 0x89, 0x80, 0x04, 0x52, 0x00, 0x44, 0x18,
     0xa4, 0x00, 0x00, 0x06, 0x20, 0x91, 0x10, 0x09, 0x42, 0x20, 0x24, 0x40, 0x30,
     0x28, 0x00, 0x84, 0x40, 0x40, 0x80, 0x08, 0x10, 0x04, 0x09, 0x08, 0x04, 0x40,
     0x08, 0x22, 0x00, 0x19, 0x02, 0x00, 0x00, 0x80, 0x2c, 0x02, 0x02, 0x21, 0x01,
     0x90, 0x20, 0x40, 0x00, 0x0c, 0x00, 0x34, 0x48, 0x58, 0x20, 0x01, 0x43, 0x04,
     0x20, 0x80, 0x14, 0x00, 0x90, 0x00, 0x6d, 0x11, 0x00, 0x00, 0x40, 0x20, 0x00,
     0x03, 0x10, 0x40, 0x88, 0x30, 0x05, 0x4a, 0x00, 0x65, 0x10, 0x24, 0x08, 0x18,
     0x84, 0x28, 0x03, 0x80, 0x20, 0x42, 0xb0, 0x40, 0x00, 0x10, 0x69, 0x19, 0x04,
     0x00, 0x00, 0x80, 0x04, 0xc2, 0x04, 0x00, 0x01, 0x00, 0x05, 0x00, 0x22, 0x25,
     0x08, 0x96, 0x04, 0x02, 0x22, 0x00, 0xd0, 0x10, 0x29, 0x01, 0xa0, 0x60, 0x08,
     0x10, 0x04, 0x01, 0x16, 0x44, 0x10, 0x02, 0x28, 0x02, 0x82, 0x48, 0x40, 0x84,
     0x20, 0x90, 0x22, 0x28, 0x80, 0x04, 0x00, 0x40, 0x04, 0x24, 0x00, 0x80, 0x29,
     0x03, 0x10, 0x60, 0x48, 0x00, 0x00, 0x81, 0xa0, 0x00, 0x51, 0x20, 0x0c, 0xd1,
     0x00, 0x01, 0x41, 0x20, 0x04, 0x92, 0x00, 0x00, 0x10, 0x92, 0x00, 0x42, 0x04,
     0x05, 0x01, 0x86, 0x40, 0x80, 0x10, 0x20, 0x52, 0x20, 0x21, 0x00, 0x10, 0x48,
     0x0a, 0x02, 0x00, 0xd0, 0x12, 0x41, 0x48, 0x80, 0x04, 0x00, 0x00, 0x48, 0x09,
     0x22, 0x04, 0x00, 0x24, 0x00, 0x43, 0x10, 0x60, 0x0a, 0x00, 0x44, 0x12, 0x20,
     0x2c, 0x08, 0x20, 0x44, 0x00, 0x84, 0x09, 0x40, 0x06, 0x08, 0xc1, 0x00, 0x40,
     0x80, 0x20, 0x00, 0x98, 0x12, 0x48, 0x10, 0xa2, 0x20, 0x00, 0x84, 0x48, 0xc0,
     0x10, 0x20, 0x90, 0x12, 0x08, 0x98, 0x82, 0x00, 0x0a, 0xa0, 0x04, 0x03, 0x00,
     0x28, 0xc3, 0x00, 0x44, 0x42, 0x10, 0x04, 0x08, 0x04, 0x40, 0x00, 0x00, 0x05,
     0x10, 0x00, 0x21, 0x03, 0x80, 0x04, 0x88, 0x12, 0x69, 0x10, 0x00, 0x04, 0x08,
     0x04, 0x04, 0x02, 0x84, 0x48, 0x49, 0x04, 0x20, 0x18, 0x02, 0x64, 0x80, 0x30,
     0x08, 0x01, 0x02, 0x00, 0x52, 0x12, 0x49, 0x08, 0x20, 0x41, 0x88, 0x10, 0x48,
     0x08, 0x34, 0x00, 0x01, 0x86, 0x05, 0xd0, 0x00, 0x00, 0x83, 0x84, 0x21, 0x40,
     0x02, 0x41, 0x10, 0x80, 0x48, 0x40, 0xa2, 0x20, 0x51, 0x00, 0x00, 0x49, 0x00,
     0x01, 0x90, 0x20, 0x40, 0x18, 0x02, 0x40, 0x02, 0x22, 0x05, 0x40, 0x80, 0x08,
     0x82, 0x10, 0x20, 0x18, 0x00, 0x05, 0x01, 0x82, 0x40, 0x58, 0x00, 0x04, 0x81,
     0x90, 0x29, 0x01, 0xa0, 0x64, 0x00, 0x22, 0x40, 0x01, 0xa2, 0x00, 0x18, 0x04,
     0x0d, 0x00, 0x00, 0x60, 0x80, 0x94, 0x60, 0x82, 0x10, 0x0d, 0x80, 0x30, 0x0c,
     0x12, 0x20, 0x00, 0x00, 0x12, 0x40, 0xc0, 0x20, 0x21, 0x58, 0x02, 0x41, 0x10,
     0x80, 0x44, 0x03, 0x02, 0x04, 0x13, 0x90, 0x29, 0x08, 0x00, 0x44, 0xc0, 0x00,
     0x21, 0x00, 0x26, 0x00, 0x1a, 0x80, 0x01, 0x13, 0x14, 0x20, 0x0a, 0x14, 0x20,
     0x00, 0x32, 0x61, 0x08, 0x00, 0x40, 0x42, 0x20, 0x09, 0x80, 0x06, 0x01, 0x81,
     0x80, 0x60, 0x42, 0x00, 0x68, 0x90, 0x82, 0x08, 0x42, 0x80, 0x04, 0x02, 0x80,
     0x09, 0x0b, 0x04, 0x00, 0x98, 0x00, 0x0c, 0x81, 0x06, 0x44, 0x48, 0x84, 0x28,
     0x03, 0x92, 0x00, 0x01, 0x80, 0x40, 0x0a, 0x00, 0x0c, 0x81, 0x02, 0x08, 0x51,
     0x04, 0x28, 0x90, 0x02, 0x20, 0x09, 0x10, 0x60, 0x00, 0x00, 0x09, 0x81, 0xa0,
     0x0c, 0x00, 0xa4, 0x09, 0x00, 0x02, 0x28, 0x80, 0x20, 0x00, 0x02, 0x02, 0x04,
     0x81, 0x14, 0x04, 0x00, 0x04, 0x09, 0x11, 0x12, 0x60, 0x40, 0x20, 0x01, 0x48,
     0x30, 0x40, 0x11, 0x00, 0x08, 0x0a, 0x86, 0x00, 0x00, 0x04, 0x60, 0x81, 0x04,
     0x01, 0xd0, 0x02, 0x41, 0x18, 0x90, 0x00, 0x0a, 0x20, 0x00, 0xc1, 0x06, 0x01,
     0x08, 0x80, 0x64, 0xca, 0x10, 0x04, 0x99, 0x80, 0x48, 0x01, 0x82, 0x20, 0x50,
     0x90, 0x48, 0x80, 0x84, 0x20, 0x90, 0x22, 0x00, 0x19, 0x00, 0x04, 0x18, 0x20,
     0x24, 0x10, 0x86, 0x40, 0xc2, 0x00, 0x24, 0x12, 0x10, 0x44, 0x00, 0x16, 0x08,
     0x10, 0x24, 0x00, 0x12, 0x06, 0x01, 0x08, 0x90, 0x00, 0x12, 0x02, 0x4d, 0x10,
     0x80, 0x40, 0x50, 0x22, 0x00, 0x43, 0x10, 0x01, 0x00, 0x30, 0x21, 0x0a, 0x00,
     0x00, 0x01, 0x14, 0x00, 0x10, 0x84, 0x04, 0xc1, 0x10, 0x29, 0x0a, 0x00, 0x01,
     0x8a, 0x00, 0x20, 0x01, 0x12, 0x0c, 0x49, 0x20, 0x04, 0x81, 0x00, 0x48, 0x01,
     0x04, 0x60, 0x80, 0x12, 0x0c, 0x08, 0x10, 0x48, 0x4a, 0x04, 0x28, 0x10, 0x00,
     0x28, 0x40, 0x84, 0x45, 0x50, 0x10, 0x60, 0x10, 0x06, 0x44, 0x01, 0x80, 0x09,
     0x00, 0x86, 0x01, 0x42, 0xa0, 0x00, 0x90, 0x00, 0x05, 0x90, 0x22, 0x40, 0x41,
     0x00, 0x08, 0x80, 0x02, 0x08, 0xc0, 0x00, 0x01, 0x58, 0x30, 0x49, 0x09, 0x14,
     0x00, 0x41, 0x02, 0x0c, 0x02, 0x80, 0x40, 0x89, 0x00, 0x24, 0x08, 0x10, 0x05,
     0x90, 0x32, 0x40, 0x0a, 0x82, 0x08, 0x00, 0x12, 0x61, 0x00, 0x04, 0x21, 0x00,
     0x22, 0x04, 0x10, 0x24, 0x08, 0x0a, 0x04, 0x01, 0x10, 0x00, 0x20, 0x40, 0x84,
     0x04, 0x88, 0x22, 0x20, 0x90, 0x12, 0x00, 0x53, 0x06, 0x24, 0x01, 0x04, 0x40,
     0x0b, 0x14, 0x60, 0x82, 0x02, 0x0d, 0x10, 0x90, 0x0c, 0x08, 0x20, 0x09, 0x00,
     0x14, 0x09, 0x80, 0x80, 0x24, 0x82, 0x00, 0x40, 0x01, 0x02, 0x44, 0x01, 0x20,
     0x0c, 0x40, 0x84, 0x40, 0x0a, 0x10, 0x41, 0x00, 0x30, 0x05, 0x09, 0x80, 0x44,
     0x08, 0x20, 0x20, 0x02, 0x00, 0x49, 0x43, 0x20, 0x21, 0x00, 0x20, 0x00, 0x01,
     0xb6, 0x08, 0x40, 0x04, 0x08, 0x02, 0x80, 0x01, 0x41, 0x80, 0x40, 0x08, 0x10,
     0x24, 0x00, 0x20, 0x04, 0x12, 0x86, 0x09, 0xc0, 0x12, 0x21, 0x81, 0x14, 0x04,
     0x00, 0x02, 0x20, 0x89, 0xb4, 0x44, 0x12, 0x80, 0x00, 0xd1, 0x00, 0x69, 0x40,
     0x80, 0x00, 0x42, 0x12, 0x00, 0x18, 0x04, 0x00, 0x49, 0x06, 0x21, 0x02, 0x04,
     0x28, 0x02, 0x84, 0x01, 0xc0, 0x10, 0x68, 0x00, 0x20, 0x08, 0x40, 0x00, 0x08,
     0x91, 0x10, 0x01, 0x81, 0x24, 0x04, 0xd2, 0x10, 0x4c, 0x88, 0x86, 0x00, 0x10,
     0x80, 0x0c, 0x02, 0x14, 0x00, 0x8a, 0x90, 0x40, 0x18, 0x20, 0x21, 0x80, 0xa4,
     0x00, 0x58, 0x24, 0x20, 0x10, 0x10, 0x60, 0xc1, 0x30, 0x41, 0x48, 0x02, 0x48,
     0x09, 0x00, 0x40, 0x09, 0x02, 0x05, 0x11, 0x82, 0x20, 0x4a, 0x20, 0x24, 0x18,
     0x02, 0x0c, 0x10, 0x22, 0x0c, 0x0a, 0x04, 0x00, 0x03, 0x06, 0x48, 0x48, 0x04,
     0x04, 0x02, 0x00, 0x21, 0x80, 0x84, 0x00, 0x18, 0x00, 0x0c, 0x02, 0x12, 0x01,
     0x00, 0x14, 0x05, 0x82, 0x10, 0x41, 0x89, 0x12, 0x08, 0x40, 0xa4, 0x21, 0x01,
     0x84, 0x48, 0x02, 0x10, 0x60, 0x40, 0x02, 0x28, 0x00, 0x14, 0x08, 0x40, 0xa0,
     0x20, 0x51, 0x12, 0x00, 0xc2, 0x00, 0x01, 0x1a, 0x30, 0x40, 0x89, 0x12, 0x4c,
     0x02, 0x80, 0x00, 0x00, 0x14, 0x01, 0x01, 0xa0, 0x21, 0x18, 0x22, 0x21, 0x18,
     0x06, 0x40, 0x01, 0x80, 0x00, 0x90, 0x04, 0x48, 0x02, 0x30, 0x04, 0x08, 0x00,
     0x05, 0x88, 0x24, 0x08, 0x48, 0x04, 0x24, 0x02, 0x06, 0x00, 0x80, 0x00, 0x00,
     0x00, 0x10, 0x65, 0x11, 0x90, 0x00, 0x0a, 0x82, 0x04, 0xc3, 0x04, 0x60, 0x48,
     0x24, 0x04, 0x92, 0x02, 0x44, 0x88, 0x80, 0x40, 0x18, 0x06, 0x29, 0x80, 0x10,
     0x01, 0x00, 0x00, 0x44, 0xc8, 0x10, 0x21, 0x89, 0x30, 0x00, 0x4b, 0xa0, 0x01,
     0x10, 0x14, 0x00, 0x02, 0x94, 0x40, 0x00, 0x20, 0x65, 0x00, 0xa2, 0x0c, 0x40,
     0x22, 0x20, 0x81, 0x12, 0x20, 0x82, 0x04, 0x01, 0x10, 0x00, 0x08, 0x88, 0x00,
     0x00, 0x11, 0x80, 0x04, 0x42, 0x80, 0x40, 0x41, 0x14, 0x00, 0x40, 0x32, 0x2c,
     0x80, 0x24, 0x04, 0x19, 0x00, 0x00, 0x91, 0x00, 0x20, 0x83, 0x00, 0x05, 0x40,
     0x20, 0x09, 0x01, 0x84, 0x40, 0x40, 0x20, 0x20, 0x11, 0x00, 0x40, 0x41, 0x90,
     0x20, 0x00, 0x00, 0x40, 0x90, 0x92, 0x48, 0x18, 0x06, 0x08, 0x81, 0x80, 0x48,
     0x01, 0x34, 0x24, 0x10, 0x20, 0x04, 0x00, 0x20, 0x04, 0x18, 0x06, 0x2d, 0x90,
     0x10, 0x01, 0x00, 0x90, 0x00, 0x0a, 0x22, 0x01, 0x00, 0x22, 0x00, 0x11, 0x84,
     0x01, 0x01, 0x00, 0x20, 0x88, 0x00, 0x44, 0x00, 0x22, 0x01, 0x00, 0xa6, 0x40,
     0x02, 0x06, 0x20, 0x11, 0x00, 0x01, 0xc8, 0xa0, 0x04, 0x8a, 0x00, 0x28, 0x19,
     0x80, 0x00, 0x52, 0xa0, 0x24, 0x12, 0x12, 0x09, 0x08, 0x24, 0x01, 0x48, 0x00,
     0x04, 0x00, 0x24, 0x40, 0x02, 0x84, 0x08, 0x00, 0x04, 0x48, 0x40, 0x90, 0x60,
     0x0a, 0x22, 0x01, 0x88, 0x14, 0x08, 0x01, 0x02, 0x08, 0xd3, 0x00, 0x20, 0xc0,
     0x90, 0x24, 0x10, 0x00, 0x00, 0x01, 0xb0, 0x08, 0x0a, 0xa0, 0x00, 0x80, 0x00,
     0x01, 0x09, 0x00, 0x20, 0x52, 0x02, 0x25, 0x00, 0x24, 0x04, 0x02, 0x84, 0x24,
     0x10, 0x92, 0x40, 0x02, 0xa0, 0x40, 0x00, 0x22, 0x08, 0x11, 0x04, 0x08, 0x01,
     0x22, 0x00, 0x42, 0x14, 0x00, 0x09, 0x90, 0x21, 0x00, 0x30, 0x6c, 0x00, 0x00,
     0x0c, 0x00, 0x22, 0x09, 0x90, 0x10, 0x28, 0x40, 0x00, 0x20, 0xc0, 0x20, 0x00,
     0x90, 0x00, 0x40, 0x01, 0x82, 0x05, 0x12, 0x12, 0x09, 0xc1, 0x04, 0x61, 0x80,
     0x02, 0x28, 0x81, 0x24, 0x00, 0x49, 0x04, 0x08, 0x10, 0x86, 0x29, 0x41, 0x80,
     0x21, 0x0a, 0x30, 0x49, 0x88, 0x90, 0x00, 0x41, 0x04, 0x29, 0x81, 0x80, 0x41,
     0x09, 0x00, 0x40, 0x12, 0x10, 0x40, 0x00, 0x10, 0x40, 0x48, 0x02, 0x05, 0x80,
     0x02, 0x21, 0x40, 0x20, 0x00, 0x58, 0x20, 0x60, 0x00, 0x90, 0x48, 0x00, 0x80,
     0x28, 0xc0, 0x80, 0x48, 0x00, 0x00, 0x44, 0x80, 0x02, 0x00, 0x09, 0x06, 0x00,
     0x12, 0x02, 0x01, 0x00, 0x10, 0x08, 0x83, 0x10, 0x45, 0x12, 0x00, 0x2c, 0x08,
     0x04, 0x44, 0x00, 0x20, 0x20, 0xc0, 0x10, 0x20, 0x01, 0x00, 0x05, 0xc8, 0x20,
     0x04, 0x98, 0x10, 0x08, 0x10, 0x00, 0x24, 0x02, 0x16, 0x40, 0x88, 0x00, 0x61,
     0x88, 0x12, 0x24, 0x80, 0xa6, 0x00, 0x42, 0x00, 0x08, 0x10, 0x06, 0x48, 0x40,
     0xa0, 0x00, 0x50, 0x20, 0x04, 0x81, 0xa4, 0x40, 0x18, 0x00, 0x08, 0x10, 0x80,
     0x01, 0x01};

#if RSA_KEY_SIEVE && SIMULATION && RSA_INSTRUMENT
UINT32 PrimeIndex               = 0;
UINT32 failedAtIteration[10]    = {0};
UINT32 PrimeCounts[3]           = {0};
UINT32 MillerRabinTrials[3]     = {0};
UINT32 totalFieldsSieved[3]     = {0};
UINT32 bitsInFieldAfterSieve[3] = {0};
UINT32 emptyFieldsSieved[3]     = {0};
UINT32 noPrimeFields[3]         = {0};
UINT32 primesChecked[3]         = {0};
UINT16 lastSievePrime           = 0;
#endif
