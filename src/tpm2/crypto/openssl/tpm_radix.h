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

//** Introduction
// Common defines for supporting large numbers and cryptographic buffer sizing.
//*********************

#ifdef TPM_POSIX                       // libtpms added begin
# include <openssl/bn.h>
# ifdef THIRTY_TWO_BIT
#  define RADIX_BITS                     32
# endif
# ifdef SIXTY_FOUR_BIT_LONG
#  define RADIX_BITS                     64
# endif
# ifndef RADIX_BITS
#  error Need to determine RADIX_BITS value
# endif
#endif
#ifdef TPM_WINDOWS
#define  RADIX_BITS                      32
#endif                                 // libtpms added end

#ifndef RADIX_BITS
#  if defined(__x86_64__) || defined(__x86_64) || defined(__amd64__)	\
    || defined(__amd64) || defined(_WIN64) || defined(_M_X64) || defined(_M_ARM64) \
    || defined(__aarch64__) || defined(__PPC64__) || defined(__s390x__) \
    || defined(__powerpc64__) || defined(__ppc64__)
#    define RADIX_BITS 64
#  elif defined(__i386__) || defined(__i386) || defined(i386) || defined(_WIN32) \
    || defined(_M_IX86)
#    define RADIX_BITS 32
#  elif defined(_M_ARM) || defined(__arm__) || defined(__thumb__)
#    define RADIX_BITS 32
#  elif defined(__riscv)
// __riscv and __riscv_xlen are standardized by the RISC-V community and should be available
// on any compliant compiler.
//
// https://github.com/riscv-non-isa/riscv-toolchain-conventions
#    define RADIX_BITS __riscv_xlen
#  else
#    error Unable to determine RADIX_BITS from compiler environment
#  endif
#endif  // RADIX_BITS

#if RADIX_BITS == 64
#  define RADIX_BYTES 8
#  define RADIX_LOG2  6
#elif RADIX_BITS == 32
#  define RADIX_BYTES 4
#  define RADIX_LOG2  5
#else
#  error "RADIX_BITS must either be 32 or 64"
#endif

#define HASH_ALIGNMENT      RADIX_BYTES
#define SYMMETRIC_ALIGNMENT RADIX_BYTES

#define RADIX_MOD(x) ((x) & ((1 << RADIX_LOG2) - 1))
#define RADIX_DIV(x) ((x) >> RADIX_LOG2)
#define RADIX_MASK   ((((crypt_uword_t)1) << RADIX_LOG2) - 1)

#define BITS_TO_CRYPT_WORDS(bits)   RADIX_DIV((bits) + (RADIX_BITS - 1))
#define BYTES_TO_CRYPT_WORDS(bytes) BITS_TO_CRYPT_WORDS(bytes * 8)
#define SIZE_IN_CRYPT_WORDS(thing)  BYTES_TO_CRYPT_WORDS(sizeof(thing))

#if RADIX_BITS == 64
#  define SWAP_CRYPT_WORD(x) REVERSE_ENDIAN_64(x)
typedef uint64_t crypt_uword_t;
typedef int64_t  crypt_word_t;
#  define TO_CRYPT_WORD_64             BIG_ENDIAN_BYTES_TO_UINT64
#  define TO_CRYPT_WORD_32(a, b, c, d) TO_CRYPT_WORD_64(0, 0, 0, 0, a, b, c, d)
#define BN_PAD      0    			// libtpms added
#elif RADIX_BITS == 32
#  define SWAP_CRYPT_WORD(x) REVERSE_ENDIAN_32((x))
typedef uint32_t crypt_uword_t;
typedef int32_t  crypt_word_t;
#  define TO_CRYPT_WORD_64(a, b, c, d, e, f, g, h)			\
    BIG_ENDIAN_BYTES_TO_UINT32(e, f, g, h), BIG_ENDIAN_BYTES_TO_UINT32(a, b, c, d)
#define BN_PAD      1    /* libtpms added */
#endif

#define MAX_CRYPT_UWORD (~((crypt_uword_t)0))
#define MAX_CRYPT_WORD  ((crypt_word_t)(MAX_CRYPT_UWORD >> 1))
#define MIN_CRYPT_WORD  (~MAX_CRYPT_WORD)

// Avoid expanding LARGEST_NUMBER into a long expression that inlines 3 other long expressions.
// TODO: Decrease the size of each of the MAX_* expressions with improvements to the code generator.
#if ALG_RSA == ALG_YES
// The smallest supported RSA key (1024 bits) is larger than
// the largest supported ECC curve (628 bits)
// or the largest supported digest (512 bits)
#  define LARGEST_NUMBER MAX_RSA_KEY_BYTES
#elif ALG_ECC == ALG_YES
#  define LARGEST_NUMBER MAX(MAX_ECC_KEY_BYTES, MAX_DIGEST_SIZE)
#else
#  define LARGEST_NUMBER MAX_DIGEST_SIZE
#endif  // ALG_RSA == YES

#define LARGEST_NUMBER_BITS (LARGEST_NUMBER * 8)

#define MAX_ECC_PARAMETER_BYTES (MAX_ECC_KEY_BYTES * ALG_ECC)

// These macros use the selected libraries to get the proper include files.
// clang-format off
#define LIB_QUOTE(_STRING_)                    #_STRING_
/* kgold removed subdirectory */
#define LIB_INCLUDE2(_PREFIX_, _LIB_, _TYPE_)  LIB_QUOTE(_PREFIX_##_LIB_##_TYPE_.h)
#define LIB_INCLUDE(_PREFIX_, _LIB_, _TYPE_)   LIB_INCLUDE2(_PREFIX_,_LIB_, _TYPE_)
// clang-format on
