// SPDX-License-Identifier: BSD-2-Clause

#ifndef _TPM_INCLUDE_PRIVATE_ARCHSPECIFICS_H_
#define _TPM_INCLUDE_PRIVATE_ARCHSPECIFICS_H_

#if defined(__m68k__)
  // https://wiki.debian.org/M68k/Alignment
# define ARCH_NEEDS_INT_PADDING
#endif

#if defined(ARCH_NEEDS_INT_PADDING)
# define ARCH_PADDING(NAME, SIZE)  char NAME[SIZE]
#else
# define ARCH_PADDING(NAME, SIZE)
#endif

#endif /* _TPM_INCLUDE_PRIVATE_ARCHSPECIFICS_H_ */
