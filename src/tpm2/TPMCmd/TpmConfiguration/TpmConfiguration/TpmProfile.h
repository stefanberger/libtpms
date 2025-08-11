// SPDX-License-Identifier: BSD-2-Clause

// FOR LIBTPMS: DO NOT EDIT THIS or INCLUDED FILES!
// ANY MODIFICATION WILL LEAD TO AN UNSUPPORTED CONFIGURATION

// The primary configuration file that collects all configuration options for a
// TPM build.
#ifndef _TPM_PROFILE_H_
#define _TPM_PROFILE_H_

#include <TpmConfiguration/TpmBuildSwitches.h>
#include <TpmConfiguration/TpmProfile_Common.h>
#include <TpmConfiguration/TpmProfile_CommandList.h>
#include <TpmConfiguration/TpmProfile_Misc.h>
#include <TpmConfiguration/TpmProfile_ErrorCodes.h>

//					libtpms: added begin
#ifndef HASH_LIB
#define HASH_LIB                        Ossl
#endif
#ifndef SYM_LIB
#define SYM_LIB                         Ossl
#endif
#ifndef MATH_LIB
#define MATH_LIB                        TpmBigNum
#endif
#ifndef BN_MATH_LIB
#define BN_MATH_LIB			Ossl
#endif
//					libtpms: added end

#endif  // _TPM_PROFILE_H_
