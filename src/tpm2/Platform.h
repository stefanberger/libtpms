// SPDX-License-Identifier: BSD-2-Clause


#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#include "TpmBuildSwitches.h"
#include "TpmProfile.h"
#include "BaseTypes.h"
#include "TPMB.h"
#include "MinMax.h"

#include "PlatformACT.h"
#include "PlatformClock.h"
#include "PlatformData.h"
#include "platform_public_interface.h"
#include "tpm_to_platform_interface.h"
#include "platform_to_tpm_interface.h"
#include "PlatformInternal.h"

#define GLOBAL_C
#define NV_C
#include "pcrstruct.h"
#include "platform_pcr_fp.h"

#endif  // _PLATFORM_H_
