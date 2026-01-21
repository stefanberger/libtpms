// SPDX-License-Identifier: BSD-2-Clause

//** Description

//    This module simulates the physical presence interface pins on the TPM.

//** Includes
#include "Platform.h"
#include "LibtpmsCallbacks.h" /* libtpms added */

//** Functions

//***_plat__PhysicalPresenceAsserted()
// Check if physical presence is signaled
//  Return Type: int
//      TRUE(1)         if physical presence is signaled
//      FALSE(0)        if physical presence is not signaled
LIB_EXPORT int _plat__PhysicalPresenceAsserted(void)
{
#ifdef TPM_LIBTPMS_CALLBACKS
    BOOL pp;
    int ret = libtpms_plat__PhysicalPresenceAsserted(&pp);

    if (ret != LIBTPMS_CALLBACK_FALLTHROUGH)
        return pp;
#endif /* TPM_LIBTPMS_CALLBACKS */
    // Do not know how to check physical presence without real hardware.
    // so always return TRUE;
    return s_physicalPresence;
}

#if 0 /* libtpms added */
//***_plat__Signal_PhysicalPresenceOn()
// Signal physical presence on
LIB_EXPORT void _plat__Signal_PhysicalPresenceOn(void)
{
    s_physicalPresence = TRUE;
    return;
}

//***_plat__Signal_PhysicalPresenceOff()
// Signal physical presence off
LIB_EXPORT void _plat__Signal_PhysicalPresenceOff(void)
{
    s_physicalPresence = FALSE;
    return;
}
#endif /* libtpms added */
