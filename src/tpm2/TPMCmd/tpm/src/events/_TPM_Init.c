// SPDX-License-Identifier: BSD-2-Clause

#include <private/Tpm.h>
// TODO_RENAME_INC_FOLDER:platform_interface refers to the TPM_CoreLib platform interface
#include <platform_interface/prototypes/_TPM_Init_fp.h>
#include "StateMarshal.h"		// libtpms added

// Move this to a future _plat_NvUpdateData() API and perform this in
// platform code.
static void UpgradeNvData()					// libtpms changed: static
{
    // only update when required to avoid unnecessary flash defragmentation
    if(gp.firmwareV1 != _plat__GetTpmFirmwareVersionHigh()
       || gp.firmwareV2 != _plat__GetTpmFirmwareVersionLow())
    {
        gp.firmwareV1 = _plat__GetTpmFirmwareVersionHigh();
        gp.firmwareV2 = _plat__GetTpmFirmwareVersionLow();
        NV_SYNC_PERSISTENT(firmwareV1);
        NV_SYNC_PERSISTENT(firmwareV2);
    }
}

// This function is used to process a _TPM_Init indication.
LIB_EXPORT void _TPM_Init(void)
{
    BOOL restored  = FALSE;  /* libtpms added */
    _plat__StartTpmInit();
    g_powerWasLost = g_powerWasLost | _plat__WasPowerLost();

#if SIMULATION && DEBUG
    // If power was lost and this was a simulation, put canary in RAM used by NV
    // so that uninitialized memory can be detected more easily
    if(g_powerWasLost)
    {
        memset(&gc, 0xbb, sizeof(gc));
        memset(&gr, 0xbb, sizeof(gr));
        memset(&gp, 0xbb, sizeof(gp));
        memset(&go, 0xbb, sizeof(go));
    }
#endif

#if ALLOW_FORCE_FAILURE_MODE
    // Clear the flag that forces failure on self-test
    g_forceFailureMode = FALSE;
#endif

    // Disable the tick processing
#if ACT_SUPPORT || 1	// libtpms: changed
    _plat__ACT_EnableTicks(FALSE);
#endif

    // Set initialization state
    TPMInit();

    // Set g_DRTMHandle as unassigned
    g_DRTMHandle = TPM_RH_UNASSIGNED;

    // No H-CRTM, yet.
    g_DrtmPreStartup = FALSE;

    // Initialize the NvEnvironment.
    g_nvOk = NvPowerOn();

    // Initialize cryptographic functions

#if 0								// libtpms added
	                // libtpms: FAIL would do longjmp, but there was no setjmp
    if(g_nvOk != TRUE)
    {
        FAIL(FATAL_ERROR_NV_INIT);
    }
    else if(!CryptInit())
    {
        FAIL(FATAL_ERROR_CRYPTO_INIT);
    }
#else								// libtpms added begin
    BOOL inFailureMode = (g_nvOk == FALSE) || (CryptInit() == FALSE);
    if (inFailureMode)
        _plat__SetInFailureMode(TRUE);
#endif								// libtpms added end

    if(!_plat__InFailureMode())
    {
        // Load the persistent data
        NvReadPersistent();

        // Load the orderly data (clock and DRBG state).
        // If this is not done here, things break
        NvRead(&go, NV_ORDERLY_DATA, sizeof(go));

        // Update and fix up any NV variables
        UpgradeNvData();

        // Start clock. Need to do this after NV has been restored.
        TimePowerOn();
                                        /* libtpms added begin */
        VolatileLoad(&restored);
        if (restored)
            NVShadowRestore();
                                        /* libtpms added end */
    }

    g_initCompleted = TRUE;
    if(! _plat__InFailureMode())
    {
        _plat__EndOkTpmInit();
    }

    return;
}
