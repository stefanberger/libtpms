// SPDX-License-Identifier: BSD-2-Clause

// (c) Copyright IBM Corporation 2018.

#ifndef LIBTPMS_CALLBACKS_H
#define LIBTPMS_CALLBACKS_H

#define LIBTPMS_CALLBACK_FALLTHROUGH -2

int libtpms_plat__NVEnable(void);
int libtpms_plat__NVDisable(void);
int libtpms_plat__IsNvAvailable(void);
int libtpms_plat__NvCommit(void);
int libtpms_plat__PhysicalPresenceAsserted(BOOL *pp);

#endif /* LIBTPMS_CALLBACKS_H */
