/*
 * Part of Android VSoC USB Host Driver.
 *
 * Copyright (C) 2017 Google, Inc.
 *
 * Author: romitd@google.com
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __VSOC_USB_SHM_H
#define __VSOC_USB_SHM_H

#include "vsoc_usb_common.h"
#include "vsoc_usb_regs.h"

extern struct vsoc_usb_shm *vsoc_usb_shm_get(unsigned int index);

/* called by guest */
extern int vsoc_usb_register_h2g_ipi(int (*kick)(unsigned long data),
				     unsigned long data);
extern int vsoc_usb_unregister_h2g_ipi(void);
extern int vsoc_usb_g2h_kick(void);

/* called by host */
extern int vsoc_usb_register_g2h_ipi(int (*kick) (unsigned long data),
				     unsigned long data);
extern int vsoc_usb_unregister_g2h_ipi(void);
extern int vsoc_usb_h2g_kick(void);

#endif /* __VSOC_USB_SHM_H */
