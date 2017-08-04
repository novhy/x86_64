/*
 * Part of Android VSoC USB Gadget Controller Driver.
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
 * Based on drivers/usb/gadget/udc/dummy_hcd.c - Dummy/Loopback USB Host and
 * device emulator driver.
 *  Copyright (C) 2003 David Brownell
 *  Copyright (C) 2003-2005 Alan Stern
 */

#ifndef __VSOC_USB_GADGET_DRIVER_H
#define __VSOC_USB_GADGET_DRIVER_H
#include <linux/pm.h>
#include "vsoc_usb_gadget.h"

int vsoc_usb_gadget_probe(struct platform_device *pdev);
int vsoc_usb_gadget_remove(struct platform_device *pdev);
int vsoc_usb_gadget_suspend(struct platform_device *pdev, pm_message_t state);
int vsoc_usb_gadget_resume(struct platform_device *pdev);

#endif /* __VSOC_USB_GADGET_DRIVER_H */
