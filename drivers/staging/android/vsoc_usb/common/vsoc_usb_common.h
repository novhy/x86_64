/*
 * Part of Android VSoC USB Driver.
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

#ifndef __VSOC_USB_COMMON_H
#define __VSOC_USB_COMMON_H

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/usb.h>
#include <linux/platform_device.h>

#include <asm/byteorder.h>
#include <asm/unaligned.h>

#define VSOC_USB_MAX_NUM_CONTROLLER 1

/* Magic from ascii value of 'VSOC' */
#define VSOC_USB_SHM_MAGIC  0x56534f43

#if defined(DEBUG)
#define dbg(format, arg...) \
	printk(KERN_DEBUG format, ##arg)
#else
#define dbg(format, arg...) \
({                          \
     if(0);                 \
})
#endif

#endif /* __VSOC_USB_COMMON_H */
