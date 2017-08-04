/*
 * Android VSoC USB Driver.
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

#include <linux/init.h>
#include <linux/module.h>

static int __init vsoc_usb_hcd_init(void)
{
	printk(KERN_INFO "VSoC USB Host Controller Driver loaded.\n");
	return 0;
}

static void __exit vsoc_usb_hcd_exit(void)
{
	printk(KERN_INFO "VSoC USB Host Controller Driver unloaded.\n");
	return;
}

module_init(vsoc_usb_hcd_init);
module_exit(vsoc_usb_hcd_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("VSoC USB Host Controller Driver");
MODULE_AUTHOR("Google Inc.");
