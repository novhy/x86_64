/*
 * Part of Android VSoC USB Host Controller Driver.
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

#include "vsoc_usb_hcd.h"
#include "vsoc_usb_hcd_driver.h"

const char hcd_name[] = "vsoc_usb_hcd";

static struct platform_device *vsoc_hcd_pdev[VSOC_USB_MAX_NUM_CONTROLLER];

static struct platform_driver vsoc_usb_hcd_driver = {
	.probe = vsoc_usb_hcd_probe,
	.remove = vsoc_usb_hcd_remove,
	.suspend = vsoc_usb_hcd_suspend,
	.resume = vsoc_usb_hcd_resume,
	.driver = {
		   .name = (char *)hcd_name,
		   },
};

static int __init vsoc_usb_hcd_init(void)
{
	int rc = -ENOMEM;
	int i;

	if (usb_disabled())
		return -ENODEV;

	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		vsoc_hcd_pdev[i] = platform_device_alloc(hcd_name, i);
		if (!vsoc_hcd_pdev[i]) {
			rc = -ENOMEM;
			goto err_alloc_hcd;
		}
	}

	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		struct vsoc_usb_shm *shm = vsoc_usb_shm_get(i);
		rc = platform_device_add_data(vsoc_hcd_pdev[i], &shm,
					      sizeof(void *));
		if (rc)
			goto err_alloc_pdata;
	}
	rc = platform_driver_register(&vsoc_usb_hcd_driver);
	if (rc < 0)
		goto err_alloc_hcd;

	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		rc = platform_device_add(vsoc_hcd_pdev[i]);
		if (rc < 0) {
			i--;
			while (i >= 0)
				platform_device_del(vsoc_hcd_pdev[i--]);
			goto err_device_add;
		}
	}
	printk(KERN_INFO "VSoC USB Host Controller Driver loaded.\n");
	return 0;

err_device_add:
	platform_driver_unregister(&vsoc_usb_hcd_driver);
err_alloc_pdata:
err_alloc_hcd:
	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		/* Checks for NULL internally. */
		platform_device_put(vsoc_hcd_pdev[i]);
	}

	return rc;
}

static void __exit vsoc_usb_hcd_exit(void)
{
	int i;

	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		platform_device_unregister(vsoc_hcd_pdev[i]);
	}

	platform_driver_unregister(&vsoc_usb_hcd_driver);
	printk(KERN_INFO "VSoC USB Host Controller Driver unloaded.\n");
	return;
}

module_init(vsoc_usb_hcd_init);
module_exit(vsoc_usb_hcd_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("VSoC USB Host Controller Driver");
MODULE_AUTHOR("Google Inc.");
