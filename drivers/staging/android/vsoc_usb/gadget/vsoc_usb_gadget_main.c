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

#include "vsoc_usb_gadget.h"
#include "vsoc_usb_gadget_driver.h"

const char gadget_name[] = "vsoc_usb_udc";
const char ep0name[] = "ep0";
struct platform_device *vsoc_udc_pdev[VSOC_USB_MAX_NUM_CONTROLLER];
const struct {
	const char *name;
	const struct usb_ep_caps caps;
} ep_info[] = {
#define EP_INFO(_name, _caps) \
	{ \
		.name = _name, \
		.caps = _caps, \
	}

	EP_INFO(ep0name,
		USB_EP_CAPS(USB_EP_CAPS_TYPE_CONTROL, USB_EP_CAPS_DIR_ALL)),
	    EP_INFO("ep1in-bulk",
		    USB_EP_CAPS(USB_EP_CAPS_TYPE_BULK, USB_EP_CAPS_DIR_IN)),
	    EP_INFO("ep1out-bulk",
		    USB_EP_CAPS(USB_EP_CAPS_TYPE_BULK, USB_EP_CAPS_DIR_OUT)),
#undef EP_INFO
};

#define ENDPOINT_COUNT ARRAY_SIZE(ep_info)

static struct platform_driver vsoc_usb_gadget_driver = {
	.probe = vsoc_usb_gadget_probe,
	.remove = vsoc_usb_gadget_remove,
	.suspend = vsoc_usb_gadget_suspend,
	.resume = vsoc_usb_gadget_resume,
	.driver = {
		   .name = (char *)gadget_name,
		   },
};

const char *vsoc_usb_gadget_get_ep_name(int i)
{
	return ((i < VSOC_NUM_ENDPOINTS) ? ep_info[i].name : NULL);
}

const struct usb_ep_caps *vsoc_usb_gadget_get_ep_caps(int i)
{
	return ((i < VSOC_NUM_ENDPOINTS) ? &ep_info[i].caps : NULL);
}

static int __init vsoc_usb_gadget_init(void)
{
	int rc = -ENOMEM;
	int i;
	struct vsoc_usb_gadget *gadget_controller[VSOC_USB_MAX_NUM_CONTROLLER];

	BUILD_BUG_ON((ENDPOINT_COUNT) != (VSOC_NUM_ENDPOINTS));
	BUILD_BUG_ON(VSOC_ENDPOINT_BUFFER_SIZE < VSOC_MIN_BUFFER_SIZE);

	dbg("%s\n", __func__);
	if (usb_disabled()) return -ENODEV;

	memset(gadget_controller, 0, sizeof(gadget_controller));

	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		vsoc_udc_pdev[i] = platform_device_alloc(gadget_name, i);
		if (!vsoc_udc_pdev[i]) {
			rc = -ENOMEM;
			goto err_alloc_udc;
		}
	}

	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		struct vsoc_usb_shm *shm;
		gadget_controller[i] = kzalloc(sizeof(struct vsoc_usb_gadget),
					       GFP_KERNEL);
		if (!gadget_controller[i]) {
			rc = -ENOMEM;
			goto err_alloc_pdata;
		}

		gadget_controller[i]->gep =
		    kzalloc(sizeof(struct vsoc_usb_gadget_ep) *
			    VSOC_NUM_ENDPOINTS, GFP_KERNEL);
		if (!gadget_controller[i]->gep) {
			goto err_alloc_pdata;
		}

		shm = vsoc_usb_shm_get(i);
		gadget_controller[i]->shm = shm;
	}

	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		rc = platform_device_add_data(vsoc_udc_pdev[i],
						  &gadget_controller[i],
						  sizeof(void *));
		if (rc)
			goto err_add_pdata;
	}

	rc = platform_driver_register(&vsoc_usb_gadget_driver);
	if (rc < 0)
		goto err_driver_register;

	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		rc = platform_device_add(vsoc_udc_pdev[i]);
		if (rc)
			goto err_device_add;
	}
	printk(KERN_INFO "VSoC USB Gadget Controller Driver loaded.\n");
	return 0;

err_device_add:
	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		platform_device_del(vsoc_udc_pdev[i]);
	}

	platform_driver_unregister(&vsoc_usb_gadget_driver);

err_driver_register:
err_add_pdata:
err_alloc_pdata:
	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		kfree(gadget_controller[i]->gep);
		kfree(gadget_controller[i]);
	}

err_alloc_udc:
	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++)
		/* Checks for NULL internally. */
		platform_device_put(vsoc_udc_pdev[i]);

	return rc;
}

static void __exit vsoc_usb_gadget_exit(void)
{
	int i;
	dbg("%s\n", __func__);
	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		struct vsoc_usb_gadget *gadget_controller;
		gadget_controller =
		    *((void **)dev_get_platdata(&vsoc_udc_pdev[i]->dev));
		platform_device_unregister(vsoc_udc_pdev[i]);
		kfree(gadget_controller->gep);
		kfree(gadget_controller);
	}

	platform_driver_unregister(&vsoc_usb_gadget_driver);
	printk(KERN_INFO "VSoC USB Gadget Controller Driver unloaded.\n");
	return;
}

module_init(vsoc_usb_gadget_init);
module_exit(vsoc_usb_gadget_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("VSoC USB Gadget Controller Driver");
MODULE_AUTHOR("Google Inc.");
