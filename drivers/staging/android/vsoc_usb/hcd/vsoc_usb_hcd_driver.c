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
#define DEBUG 1
#include "vsoc_usb_hcd_driver.h"

#define DRIVER_VERSION "Same domain Shared Memory"

static const char driver_desc[] = "VSoC USB Host Emulator";

static struct vsoc_hcd *hcd_to_vsoc_hcd(struct usb_hcd *hcd)
{
	return (struct vsoc_hcd *)(hcd->hcd_priv);
}

static int vsoc_hcd_setup(struct usb_hcd *hcd)
{
	dbg("%s\n", __func__);

	hcd->self.sg_tablesize = ~0;

	if (usb_hcd_is_primary_hcd(hcd)) {
		hcd->speed = HCD_USB2;
		hcd->self.root_hub->speed = USB_SPEED_HIGH;
	} else {
		/*
		 * We are not ready for Super Speed yet.
		 */
		return -ENODEV;
	}
	return 0;
}

static int vsoc_hcd_start(struct usb_hcd *hcd)
{
	struct vsoc_hcd *vsoc_hcd;

	dbg("%s\n", __func__);

	vsoc_hcd = hcd_to_vsoc_hcd(hcd);

	/*
	 * We are not ready for Super Speed yet.
	 */
	if (!usb_hcd_is_primary_hcd(hcd))
		return -ENODEV;

	spin_lock_init(&vsoc_hcd->vsoc_hcd_lock);
	INIT_LIST_HEAD(&vsoc_hcd->urbp_list);

	hcd->power_budget = POWER_BUDGET;
	hcd->state = HC_STATE_RUNNING;
	hcd->uses_new_polling = 1;

	return 0;
}

static void vsoc_hcd_stop(struct usb_hcd *hcd)
{
	dbg("%s\n", __func__);
}

static int vsoc_hcd_urb_enqueue(struct usb_hcd *hcd, struct urb *urb,
				gfp_t mem_flags)
{
	dbg("%s\n", __func__);
	return 0;
}

static int vsoc_hcd_urb_dequeue(struct usb_hcd *hcd, struct urb *urb,
				int status)
{
	dbg("%s\n", __func__);
	return 0;
}

static int vsoc_hcd_get_frame(struct usb_hcd *hcd)
{
	dbg("%s\n", __func__);
	return 0;
}

static int vsoc_hcd_hub_status(struct usb_hcd *hcd, char *buf)
{
	dbg("%s\n", __func__);
	return 0;
}

static inline void vsoc_hub_descriptor(struct usb_hub_descriptor *desc)
{
	memset(desc, 0, sizeof(*desc));
	desc->bDescriptorType = USB_DT_HUB;
	desc->bDescLength = 9;
	desc->wHubCharacteristics = cpu_to_le16(HUB_CHAR_INDV_PORT_LPSM |
						HUB_CHAR_COMMON_OCPM);
	desc->bNbrPorts = 1;
	desc->u.hs.DeviceRemovable[0] = 0xff;
	desc->u.hs.DeviceRemovable[1] = 0xff;
}

static int vsoc_hcd_hub_control(struct usb_hcd *hcd, u16 typeReq, u16 wValue,
				u16 wIndex, char *buf, u16 wLength)
{
	struct vsoc_hcd *vsoc_hcd;
	int retval = 0;
	unsigned long flags;

	dbg("%s\n", __func__);

	if (!HCD_HW_ACCESSIBLE(hcd))
		return -ETIMEDOUT;
	vsoc_hcd = hcd_to_vsoc_hcd(hcd);

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	switch (typeReq) {
	case ClearHubFeature:
		dbg("%s t:%s\n", __func__, "ClearHubFeature");
		break;
	case ClearPortFeature:
		dbg("%s t:%s v:%04x\n", __func__, "ClearPortFeature", wValue);
		switch (wValue) {
		}
		break;
	case GetHubDescriptor:
		dbg("%s t:%s\n", __func__, "GetHubDescriptor");
		vsoc_hub_descriptor((struct usb_hub_descriptor *)buf);
		break;
	case DeviceRequest | USB_REQ_GET_DESCRIPTOR:
		dbg("%s t:%s\n", __func__,
		    "DeviceRequest | USB_REQ_GET_DESCRIPTOR");
		if (hcd->speed != HCD_USB3)
			goto error;
		if ((wValue >> 8) != USB_DT_BOS)
			goto error;
		break;
	case GetHubStatus:
		dbg("%s t:%s\n", __func__, "GetHubStatus");
		break;
	case GetPortStatus:
		dbg("%s t:%s\n", __func__, "GetPortStatus");
		break;
	case SetHubFeature:
		dbg("%s t:%s\n", __func__, "SetHubFeature");
		break;
	case SetPortFeature:
		dbg("%s t:%s\n", __func__, "SetPortFeature");
		break;
	case GetPortErrorCount:
		dbg("%s t:%s\n", __func__, "GetPortErrorCount");
		break;
	case SetHubDepth:
		dbg("%s t:%s\n", __func__, "SetHubDepth");
		break;
	default:
		dbg("hub control req%04x v%04x i%04x l%d\n",
		    typeReq, wValue, wIndex, wLength);
error:
		retval = -EPIPE;
		break;
	}
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);

	if ((vsoc_hcd->port_status & PORT_C_MASK) != 0)
		usb_hcd_poll_rh_status(hcd);

	return retval;
}

static int vsoc_hcd_bus_suspend(struct usb_hcd *hcd)
{
	dbg("%s\n", __func__);
	return 0;
}

static int vsoc_hcd_bus_resume(struct usb_hcd *hcd)
{
	dbg("%s\n", __func__);
	return 0;
}

static int vsoc_hcd_alloc_streams(struct usb_hcd *hcd, struct usb_device *udev,
				  struct usb_host_endpoint **eps,
				  unsigned int num_eps,
				  unsigned int num_streams, gfp_t mem_flags)
{
	dbg("%s\n", __func__);
	return 0;
}

static int vsoc_hcd_free_streams(struct usb_hcd *hcd, struct usb_device *udev,
				 struct usb_host_endpoint **eps,
				 unsigned int num_eps, gfp_t mem_flags)
{
	dbg("%s\n", __func__);
	return 0;
}

static struct hc_driver vsoc_hc_driver = {
	.description = (char *)hcd_name,
	.product_desc = "VSoC USB Host Controller",
	.hcd_priv_size = sizeof(struct vsoc_hcd),
	.flags = HCD_USB2,

	.reset = vsoc_hcd_setup,
	.start = vsoc_hcd_start,
	.stop = vsoc_hcd_stop,
	.urb_enqueue = vsoc_hcd_urb_enqueue,
	.urb_dequeue = vsoc_hcd_urb_dequeue,
	.get_frame_number = vsoc_hcd_get_frame,
	.hub_status_data = vsoc_hcd_hub_status,
	.hub_control = vsoc_hcd_hub_control,
	.bus_suspend = vsoc_hcd_bus_suspend,
	.bus_resume = vsoc_hcd_bus_resume,
	.alloc_streams = vsoc_hcd_alloc_streams,
	.free_streams = vsoc_hcd_free_streams,
};

int vsoc_usb_hcd_probe(struct platform_device *pdev)
{
	struct usb_hcd *hs_hcd;
	struct vsoc_hcd *vsoc_hcd;
	int retval;

	dbg("%s\n", __func__);
	dev_info(&pdev->dev, "%s, driver " DRIVER_VERSION "\n", driver_desc);

	hs_hcd = usb_create_hcd(&vsoc_hc_driver, &pdev->dev,
				dev_name(&pdev->dev));
	if (!hs_hcd)
		return -ENOMEM;

	vsoc_hcd = hcd_to_vsoc_hcd(hs_hcd);

	hs_hcd->has_tt = 1;

	retval = usb_add_hcd(hs_hcd, 0, 0);
	if (retval)
		goto put_usb2_hcd;
	return 0;

put_usb2_hcd:
	usb_put_hcd(hs_hcd);

	return retval;
}

int vsoc_usb_hcd_remove(struct platform_device *pdev)
{
	struct usb_hcd *hcd;

	dbg("%s\n", __func__);
	hcd = platform_get_drvdata(pdev);
	usb_remove_hcd(hcd);
	usb_put_hcd(hcd);
	return 0;
}

int vsoc_usb_hcd_suspend(struct platform_device *pdev, pm_message_t state)
{
	dbg("%s\n", __func__);
	return 0;
}

int vsoc_usb_hcd_resume(struct platform_device *pdev)
{
	dbg("%s\n", __func__);
	return 0;
}
