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
	struct vsoc_usb_regs *usb_regs;
	dbg("%s\n", __func__);

	usb_regs = *((void **)dev_get_platdata(hcd->self.controller));
	if (!usb_regs) {
		dbg("%s couldn't get pointer to usb shared mem\n", __func__);
		return -ENODEV;
	}

	if (usb_regs->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}

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
	struct vsoc_hcd *vsoc_hcd;
	unsigned long flags;
	int rc;

	dbg("%s\n", __func__);
	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	rc = usb_hcd_link_urb_to_ep(hcd, urb);
	if (rc)
		goto done;
	if (usb_pipetype(urb->pipe) == PIPE_CONTROL)
		urb->error_count = 1;

done:
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	return rc;
}

static int vsoc_hcd_urb_dequeue(struct usb_hcd *hcd, struct urb *urb,
				int status)
{
	struct vsoc_hcd *vsoc_hcd;
	unsigned long flags;
	int rc;

	dbg("%s\n", __func__);
	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	rc = usb_hcd_check_unlink_urb(hcd, urb, status);
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	return rc;
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

static void vsoc_set_link_state_by_speed(struct vsoc_hcd *vsoc_hcd)
{
	if ((vsoc_hcd->port_status & USB_PORT_STAT_POWER) == 0) {
		vsoc_hcd->port_status = 0;
	} else {
		vsoc_hcd->port_status |= USB_PORT_STAT_CONNECTION;
		if ((vsoc_hcd->old_status & USB_PORT_STAT_CONNECTION) == 0)
			vsoc_hcd->port_status |= (USB_PORT_STAT_C_CONNECTION <<
						  16);
		if ((vsoc_hcd->port_status & USB_PORT_STAT_ENABLE) == 0)
			vsoc_hcd->port_status &= ~USB_PORT_STAT_SUSPEND;
		else if (((vsoc_hcd->port_status & USB_PORT_STAT_SUSPEND) == 0)
			 && (vsoc_hcd->rh_state != VSOC_HCD_RH_SUSPENDED))
			vsoc_hcd->active = 1;
	}
}

/*
 * TODO (romitd): Implement the actual shared memory based signalling.
 */
static void vsoc_set_link_state(struct vsoc_hcd *vsoc_hcd)
{
	dbg("%s\n", __func__);

	vsoc_hcd->active = 0;

	vsoc_set_link_state_by_speed(vsoc_hcd);

	if (((vsoc_hcd->port_status & USB_PORT_STAT_ENABLE) == 0) ||
	    vsoc_hcd->active)
		vsoc_hcd->resuming = 0;

	/* Currently !connected or in reset */
	if (((vsoc_hcd->port_status & USB_PORT_STAT_CONNECTION) == 0) ||
	    ((vsoc_hcd->port_status & USB_PORT_STAT_RESET) != 0)) {
		/*
		   unsigned disconnect = USB_PORT_STAT_CONNECTION &
		   vsoc_hcd->old_status & (~vsoc_hcd->port_status);
		   unsigned reset = USB_PORT_STAT_RESET &
		   (~vsoc_hcd->old_status) & vsoc_hcd->port_status;
		 */

		dbg("%s %s\n", __func__, "handle reset and disconnect to "
		    "gadget");
		/*
		 * TODO (romitd):
		 * Report reset and disconnect events to the driver.
		 */
	} else if (vsoc_hcd->active != vsoc_hcd->old_active) {
		dbg("%s %s\n", __func__, "handle suspend and resume");
		/*
		 * TODO (romitd):
		 * Handle suspend and resume.
		 */
	}

	vsoc_hcd->old_status = vsoc_hcd->port_status;
	vsoc_hcd->old_active = vsoc_hcd->active;
}

static int vsoc_hcd_hub_control(struct usb_hcd *hcd, u16 typeReq, u16 wValue,
				u16 wIndex, char *buf, u16 wLength)
{
	struct vsoc_hcd *vsoc_hcd;
	struct vsoc_usb_regs *usb_regs;
	int retval = 0;
	unsigned long flags;

	dbg("%s\n", __func__);

	if (!HCD_HW_ACCESSIBLE(hcd))
		return -ETIMEDOUT;

	usb_regs = *((void **)dev_get_platdata(hcd->self.controller));

	vsoc_hcd = hcd_to_vsoc_hcd(hcd);

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	switch (typeReq) {
	case ClearHubFeature:
		dbg("%s t:%s\n", __func__, "ClearHubFeature");
		break;
	case ClearPortFeature:
		dbg("%s t:%s v:0x%04x\n", __func__, "ClearPortFeature", wValue);
		switch (wValue) {
		case USB_PORT_FEAT_SUSPEND:
			dbg("%s %s:%s\n", __func__, "ClearPortFeature",
			    "USB_PORT_FEAT_SUSPEND");
			if (vsoc_hcd->port_status & USB_PORT_STAT_SUSPEND) {
				vsoc_hcd->resuming = 1;
			}
			break;
		case USB_PORT_FEAT_POWER:
			dbg("%s %s:%s\n", __func__, "ClearPortFeature",
			    "USB_PORT_FEAT_POWER");
			if (vsoc_hcd->port_status & USB_SS_PORT_STAT_POWER) {
				dbg("%s %s:%s %s\n", __func__,
				    "ClearPortFeature", "USB_PORT_FEAT_POWER",
				    "port_stats has USB_SS_PORT_STAT_POWER");
			}
			/* falls through */
		default:
			vsoc_hcd->port_status &= ~(1 << wValue);
			vsoc_set_link_state(vsoc_hcd);
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
		break;
	case GetHubStatus:
		dbg("%s t:%s\n", __func__, "GetHubStatus");
		memset(buf, 0, sizeof(__le32));
		break;
	case GetPortStatus:
		dbg("%s t:%s\n", __func__, "GetPortStatus");
		if (wIndex != 1)
			retval = -EPIPE;
		if (vsoc_hcd->resuming) {
			vsoc_hcd->port_status |= (USB_PORT_STAT_C_SUSPEND <<
						  16);
			vsoc_hcd->port_status &= ~USB_PORT_STAT_SUSPEND;
		}
		if ((vsoc_hcd->port_status & USB_PORT_STAT_RESET) != 0) {
			vsoc_hcd->port_status |= (USB_PORT_STAT_C_RESET << 16);
			vsoc_hcd->port_status &= ~USB_PORT_STAT_RESET;
			vsoc_hcd->port_status |= USB_PORT_STAT_ENABLE;
			/*
			 * TODO (romitd): remove the assumption that the
			 * gadget is high speed.
			 */
			vsoc_hcd->port_status |= USB_PORT_STAT_HIGH_SPEED;

		}
		vsoc_set_link_state(vsoc_hcd);
		((__le16 *) buf)[0] = cpu_to_le16(vsoc_hcd->port_status);
		((__le16 *) buf)[1] = cpu_to_le16(vsoc_hcd->port_status >> 16);
		break;
	case SetHubFeature:
		dbg("%s t:%s\n", __func__, "SetHubFeature");
		retval = -EPIPE;
		break;
	case SetPortFeature:
		dbg("%s t:%s v:0x%04x\n", __func__, "SetPortFeature", wValue);
		switch (wValue) {
		case USB_PORT_FEAT_LINK_STATE:
			dbg("%s %s:%s\n", __func__, "SetPortFeature",
			    "USB_PORT_FEAT_LINK_STATE");
			break;
		case USB_PORT_FEAT_U1_TIMEOUT:
		case USB_PORT_FEAT_U2_TIMEOUT:
			dbg("%s %s:%s\n", __func__, "SetPortFeature",
			    "USB_PORT_FEAT_U1/U2_STATE");
			break;
		case USB_PORT_FEAT_SUSPEND:
			dbg("%s %s:%s\n", __func__, "SetPortFeature",
			    "USB_PORT_FEAT_SUSPEND");
			if (vsoc_hcd->active) {
				vsoc_hcd->port_status |= USB_PORT_STAT_SUSPEND;
				vsoc_set_link_state(vsoc_hcd);
			}
			break;
		case USB_PORT_FEAT_POWER:
			dbg("%s %s:%s\n", __func__, "SetPortFeature",
			    "USB_PORT_FEAT_POWER");
			//vsoc_hcd->port_status |= USB_PORT_STAT_POWER;
			vsoc_set_link_state(vsoc_hcd);
			break;
		case USB_PORT_FEAT_BH_PORT_RESET:
			dbg("%s %s:%s\n", __func__, "SetPortFeature",
			    "USB_PORT_FEAT_BH_PORT_RESET");
			/* Falls through */
		case USB_PORT_FEAT_RESET:
			dbg("%s %s:%s\n", __func__, "SetPortFeature",
			    "USB_PORT_FEAT_RESET");
			vsoc_hcd->port_status &= ~(USB_PORT_STAT_ENABLE |
						   USB_PORT_STAT_LOW_SPEED |
						   USB_PORT_STAT_HIGH_SPEED);
			/*TODO (romitd): Update gadget controller's devstatus */

			/* Falls through */
		default:
			if ((vsoc_hcd->port_status & USB_PORT_STAT_POWER) != 0) {
				vsoc_hcd->port_status |= (1 << wValue);
				vsoc_set_link_state(vsoc_hcd);
			}
		}
		break;
	case GetPortErrorCount:
		dbg("%s t:%s\n", __func__, "GetPortErrorCount");
		memset(buf, 0, sizeof(__le32));
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
	struct vsoc_usb_regs *usb_regs;
	int retval;

	dbg("%s\n", __func__);
	dev_info(&pdev->dev, "%s, driver " DRIVER_VERSION "\n", driver_desc);

	usb_regs = *((void **)dev_get_platdata(&pdev->dev));
	if (!usb_regs) {
		dbg("%s couldn't get pointer to usb shared mem\n", __func__);
		return -ENODEV;
	}

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
