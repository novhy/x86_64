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

static int kick_host_internal(unsigned long data);

struct vsoc_usb_g2h_ops g2h_ops = {
	.kick = kick_host_internal,
	.kick_and_wait = NULL,
};

static const char driver_desc[] = "VSoC USB Host Emulator";

static struct vsoc_hcd *hcd_to_vsoc_hcd(struct usb_hcd *hcd)
{
	return (struct vsoc_hcd *)(hcd->hcd_priv);
}

/*
 * This runs with hcd_ctrl_lock held.
 */
static unsigned long handle_hcd_intr(struct vsoc_hcd *vsoc_hcd, unsigned long
				     *intr)
{
	dbg("%s\n", __func__);
	if (test_and_clear_bit(RESET_COMPLETE, intr)) {
		set_bit(RESET_COMPLETE, &vsoc_hcd->action);
	}

	return vsoc_hcd->action;
}

static void hcd_tasklet(unsigned long data)
{
	struct vsoc_hcd *vsoc_hcd = (struct vsoc_hcd *)data;
	struct vsoc_usb_controller_regs *ctrl_regs;
	unsigned long flags, action, *hcd_intr;

	dbg("%s\n",__func__);
	ctrl_regs = &vsoc_hcd->regs->ctrl_regs;
	spin_lock_irqsave(&ctrl_regs->hcd_ctrl_lock, flags);
	hcd_intr = &ctrl_regs->hcd_reg.intr;
	if (!*hcd_intr) {
		spin_unlock_irqrestore(&ctrl_regs->hcd_ctrl_lock, flags);
		return;
	}
	action = handle_hcd_intr(vsoc_hcd, hcd_intr);
	if (action)
		wake_up_interruptible(&vsoc_hcd->rxq);
	spin_unlock_irqrestore(&ctrl_regs->hcd_ctrl_lock, flags);
}

static int kick_host_internal(unsigned long data)
{
	struct vsoc_hcd *vsoc_hcd = (struct vsoc_hcd *)data;
	dbg("%s\n", __func__);
#ifdef DEBUG
	if (vsoc_hcd->regs->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}
#endif
	tasklet_schedule(&vsoc_hcd->hcd_tasklet);
	return 0;
}

/*
 * TODO (romitd): Placeholder for now.
 */
static int vsoc_hcd_tx(void *data)
{
	struct vsoc_hcd *vsoc_hcd = (struct vsoc_hcd *)data;
	struct vsoc_usb_regs *usb_regs;
	struct vsoc_usb_controller_regs *ctrl_regs;

	dbg("%s\n", __func__);
#ifdef DEBUG
	if (vsoc_hcd->regs->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}
#endif
	usb_regs = vsoc_hcd->regs;
	ctrl_regs = &usb_regs->ctrl_regs;
	set_freezable();

	for(;;) {
		set_current_state(TASK_RUNNING);
		try_to_freeze();
		if (kthread_should_stop())
			break;
		set_current_state(TASK_INTERRUPTIBLE);
		dbg("%s before sleep\n", __func__);
		/*
		 * TODO (romitd):
		 * The timeout is temporary. With Tx logic coming in, this
		 * should go away.
		 */
		schedule_timeout(MAX_SCHEDULE_TIMEOUT);
		dbg("%s after wakeup\n", __func__);
	}

	return 0;
}

static int vsoc_hcd_rx(void *data)
{
	unsigned long action, flags;
	struct vsoc_hcd *vsoc_hcd = (struct vsoc_hcd *)data;
	struct vsoc_usb_regs *usb_regs;
	struct vsoc_usb_controller_regs *ctrl_regs;

	dbg("%s\n", __func__);
#ifdef DEBUG
	if (vsoc_hcd->regs->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}
#endif
	usb_regs = vsoc_hcd->regs;
	ctrl_regs = &usb_regs->ctrl_regs;
	set_freezable();

	for(;;) {
		set_current_state(TASK_RUNNING);
		try_to_freeze();
		if (kthread_should_stop())
			break;
		set_current_state(TASK_INTERRUPTIBLE);
		dbg("%s before sleep\n", __func__);
		wait_event_interruptible(vsoc_hcd->rxq,
					(vsoc_hcd->action != 0) ||
					kthread_should_stop());
		dbg("%s after wakeup\n", __func__);
		if (kthread_should_stop())
			break;

		spin_lock_irqsave(&ctrl_regs->hcd_ctrl_lock, flags);
		if (test_and_clear_bit(RESET_COMPLETE, &vsoc_hcd->action))
			set_bit(RESET_COMPLETE, &action);
		if (vsoc_hcd->action)
			printk(KERN_ERR "Unhandled action in %s\n", __func__);
		spin_unlock_irqrestore(&ctrl_regs->hcd_ctrl_lock, flags);
		if (test_and_clear_bit(RESET_COMPLETE, &action)) {
			del_timer(&vsoc_hcd->port_connection_timer);
			dbg("%s RESET_COMPLETE\n", __func__);
		}
	}

	return 0;
}

static int kick_gadget(struct vsoc_hcd *vsoc_hcd, unsigned long bit)
{
	struct vsoc_usb_controller_regs *ctrl_regs = &vsoc_hcd->regs->ctrl_regs;
	unsigned long flags;
	int rc = 0;

	dbg("%s\n", __func__);

	/*
	 * TODO(romitd): set_bit is atomic, so the lock may be removed.
	 */
	spin_lock_irqsave(&ctrl_regs->gadget_ctrl_lock, flags);
	set_bit(bit, &ctrl_regs->gadget_reg.intr);
	spin_unlock_irqrestore(&ctrl_regs->gadget_ctrl_lock, flags);
	rc = vsoc_usb_h2g_kick();
	if (rc)
		dbg("In %s, vsoc_usb_h2g_kick() failed\n", __func__);

	return rc;
}

static void device_connection_timeout(unsigned long arg)
{
	struct vsoc_hcd *vsoc_hcd;
	unsigned long flags;

	dbg("%s\n", __func__);
	vsoc_hcd = hcd_to_vsoc_hcd((struct usb_hcd *) arg);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	printk(KERN_INFO "Did not detect Gadget pullup. Powering down!\n");
	vsoc_hcd->port_status = 0;
	vsoc_hcd->port_status |= (USB_PORT_STAT_C_CONNECTION << 16);
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	if ((vsoc_hcd->port_status & PORT_C_MASK) != 0)
		usb_hcd_poll_rh_status((struct usb_hcd *) arg);
}

static int vsoc_hcd_setup(struct usb_hcd *hcd)
{
	struct vsoc_usb_regs *usb_regs;
	struct vsoc_hcd *vsoc_hcd;
	struct vsoc_usb_controller_regs *ctrl_regs;

	dbg("%s\n", __func__);

	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_init(&vsoc_hcd->vsoc_hcd_lock);
	INIT_LIST_HEAD(&vsoc_hcd->urbp_list);
	init_timer(&vsoc_hcd->port_connection_timer);
	vsoc_hcd->port_connection_timer.function = device_connection_timeout;
	vsoc_hcd->port_connection_timer.data = (unsigned long)hcd;
	hcd->power_budget = POWER_BUDGET;
	hcd->uses_new_polling = 1;

	init_waitqueue_head(&vsoc_hcd->txq);
	init_waitqueue_head(&vsoc_hcd->rxq);

	tasklet_init(&vsoc_hcd->hcd_tasklet, hcd_tasklet,
		     (unsigned long)vsoc_hcd);

	usb_regs = *((void **)dev_get_platdata(hcd->self.controller));
	if (!usb_regs) {
		dbg("%s couldn't get pointer to usb shared mem\n", __func__);
		return -ENODEV;
	}

	if (usb_regs->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
		vsoc_hcd->regs = usb_regs;
	}

	ctrl_regs = &vsoc_hcd->regs->ctrl_regs;
	spin_lock_init(&ctrl_regs->hcd_ctrl_lock);
	vsoc_hcd->action = 0;

	hcd->self.sg_tablesize = 0;

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
	unsigned long flags;

	dbg("%s\n", __func__);

	vsoc_hcd = hcd_to_vsoc_hcd(hcd);

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	/*
	 * We are not ready for Super Speed yet.
	 */
	if (!usb_hcd_is_primary_hcd(hcd))
		return -ENODEV;

	vsoc_hcd->tx_thread = kthread_run(vsoc_hcd_tx, (void *)vsoc_hcd,
					  "vsoc_h_tx/%d",
					  hcd_to_bus(hcd)->busnum);
	if (IS_ERR(vsoc_hcd->tx_thread))
	    return -ENODEV;

	vsoc_hcd->rx_thread = kthread_run(vsoc_hcd_rx, (void *)vsoc_hcd,
					  "vsoc_h_rx/%d",
					  hcd_to_bus(hcd)->busnum);
	if (IS_ERR(vsoc_hcd->rx_thread)) {
	    kthread_stop(vsoc_hcd->tx_thread);
	    vsoc_hcd->tx_thread = NULL;
	    return -ENODEV;
	}

	hcd->state = HC_STATE_RUNNING;

	/*
	 we are polling the port.
	set_bit(HCD_FLAG_POLL_RH, &hcd->flags);
	*/
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);

	return 0;
}

static void vsoc_hcd_stop(struct usb_hcd *hcd)
{
	struct vsoc_hcd *vsoc_hcd;
	unsigned long flags;

	dbg("%s\n", __func__);

	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	hcd->state = HC_STATE_HALT;
	clear_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags);
	del_timer(&vsoc_hcd->port_connection_timer);

	tasklet_kill(&vsoc_hcd->hcd_tasklet);
	if (vsoc_hcd->tx_thread) {
		kthread_stop(vsoc_hcd->tx_thread);
		vsoc_hcd->tx_thread = NULL;
	}
	if (vsoc_hcd->rx_thread) {
		kthread_stop(vsoc_hcd->rx_thread);
		vsoc_hcd->rx_thread = NULL;
	}

	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
}

static int vsoc_hcd_urb_enqueue(struct usb_hcd *hcd, struct urb *urb,
				gfp_t mem_flags)
{
	struct vsoc_hcd *vsoc_hcd;
	unsigned long flags;
	struct urbp *urbp;
	int rc;

	dbg("%s\n", __func__);
	urbp = kmalloc(sizeof(*urbp), mem_flags);
	if (!urbp)
		return -ENOMEM;
	urbp->urb = urb;

	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	rc = usb_hcd_link_urb_to_ep(hcd, urb);
	if (rc) {
		kfree(urbp);
		goto done;
	}
	if (!vsoc_hcd->udev) {
		vsoc_hcd->udev = urb->dev;
		usb_get_dev(vsoc_hcd->udev);
	} else if (unlikely(vsoc_hcd->udev != urb->dev)) {
		printk(KERN_ERR "usb device address has changed!\n");
	}
	list_add_tail(&urbp->urbp_list, &vsoc_hcd->urbp_list);
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
	struct urbp *urbp, *tmp;
	unsigned long flags;
	int rc;

	dbg("%s\n", __func__);
	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	list_for_each_entry_safe(urbp, tmp, &vsoc_hcd->urbp_list, urbp_list) {
		if (urb == urbp->urb) {
			rc = usb_hcd_check_unlink_urb(hcd, urb, status);
			if (!rc && vsoc_hcd->rh_state != VSOC_HCD_RH_RUNNING &&
				!list_empty(&vsoc_hcd->urbp_list)) {
				list_del(&urbp->urbp_list);
				kfree(urbp);
				usb_hcd_unlink_urb_from_ep(hcd, urb);
				usb_hcd_giveback_urb(hcd, urb, status);
				goto done;
			}
		}
	}
done:
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	return rc;
}

static int vsoc_hcd_get_frame(struct usb_hcd *hcd)
{
	dbg("%s\n", __func__);
	return 0;
}

static inline void vsoc_hub_descriptor(struct usb_hub_descriptor *desc)
{
	dbg("%s\n", __func__);
	memset(desc, 0, sizeof(*desc));
	desc->bDescriptorType = USB_DT_HUB;
	desc->bDescLength = 9;
	desc->wHubCharacteristics = cpu_to_le16(HUB_CHAR_INDV_PORT_LPSM |
						HUB_CHAR_COMMON_OCPM);
	/*
	 * For now support only a single device on the port
	 */
	desc->bNbrPorts = 1;

	/* Fixed devices */
	desc->u.hs.DeviceRemovable[0] = 0xff;
	desc->u.hs.DeviceRemovable[1] = 0xff;
}

static void _vsoc_set_link_state(struct vsoc_hcd *vsoc_hcd)
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

static void vsoc_set_link_state(struct vsoc_hcd *vsoc_hcd)
{
	dbg("%s\n", __func__);

	vsoc_hcd->active = 0;
	dbg("vsoc_data:\n");
	dbg("vsoc_hcd_rh_state: %d\n", vsoc_hcd->rh_state);
	dbg("vsoc_hcd_port_status: 0x%08x\n", vsoc_hcd->port_status);
	dbg("vsoc_hcd_old_status: 0x%08x\n", vsoc_hcd->old_status);
	dbg("vsoc_hcd_timeout: 0x%lx\n", vsoc_hcd->timeout);
	dbg("vsoc_hcd_udev: %p\n", vsoc_hcd->udev);
	dbg("vsoc_hcd_active: %d\n", vsoc_hcd->active);
	dbg("vsoc_hcd_old_active: %d\n", vsoc_hcd->old_active);
	dbg("vsoc_hcd_resuming: %d\n", vsoc_hcd->resuming);

	_vsoc_set_link_state(vsoc_hcd);

	if (((vsoc_hcd->port_status & USB_PORT_STAT_ENABLE) == 0) ||
	    vsoc_hcd->active)
		vsoc_hcd->resuming = 0;

	/* Currently !connected or in reset */
	if (((vsoc_hcd->port_status & USB_PORT_STAT_CONNECTION) == 0) ||
	    ((vsoc_hcd->port_status & USB_PORT_STAT_RESET) != 0)) {
		unsigned disconnect = USB_PORT_STAT_CONNECTION &
		vsoc_hcd->old_status & (~vsoc_hcd->port_status);
		unsigned reset = USB_PORT_STAT_RESET &
		(~vsoc_hcd->old_status) & vsoc_hcd->port_status;

		if (reset) {
			dbg("%s setting reset bit in port_status\n", __func__);
			vsoc_hcd->port_status |= USB_PORT_STAT_POWER;
			/* TODO(romitd) Kick gadget */
			if(!kick_gadget(vsoc_hcd, H2G_RESET)) {
				/*
				 * We will give around 2s for gadget side
				 * reset.
				 */
				vsoc_hcd->port_connection_timer.expires =
					jiffies +
					msecs_to_jiffies(VSOC_GADGET_RESET_MS);
				add_timer(&vsoc_hcd->port_connection_timer);
			} else {
				vsoc_hcd->port_status = 0;
				vsoc_hcd->port_status |=
					(USB_PORT_STAT_C_CONNECTION << 16);
			}
		} else if (disconnect)
			dbg("%s disconnect in port status\n", __func__);
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

static int vsoc_hcd_hub_status(struct usb_hcd *hcd, char *buf)
{
	struct vsoc_hcd *vsoc_hcd;
	unsigned long flags;
	int retval = 0;

	dbg("%s\n", __func__);
	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);

	if (!HCD_HW_ACCESSIBLE(hcd))
		goto done;

	if (vsoc_hcd->resuming && time_after_eq(jiffies,
						vsoc_hcd->timeout)) {
		vsoc_hcd->port_status |= (USB_PORT_STAT_C_SUSPEND << 16);
		vsoc_hcd->port_status &= ~USB_PORT_STAT_SUSPEND;
		vsoc_set_link_state(vsoc_hcd);
	}

	if ((vsoc_hcd->port_status & PORT_C_MASK) != 0) {
		*buf = (1 << 1);
		dbg("%s port status 0x%08x has changes\n",
		    __func__, vsoc_hcd->port_status);
		retval = 1;
		if (vsoc_hcd->rh_state == VSOC_HCD_RH_SUSPENDED)
			usb_hcd_resume_root_hub(hcd);
	}

done:
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	return retval;
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
				vsoc_hcd->timeout = jiffies +
				msecs_to_jiffies(VSOC_HCD_PORT_SUSPEND_MS);
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
		if (vsoc_hcd->resuming &&
		    time_after_eq(jiffies, vsoc_hcd->timeout)) {
			vsoc_hcd->port_status |= (USB_PORT_STAT_C_SUSPEND <<
						  16);
			vsoc_hcd->port_status &= ~USB_PORT_STAT_SUSPEND;
		}
		if ((vsoc_hcd->port_status & USB_PORT_STAT_RESET) != 0 &&
			time_after_eq(jiffies, vsoc_hcd->timeout)) {
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
			vsoc_hcd->port_status |= USB_PORT_STAT_POWER;
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

			/*
			 * We expect to complete the hcd side of reset in 50ms.
			 */
			vsoc_hcd->timeout = jiffies +
				msecs_to_jiffies(VSOC_HCD_RESET_MS);
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
	struct vsoc_hcd *vsoc_hcd;

	dbg("%s\n", __func__);
	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_irq(&vsoc_hcd->vsoc_hcd_lock);
	vsoc_hcd->rh_state = VSOC_HCD_RH_SUSPENDED;
	vsoc_set_link_state(vsoc_hcd);
	hcd->state = HC_STATE_SUSPENDED;
	spin_unlock_irq(&vsoc_hcd->vsoc_hcd_lock);
	return 0;
}

static int vsoc_hcd_bus_resume(struct usb_hcd *hcd)
{
	struct vsoc_hcd *vsoc_hcd;
	int rc = 0;

	dbg("%s\n", __func__);

	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_irq(&vsoc_hcd->vsoc_hcd_lock);
	if (!HCD_HW_ACCESSIBLE(hcd)) {
		rc = -ESHUTDOWN;
	} else {
		vsoc_hcd->rh_state = VSOC_HCD_RH_RUNNING;
		vsoc_set_link_state(vsoc_hcd);
		hcd->state = HC_STATE_RUNNING;
	}
	spin_unlock_irq(&vsoc_hcd->vsoc_hcd_lock);

	return rc;
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

static struct hc_driver vsoc_hcd_driver = {
	.description = (char *)hcd_name,
	.product_desc = "VSoC USB Host Controller",
	.hcd_priv_size = sizeof(struct vsoc_hcd),
	.flags = HCD_USB2, /* SS will come in later */

	.reset = vsoc_hcd_setup, /* the init routine */
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
	int rc;

	dbg("%s\n", __func__);
	dev_info(&pdev->dev, "%s, driver " DRIVER_VERSION "\n", driver_desc);

	usb_regs = *((void **)dev_get_platdata(&pdev->dev));
	if (!usb_regs) {
		dbg("%s couldn't get pointer to usb shared mem\n", __func__);
		return -ENODEV;
	}

	/*
	 * This HCD essentially would copy bytes from one region of memory to a
	 * different region of memory. We do not need DMA.
	 */

	pdev->dev.dma_mask = 0;

	hs_hcd = usb_create_hcd(&vsoc_hcd_driver, &pdev->dev,
				dev_name(&pdev->dev));
	if (!hs_hcd)
		return -ENOMEM;

	vsoc_hcd = hcd_to_vsoc_hcd(hs_hcd);

	hs_hcd->has_tt = 1;
	g2h_ops.data = (unsigned long)vsoc_hcd;
	rc = vsoc_usb_register_g2h_ops(&g2h_ops);
	if (rc < 0)
		goto put_usb2_hcd;

	/*
	 * For now there isn't any irq on the same domain implementation.
	 * When the hcd code moves host,  we need to see if there is any way to
	 * generate an interrupt (either via vhost or ivshmem-eventfd).
	 * Independent of that, however, roothubs are designed to operate with
	 * polling (by setting HCD_FLAG_POLL_RH bit on the hcd driver). That
	 * aside, we will probably not have an irq line ever for this driver.
	 */
	rc = usb_add_hcd(hs_hcd, 0, 0);
	if (rc)
		goto put_usb2_hcd;
	return 0;

put_usb2_hcd:
	usb_put_hcd(hs_hcd);

	return rc;
}

int vsoc_usb_hcd_remove(struct platform_device *pdev)
{
	struct usb_hcd *hcd;

	dbg("%s\n", __func__);
	hcd = platform_get_drvdata(pdev);
	vsoc_usb_unregister_g2h_ops();
	usb_remove_hcd(hcd);
	usb_put_hcd(hcd);
	return 0;
}

int vsoc_usb_hcd_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct usb_hcd *hcd;
	struct vsoc_hcd *vsoc_hcd;
	int rc = 0;

	dbg("%s\n", __func__);
	hcd = platform_get_drvdata(pdev);
	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	if (vsoc_hcd->rh_state == VSOC_HCD_RH_RUNNING) {
		printk(KERN_WARNING "Root hub isn't suspended!\n");
		rc = -EBUSY;
	} else
		clear_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags);

	return rc;
}

int vsoc_usb_hcd_resume(struct platform_device *pdev)
{
	struct usb_hcd *hcd;
	dbg("%s\n", __func__);
	hcd = platform_get_drvdata(pdev);
	set_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags);
	usb_hcd_poll_rh_status(hcd);

	return 0;
}
