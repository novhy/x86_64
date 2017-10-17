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

#define DEBUG 1
#include "vsoc_usb_gadget_driver.h"

static int kick_gadget_internal(unsigned long data);

static struct vsoc_usb_gadget_ep *usb_ep_to_vsoc_gadget_ep(struct usb_ep *ep)
{
	return container_of(ep, struct vsoc_usb_gadget_ep, ep);
}

static struct vsoc_usb_gadget *gadget_dev_to_vsoc_gadget(struct device
								*dev)
{
	return container_of(dev, struct vsoc_usb_gadget, gadget.dev);
}

static struct vsoc_usb_gadget *gadget_to_vsoc_gadget(struct usb_gadget
							    *gadget)
{
	return container_of(gadget, struct vsoc_usb_gadget, gadget);
}

static struct vsoc_usb_gadget
	*vsoc_gadget_ep_to_vsoc_gadget(struct vsoc_usb_gadget_ep *gep)
{
	return container_of(gep->gadget, struct vsoc_usb_gadget, gadget);
}

static struct device *udc_dev(struct vsoc_usb_gadget *vsoc_gadget)
{
	return vsoc_gadget->gadget.dev.parent;
}

static struct vsoc_usb_gadget_request
	*usb_req_to_vsoc_usb_gadget_req(struct usb_request *usb_req)
{
	return container_of(usb_req, struct vsoc_usb_gadget_request, req);
}

static int handle_gadget_reset(struct vsoc_usb_gadget *gadget_controller)
{
	int rc = 0;
	unsigned long flags;
	dbg("%s\n", __func__);

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	if (gadget_controller->pullup) {
		/*
		 * TODO (romitd): Bring all individual endpoint states to init.
		 */
		dbg("%s got reset with pullup engaged\n", __func__);
	} else {
		dbg("%s got reset with pullup disengaged\n", __func__);
		rc = -ENODEV;
	}
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);
	return rc;
}


static int handle_gadget_ep_intr_out(struct vsoc_usb_gadget *gadget_controller,
			      int ep_num)
{
	int rc = 0, set_rx_action = 0;
	unsigned long flags;
	struct vsoc_usb_shm *shm = gadget_controller->shm;
	struct vsoc_usb_controller_regs *csr = &shm->csr;

	BUG_ON(!spin_is_locked(&shm->shm_lock));

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	if (test_and_clear_bit(H2G_DATA_OUT,
			       &csr->gadget_ep_out_reg[ep_num].intr)) {
		set_bit(H2G_DATA_OUT,
			&gadget_controller->rx_action_reason[ep_num]);
		set_rx_action = 1;
	}

	if (test_and_clear_bit(H2G_CONTROL_SETUP,
			       &csr->gadget_ep_out_reg[ep_num].intr)) {
		set_bit(H2G_CONTROL_SETUP,
			&gadget_controller->rx_action_reason[ep_num]);
		set_rx_action = 1;
	}

	if (test_and_clear_bit(H2G_CONTROL_DATA_OUT,
			       &csr->gadget_ep_out_reg[ep_num].intr)) {
		set_bit(H2G_CONTROL_DATA_OUT,
			&gadget_controller->rx_action_reason[ep_num]);
		set_rx_action = 1;
	}

	if (set_rx_action)
		set_bit(ep_num, &gadget_controller->rx_action);
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);

	return rc;
}

static int handle_gadget_ep_intr_in(struct vsoc_usb_gadget *gadget_controller,
			     int ep_num)
{
	int rc = 0, set_tx_action = 0;
	unsigned long flags;
	struct vsoc_usb_shm *shm = gadget_controller->shm;
	struct vsoc_usb_controller_regs *csr = &shm->csr;

	BUG_ON(!spin_is_locked(&shm->shm_lock));

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	if (test_and_clear_bit(H2G_DATA_IN,
			       &csr->gadget_ep_in_reg[ep_num].intr)) {
		set_bit(H2G_DATA_IN,
			 &gadget_controller->tx_action_reason[ep_num]);
		set_tx_action = 1;
	}
	if (test_and_clear_bit(H2G_CONTROL_DATA_IN,
			       &csr->gadget_ep_in_reg[ep_num].intr)) {
		set_bit(H2G_CONTROL_DATA_IN,
			&gadget_controller->tx_action_reason[ep_num]);
		set_tx_action  = 1;
	}

	if (set_tx_action)
		set_bit(ep_num, &gadget_controller->tx_action);
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);

	return rc;
}

static int handle_gadget_controller_intr(struct vsoc_usb_gadget *gadget_controller)
{
	int rc = 0;
	unsigned long flags;
	struct vsoc_usb_shm *shm = gadget_controller->shm;
	struct vsoc_usb_controller_regs *csr = &shm->csr;

	BUG_ON(!spin_is_locked(&shm->shm_lock));

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	if (test_and_clear_bit(H2G_RESET, &csr->gadget_reg.intr))
		set_bit(H2G_RESET, &gadget_controller->controller_action);
	if (test_and_clear_bit(H2G_DISCONNECT, &csr->gadget_reg.intr))
		set_bit(H2G_DISCONNECT, &gadget_controller->controller_action);
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);
	return rc;
}

static int handle_gadget_intr(struct vsoc_usb_gadget *gadget_controller)
{
	int rc = 0;
	int i;
	struct vsoc_usb_shm *shm = gadget_controller->shm;

	dbg("%s\n", __func__);

	BUG_ON(!spin_is_locked(&shm->shm_lock));
	handle_gadget_controller_intr(gadget_controller);

	for (i = 0; i < VSOC_NUM_ENDPOINTS; i++) {
		handle_gadget_ep_intr_in(gadget_controller, i);
		handle_gadget_ep_intr_out(gadget_controller, i);
	}

	return rc;
}

static void gadget_tasklet(unsigned long data)
{
	struct vsoc_usb_gadget *gadget_controller =
		(struct vsoc_usb_gadget *)data;
	struct vsoc_usb_shm *shm = gadget_controller->shm;
	unsigned long flags;
	int rc;

	dbg("%s\n", __func__);

	spin_lock_irqsave(&shm->shm_lock, flags);
	rc = handle_gadget_intr(gadget_controller);
	spin_unlock_irqrestore(&shm->shm_lock, flags);

	if (rc)
		printk(KERN_ERR "  handle_gadget_intr failed\n");

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	if (gadget_controller->controller_action ||
	    gadget_controller->rx_action)
		wake_up_interruptible(&gadget_controller->rxq);
	if (gadget_controller->tx_action)
		wake_up_interruptible(&gadget_controller->txq);
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);
}

/*
 * Generic routine to set interrupt bits in the virtual register area.
 * controller specific bits if ep_num == -1 && dir == NONE.
 */
static int kick_hcd(struct vsoc_usb_gadget *gadget_controller, int ep_num,
		    enum transaction_direction dir, unsigned long bit)
{
	struct vsoc_usb_shm *shm = gadget_controller->shm;
	struct vsoc_usb_controller_regs *csr =
		&gadget_controller->shm->csr;
	unsigned long flags, *hcd_intr_reg;
	int rc = 0;

	dbg("%s\n", __func__);

	BUG_ON(ep_num >= VSOC_NUM_ENDPOINTS);
	BUG_ON((dir == NONE) && (ep_num != -1));

	if (ep_num == -1)
		hcd_intr_reg = &csr->hcd_reg.intr;
	else
		hcd_intr_reg = (dir == IN) ? &csr->hcd_ep_in_reg[ep_num].intr :
					     &csr->hcd_ep_out_reg[ep_num].intr;

	spin_lock_irqsave(&shm->shm_lock, flags);
	set_bit(bit, hcd_intr_reg);
	spin_unlock_irqrestore(&shm->shm_lock, flags);
	rc = vsoc_usb_g2h_kick();
	if (rc)
		dbg("In %s, vsoc_usb_g2h_kick() failed\n", __func__);

	return rc;
}

/*
 * TODO(romitd): Implement.
 */
static int gadget_handle_control_data(
		struct vsoc_usb_gadget *gadget_controller, int ep_num, int dir)
{
	int rc = 0;
	return rc;
}

/*
 * TODO(romitd): Implement.
 */
static int gadget_handle_control_setup(
		struct vsoc_usb_gadget *gadget_controller, int ep_num)
{
	int rc = 0;
	return rc;
}

static int kick_gadget_internal(unsigned long data)
{
	struct vsoc_usb_gadget *gadget_controller =
		(struct vsoc_usb_gadget *)data;
	dbg("%s\n", __func__);
#ifdef DEBUG
	if (gadget_controller->shm->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}
#endif
	tasklet_schedule(&gadget_controller->gadget_tasklet);

	return 0;
}

static int gadget_handle_control_transaction(
		struct vsoc_usb_gadget *gadget_controller, int ep_num,
		unsigned long reason)
{
	int rc = 0;

	if (test_and_clear_bit(H2G_CONTROL_SETUP, &reason))
		rc = gadget_handle_control_setup(gadget_controller, ep_num);
	else if (test_and_clear_bit(H2G_CONTROL_DATA_IN, &reason))
		rc = gadget_handle_control_data(gadget_controller, ep_num, IN);
	else if (test_and_clear_bit(H2G_CONTROL_DATA_OUT, &reason))
		rc = gadget_handle_control_data(gadget_controller, ep_num, OUT);

	return rc;
}

static int vsoc_gadget_handle_ep_tx_events(
	struct vsoc_usb_gadget *gadget_controller, int ep_num)
{
	unsigned long flags, reason = 0;
	int rc = 0, is_control_event = 0;

	dbg("%s\n", __func__);
	dbg("   handling ep-%d-IN\n", ep_num);

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	if (test_and_clear_bit(H2G_DATA_IN,
			       &gadget_controller->tx_action_reason[ep_num])) {
		dbg("%s  H2G_DATA_IN_REQ\n", __func__);
		set_bit(H2G_DATA_IN, &reason);
	}

	if (test_and_clear_bit(H2G_CONTROL_DATA_IN,
			       &gadget_controller->tx_action_reason[ep_num])) {
		dbg("%s  H2G_CONTROL_DATA_IN\n", __func__);
		set_bit(H2G_CONTROL_DATA_IN, &reason);
		is_control_event = 1;
	}
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);

	if (is_control_event)
		rc = gadget_handle_control_transaction(gadget_controller,
						       ep_num, reason);
	return rc;
}

/*
 * Called from vsoc_gadget_tx
 */
static int _vsoc_gadget_tx(struct vsoc_usb_gadget *gadget_controller)
{
	unsigned long flags, tx_action;
	int i, status;
	set_current_state(TASK_RUNNING);
	try_to_freeze();
	set_current_state(TASK_INTERRUPTIBLE);
	dbg("%s before sleep\n", __func__);
	wait_event_interruptible(gadget_controller->txq,
				 gadget_controller->tx_action ||
				 kthread_should_stop());
	dbg("%s after wakeup\n", __func__);
	if (kthread_should_stop())
		return 1;

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	tx_action = gadget_controller->tx_action;
	gadget_controller->tx_action = 0;
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);

	/*
	 * Go through the pending work per endpoint.
	 */
	status = 0;
	for (i = 0; i < VSOC_NUM_ENDPOINTS && tx_action; i++) {
		if (test_and_clear_bit(i, &tx_action)) {
			status = vsoc_gadget_handle_ep_tx_events(
							gadget_controller, i);
			if (status)
				printk(KERN_INFO "%s Error in ep-%d IN\n",
				       __func__, i);
		}
	}

	if (tx_action)
		printk(KERN_ERR "Unhandled tx_action[%lu] in %s\n", tx_action,
		       __func__);
	return 0;
}

/*
 * Tx w.r.t. gadget.
 * Handles IN transactions.
 */
static int vsoc_gadget_tx(void *data)
{
	struct vsoc_usb_gadget *gadget_controller =
		(struct vsoc_usb_gadget *)data;

	dbg("%s\n", __func__);
#ifdef DEBUG
	if (gadget_controller->shm->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}
#endif
	set_freezable();

	for(;;)
		if (_vsoc_gadget_tx(gadget_controller)) break;

	return 0;
}

static int vsoc_gadget_handle_controller_events(
	struct vsoc_usb_gadget *gadget_controller, unsigned long action)
{
	int rc = 0;

	dbg("%s\n", __func__);

	if (test_and_clear_bit(H2G_RESET, &action)) {
		if (!handle_gadget_reset(gadget_controller))
			kick_hcd(gadget_controller, -1, NONE,
				 G2H_RESET_COMPLETE);
	}

	if(action)
		printk(KERN_ERR "Unhandled controller_action[%lu] in %s",
		       action, __func__);
	return rc;
}

static int vsoc_gadget_handle_ep_rx_events(
	struct vsoc_usb_gadget *gadget_controller, int ep_num)
{
	unsigned long flags, reason = 0;
	int rc = 0, is_control_event = 0;

	dbg("%s\n", __func__);
	dbg("   handling ep-%d-OUT\n", ep_num);

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	if (test_and_clear_bit(H2G_DATA_OUT,
		&gadget_controller->rx_action_reason[ep_num])) {
		dbg("%s  H2G_DATA_OUT", __func__);
		set_bit(H2G_DATA_OUT, &reason);
	}

	if (test_and_clear_bit(H2G_CONTROL_SETUP,
		&gadget_controller->rx_action_reason[ep_num])) {
		dbg("%s  H2G_CONTROL_SETUP", __func__);
		set_bit(H2G_CONTROL_SETUP, &reason);
		is_control_event = 1;
	}
	if (test_and_clear_bit(H2G_CONTROL_DATA_OUT,
		&gadget_controller->rx_action_reason[ep_num])) {
		dbg("%s  H2G_CONTROL_DATA_OUT", __func__);
		set_bit(H2G_CONTROL_DATA_OUT, &reason);
		is_control_event = 1;
	}

	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);

	if (is_control_event)
		rc = gadget_handle_control_transaction(gadget_controller,
						       ep_num, reason);
	return rc;
}

/*
 * Called from vsoc_gadget_rx
 */
static int _vsoc_gadget_rx(struct vsoc_usb_gadget *gadget_controller)
{
	unsigned long flags, controller_action, rx_action;
	int status, i;

	set_current_state(TASK_RUNNING);
	try_to_freeze();
	set_current_state(TASK_INTERRUPTIBLE);
	dbg("%s before sleep\n", __func__);
	wait_event_interruptible(gadget_controller->rxq,
			gadget_controller->controller_action ||
			gadget_controller->rx_action ||
			kthread_should_stop());
	dbg("%s after wakeup\n", __func__);
	if (kthread_should_stop())
		return 1;
	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	controller_action = gadget_controller->controller_action;
	gadget_controller->controller_action = 0;
	rx_action = gadget_controller->rx_action;
	gadget_controller->rx_action = 0;
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);

	vsoc_gadget_handle_controller_events(gadget_controller,
					     controller_action);

	/*
	 * Go through the pending work per endpoint.
	 */
	status = 0;
	for (i = 0; i < VSOC_NUM_ENDPOINTS && rx_action; i++) {
		if (test_and_clear_bit(i, &rx_action)) {
			status = vsoc_gadget_handle_ep_rx_events(
							gadget_controller, i);
			if (status)
				printk(KERN_INFO "%s Error in ep-%d OUT\n",
				       __func__, i);
		}
	}

	if (rx_action)
		printk(KERN_ERR "Unhandled rx_action[%lu] in %s\n", rx_action,
		       __func__);
	return 0;
}

/*
 * Rx w.r.t. gadget.
 * Handles OUT transactions & gadget controller specific events.
 */
static int vsoc_gadget_rx(void *data)
{
	struct vsoc_usb_gadget *gadget_controller =
		(struct vsoc_usb_gadget *)data;

	dbg("%s\n", __func__);
#ifdef DEBUG
	if (gadget_controller->shm->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}
#endif
	set_freezable();

	for(;;)
		if (_vsoc_gadget_rx(gadget_controller)) break;

	return 0;
}

/*
 * This routine is called with vsoc_usb_gadget lock held.
 */
static void nuke(struct vsoc_usb_gadget *gadget_controller,
		 struct vsoc_usb_gadget_ep *gep)
{
	dbg("%s\n", __func__);
	while (!list_empty(&gep->queue)) {
		struct vsoc_usb_gadget_request *req;

		req = list_entry(gep->queue.next,
				 struct vsoc_usb_gadget_request, queue);
		list_del_init(&req->queue);
		req->req.status = -ESHUTDOWN;

		spin_unlock(&gadget_controller->gadget_lock);
		/*
		 * This will call the complete function of the usb_request
		 */
		usb_gadget_giveback_request(&gep->ep, &req->req);
		spin_lock(&gadget_controller->gadget_lock);
	}
}

static int gadget_ep_enable(struct usb_ep *ep,
			    const struct usb_endpoint_descriptor *desc)
{
	struct vsoc_usb_gadget *gadget_controller;
	struct vsoc_usb_gadget_ep *gep;
	unsigned max;
	int retval;

	dbg("%s\n", __func__);
	gep = usb_ep_to_vsoc_gadget_ep(ep);
	if (!ep || !desc || gep->desc || ep->name == ep0name
	    || desc->bDescriptorType != USB_DT_ENDPOINT)
		return -EINVAL;

	gadget_controller = vsoc_gadget_ep_to_vsoc_gadget(gep);
	if (!gadget_controller->driver)
		return -ESHUTDOWN;

	/*
	 * For HS/FS devices only bits 0..10 of the wMaxPacketSize represent the
	 * maximum packet size.
	 * For SS devices the wMaxPacketSize is limited by 1024.
	 */
	max = usb_endpoint_maxp(desc) & 0x7ff;

	/*
	 * Debug info for bad settings.
	 */
	retval = -EINVAL;
	switch (usb_endpoint_type(desc)) {
	case USB_ENDPOINT_XFER_BULK:
		if (strstr(gep->ep.name, "-iso")
		    || strstr(gep->ep.name, "-int")) {
			goto done;
		}
		switch (gadget_controller->gadget.speed) {
		case USB_SPEED_HIGH:
			if (max == 512)
				break;
			goto done;
		case USB_SPEED_FULL:
			if (max == 8 || max == 16 || max == 32 || max == 64)
				break;
		default:
			goto done;
		}
		break;
	case USB_ENDPOINT_XFER_INT:
		if (strstr(gep->ep.name, "-iso"))	/* bulk is ok */
			goto done;
		switch (gadget_controller->gadget.speed) {
		case USB_SPEED_HIGH:
			if (max <= 1024)
				break;
		case USB_SPEED_FULL:
			if (max <= 64)
				break;
		default:
			if (max <= 8)
				break;
			goto done;
		}
		break;
	case USB_ENDPOINT_XFER_ISOC:
		if (strstr(gep->ep.name, "-bulk")
		    || strstr(gep->ep.name, "-int"))
			goto done;
		switch (gadget_controller->gadget.speed) {
		case USB_SPEED_HIGH:
			if (max <= 1024)
				break;
		case USB_SPEED_FULL:
			if (max <= 1023)
				break;
		default:
			goto done;
		}
		break;
	default:
		goto done;
	}

	ep->maxpacket = max;
	gep->desc = desc;

	dev_dbg(udc_dev(gadget_controller), "enabled %s (ep%d%s-%s) maxpacket "
		"%d\n", ep->name,
		desc->bEndpointAddress & 0x0f,
		(desc->bEndpointAddress & USB_DIR_IN) ? "in" : "out",
		( {
		  char *val;
		  switch (usb_endpoint_type (desc)) {
		  case USB_ENDPOINT_XFER_BULK:
			val = "bulk";
			break;
		  case USB_ENDPOINT_XFER_ISOC:
			val = "isoc";
			break;
		  case USB_ENDPOINT_XFER_INT:
			val = "int";
			break;
		  default:
			val = "ctrl";
			break;
		} val;}), max) ;

	gep->halted = gep->wedged = 0;
	retval = 0;
done:
	return retval;

}

static int gadget_ep_disable(struct usb_ep *ep)
{
	struct vsoc_usb_gadget_ep *gep;
	struct vsoc_usb_gadget *gadget_controller;
	unsigned long flags;

	dbg("%s\n", __func__);
	gep = usb_ep_to_vsoc_gadget_ep(ep);
	if (!ep || !gep->desc || ep->name == ep0name)
		return -EINVAL;
	gadget_controller = vsoc_gadget_ep_to_vsoc_gadget(gep);

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	gep->desc = NULL;
	nuke(gadget_controller, gep);
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);

	dev_dbg(udc_dev(gadget_controller), "disabled %s\n", ep->name);
	return 0;
}

static struct usb_request *gadget_ep_alloc_request(struct usb_ep *ep,
						   gfp_t gfp_flags)
{
	struct vsoc_usb_gadget_request *req;

	dbg("%s\n", __func__);
	if (!ep)
		return NULL;

	req = kzalloc(sizeof(*req), gfp_flags);
	if (!req)
		return NULL;
	INIT_LIST_HEAD(&req->queue);
	return &req->req;
}

static void gadget_ep_free_request(struct usb_ep *ep, struct usb_request *req)
{
	struct vsoc_usb_gadget_request *gadget_req;

	dbg("%s\n", __func__);
	if (!ep || !req) {
		WARN_ON(1);
		return;
	}
	gadget_req = usb_req_to_vsoc_usb_gadget_req(req);
	WARN_ON(!list_empty(&gadget_req->queue));
	kfree(gadget_req);
}

static int gadget_ep_queue_request(struct usb_ep *ep, struct usb_request *req,
				   gfp_t gfp_flags)
{
	dbg("%s\n", __func__);
	return 0;
}

static int gadget_ep_dequeue_request(struct usb_ep *ep, struct usb_request *req)
{
	dbg("%s\n", __func__);
	return 0;
}

static int set_halt_and_wedge(struct usb_ep *ep, int value, int wedged)
{
	struct vsoc_usb_gadget_ep *gep;
	struct vsoc_usb_gadget *controller;

	dbg("%s\n", __func__);
	if (!ep)
		return -EINVAL;
	gep = usb_ep_to_vsoc_gadget_ep(ep);
	controller = vsoc_gadget_ep_to_vsoc_gadget(gep);

	if (!controller->driver)
		return -ESHUTDOWN;

	if (!value)
		gep->halted = gep->wedged = 0;
	else if (gep->desc && (gep->desc->bEndpointAddress & USB_DIR_IN) &&
		 !list_empty(&gep->queue))
		return -EAGAIN;
	else {
		gep->halted = 1;
		if (wedged)
			gep->wedged = 1;
	}

	return 0;
}

static int gadget_ep_halt(struct usb_ep *ep, int value)
{
	dbg("%s\n", __func__);

	return set_halt_and_wedge(ep, value, 0);
}

static int gadget_ep_wedge(struct usb_ep *ep)
{
	dbg("%s\n", __func__);
	if (!ep || ep->name == ep0name)
		return -EINVAL;

	return set_halt_and_wedge(ep, 1, 1);
}

static const struct usb_ep_ops vsoc_ep_ops = {
	.enable = gadget_ep_enable,
	.disable = gadget_ep_disable,
	.alloc_request = gadget_ep_alloc_request,
	.free_request = gadget_ep_free_request,
	.queue = gadget_ep_queue_request,
	.dequeue = gadget_ep_dequeue_request,
	.set_halt = gadget_ep_halt,
	.set_wedge = gadget_ep_wedge,
};

static int gadget_get_frame(struct usb_gadget *gadget)
{
	struct timespec64 ts64;
	dbg("%s\n", __func__);
	ktime_get_ts64(&ts64);

	return ts64.tv_nsec / NSEC_PER_MSEC;
}

static int gadget_wakeup(struct usb_gadget *gadget)
{
	unsigned long flags;
	int rc = 0;
	struct vsoc_usb_gadget *gadget_controller =
	    gadget_to_vsoc_gadget(gadget);
	dbg("%s\n", __func__);

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	if (!(gadget_controller->devstatus &
	      ((1 << USB_DEVICE_B_HNP_ENABLE) |
	       (1 << USB_DEVICE_REMOTE_WAKEUP))))
		rc = -EINVAL;
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);

	/*
	 * TODO(romitd): We need to kick the HCD.
	 */
	return rc;
}

static int gadget_set_selfpowered(struct usb_gadget *gadget, int is_selfpowered)
{
	unsigned long flags;
	struct vsoc_usb_gadget *gadget_controller =
	    gadget_to_vsoc_gadget(gadget);
	dbg("%s\n", __func__);

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	gadget->is_selfpowered = (is_selfpowered != 0);
	if (gadget->is_selfpowered)
		gadget_controller->devstatus |= (1 << USB_DEVICE_SELF_POWERED);
	else
		gadget_controller->devstatus &= ~(1 << USB_DEVICE_SELF_POWERED);
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);

	return 0;
}

static int gadget_pullup(struct usb_gadget *gadget, int is_on)
{
	unsigned long gadget_lock_flags, shm_lock_flags;
	struct vsoc_usb_gadget *gadget_controller =
	    gadget_to_vsoc_gadget(gadget);
	struct vsoc_usb_shm *shm = gadget_controller->shm;
	struct vsoc_usb_controller_regs *csr = &shm->csr;

	dbg("%s\n", __func__);

	/*
	 * TODO (romitd): On pullup, move all endpoint status to init state.
	 */
	if (is_on && gadget_controller->driver) {
		gadget_controller->gadget.speed =
		    gadget_controller->driver->max_speed;
		gadget_controller->gep[0].ep.maxpacket = 64;
	}

	spin_lock_irqsave(&gadget_controller->gadget_lock, gadget_lock_flags);
	gadget_controller->pullup = (is_on != 0);

	spin_lock_irqsave(&shm->shm_lock, shm_lock_flags);
	if (gadget_controller->pullup)
		set_bit(GADGET_PULLUP, &csr->gadget_reg.status);
	else
		clear_bit(GADGET_PULLUP, &csr->gadget_reg.status);
	spin_unlock_irqrestore(&shm->shm_lock, shm_lock_flags);

	/*
	 * Let the HCD know.
	 */
	kick_hcd(gadget_controller, -1, NONE, G2H_CONN_CHANGE);

	spin_unlock_irqrestore(&gadget_controller->gadget_lock,
			       gadget_lock_flags);

	return 0;
}

static int gadget_udc_start(struct usb_gadget *gadget,
			    struct usb_gadget_driver *driver)
{
	unsigned long flags;
	struct vsoc_usb_gadget *gadget_controller =
		gadget_to_vsoc_gadget(gadget);

	struct vsoc_usb_shm *shm = gadget_controller->shm;
	struct vsoc_usb_controller_regs *csr = &shm->csr;

	dbg("%s\n", __func__);
	if (shm->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}

	if (driver->max_speed == USB_SPEED_UNKNOWN)
		return -EINVAL;

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	gadget_controller->devstatus = 0;
	gadget_controller->driver = driver;
	gadget_controller->controller_action = 0;
	gadget_controller->tx_action = 0;
	gadget_controller->rx_action = 0;
	memset(gadget_controller->tx_action_reason, 0,
	       sizeof(gadget_controller->tx_action_reason));
	memset(gadget_controller->rx_action_reason, 0,
	       sizeof(gadget_controller->rx_action_reason));
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);

	spin_lock_irqsave(&shm->shm_lock, flags);
	memset(&csr->gadget_reg, 0, sizeof(csr->gadget_reg));
	memset(csr->gadget_ep_in_reg, 0, sizeof(csr->gadget_ep_in_reg));
	memset(csr->gadget_ep_out_reg, 0, sizeof(csr->gadget_ep_out_reg));
	spin_unlock_irqrestore(&shm->shm_lock, flags);

	return 0;
}

static int gadget_udc_stop(struct usb_gadget *gadget)
{
	unsigned long flags;
	struct vsoc_usb_gadget *gadget_controller =
	    gadget_to_vsoc_gadget(gadget);

	dbg("%s\n", __func__);
	if (gadget_controller->shm->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}

	spin_lock_irqsave(&gadget_controller->gadget_lock, flags);
	gadget_controller->devstatus = 0;
	gadget_controller->driver = NULL;
	spin_unlock_irqrestore(&gadget_controller->gadget_lock, flags);

	return 0;
}

static const struct usb_gadget_ops vsoc_gadget_ops = {
	.get_frame = gadget_get_frame,
	.wakeup = gadget_wakeup,
	.set_selfpowered = gadget_set_selfpowered,
	.pullup = gadget_pullup,
	.udc_start = gadget_udc_start,
	.udc_stop = gadget_udc_stop,
};

static ssize_t function_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct vsoc_usb_gadget *gadget_controller =
	    gadget_dev_to_vsoc_gadget(dev);
	dbg("%s\n", __func__);

	if (!gadget_controller->driver || !gadget_controller->driver->function)
		return 0;
	return scnprintf(buf, PAGE_SIZE, "%s\n",
			 gadget_controller->driver->function);
}

static DEVICE_ATTR_RO(function);

/*
 * Initializes the vsoc_usb_gadget_ep structures and adds them to the usb_gadget
 * ep list.
 * Among other things the ep ops are also assigned here.
 * Control endpoint (0) is left out of the list.
 */
static void initialize_vsoc_usb_gadget(struct vsoc_usb_gadget
				       *gadget_controller)
{
	int i;

	dbg("%s\n", __func__);
	spin_lock_init(&gadget_controller->gadget_lock);
	INIT_LIST_HEAD(&gadget_controller->gadget.ep_list);
	for (i = 0; i < VSOC_NUM_ENDPOINTS; i++) {
		struct vsoc_usb_gadget_ep *gep = &gadget_controller->gep[i];
		if (!vsoc_usb_gadget_get_ep_name(i))
			break;
		gep->ep.name = vsoc_usb_gadget_get_ep_name(i);
		gep->ep.caps = *vsoc_usb_gadget_get_ep_caps(i);
		gep->ep.ops = &vsoc_ep_ops;
		list_add_tail(&gep->ep.ep_list,
			      &gadget_controller->gadget.ep_list);
		usb_ep_set_maxpacket_limit(&gep->ep, ~0);
		gep->last_io = jiffies;
		gep->gadget = &gadget_controller->gadget;
		INIT_LIST_HEAD(&gep->queue);
	}

	gadget_controller->gadget.ep0 = &gadget_controller->gep[0].ep;

	/* removes ep 0 from the gadget ep list */
	list_del_init(&gadget_controller->gep[0].ep.ep_list);

	init_waitqueue_head(&gadget_controller->txq);
	init_waitqueue_head(&gadget_controller->rxq);

	tasklet_init(&gadget_controller->gadget_tasklet, gadget_tasklet,
		     (unsigned long)gadget_controller);
}

/*
 * Initializes the vsoc_usb_gadget structure for the pdev.
 * Among other things the gadget ops are also assigned here.
 */
int vsoc_usb_gadget_probe(struct platform_device *pdev)
{
	struct vsoc_usb_gadget *gadget_controller;
	int rc;

	dbg("%s\n", __func__);
	gadget_controller = *((void **)dev_get_platdata(&pdev->dev));
	gadget_controller->gadget.name = gadget_name;
	gadget_controller->gadget.ops = &vsoc_gadget_ops;
	gadget_controller->gadget.max_speed = USB_SPEED_HIGH;
	gadget_controller->gadget.dev.parent = &pdev->dev;
	initialize_vsoc_usb_gadget(gadget_controller);
	INIT_LIST_HEAD(&gadget_controller->fifo_req.queue);

	rc = usb_add_gadget_udc(&pdev->dev, &gadget_controller->gadget);
	if (rc < 0)
		goto err_udc;

	rc = device_create_file(&gadget_controller->gadget.dev,
				&dev_attr_function);
	if (rc < 0)
		goto err_dev;

	rc = vsoc_usb_register_h2g_ipi(kick_gadget_internal,
				       (unsigned long)gadget_controller);
	if (rc < 0)
		goto err_dev_file;

	gadget_controller->tx_thread = kthread_run(vsoc_gadget_tx,
					(void *)gadget_controller,
					"vsoc_g_tx/%d",
					gadget_controller->gadget.dev.id);
	if (IS_ERR(gadget_controller->tx_thread)) {
		rc = -ENODEV;
		goto err_kthread;
	}

	gadget_controller->rx_thread = kthread_run(vsoc_gadget_rx,
					 (void *)gadget_controller,
					 "vsoc_g_rx/%d",
					 gadget_controller->gadget.dev.id);

	if (IS_ERR(gadget_controller->rx_thread)) {
		rc = -ENODEV;
		kthread_stop(gadget_controller->tx_thread);
		gadget_controller->tx_thread = NULL;
		goto err_kthread;
	}

	platform_set_drvdata(pdev, gadget_controller);
	return 0;

err_kthread:
	vsoc_usb_unregister_h2g_ipi();
err_dev_file:
	device_remove_file(&gadget_controller->gadget.dev, &dev_attr_function);
err_dev:
	usb_del_gadget_udc(&gadget_controller->gadget);
err_udc:
	return rc;
}

int vsoc_usb_gadget_remove(struct platform_device *pdev)
{
	struct vsoc_usb_gadget *gadget_controller = platform_get_drvdata(pdev);

	dbg("%s\n", __func__);
	device_remove_file(&gadget_controller->gadget.dev, &dev_attr_function);
	usb_del_gadget_udc(&gadget_controller->gadget);
	vsoc_usb_unregister_h2g_ipi();
	tasklet_kill(&gadget_controller->gadget_tasklet);
	if (gadget_controller->tx_thread) {
		kthread_stop(gadget_controller->tx_thread);
		gadget_controller->tx_thread = NULL;
	}
	if (gadget_controller->rx_thread) {
		kthread_stop(gadget_controller->rx_thread);
		gadget_controller->rx_thread = NULL;
	}

	return 0;
}

static void vsoc_gadget_controller_pm(struct vsoc_usb_gadget *gadget_controller,
				      int suspend)
{
	dbg("%s\n", __func__);
	spin_lock_irq(&gadget_controller->gadget_lock);
	gadget_controller->udc_suspended = suspend;

	/*
	 * TODO(romitd): Notify HCD.
	 */

	spin_unlock_irq(&gadget_controller->gadget_lock);
}

int vsoc_usb_gadget_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct vsoc_usb_gadget *gadget_controller = platform_get_drvdata(pdev);
	dev_dbg(&pdev->dev, "%s\n", __func__);
	vsoc_gadget_controller_pm(gadget_controller, 1);

	/*
	 * TODO(romitd): Notify the HCD.
	 */

	return 0;
}

int vsoc_usb_gadget_resume(struct platform_device *pdev)
{
	struct vsoc_usb_gadget *gadget_controller = platform_get_drvdata(pdev);
	dev_dbg(&pdev->dev, "%s\n", __func__);
	vsoc_gadget_controller_pm(gadget_controller, 0);

	/*
	 * TODO(romitd): Notify the HCD.
	 */

	return 0;
}
