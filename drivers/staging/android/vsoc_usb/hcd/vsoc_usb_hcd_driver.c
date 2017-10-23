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

#define DRIVER_VERSION "Intra-Domain Shared Memory"


static int kick_hcd_internal(unsigned long data);
static int handle_gadget_conn_change(struct vsoc_hcd *vsoc_hcd);

static const char driver_desc[] = "VSoC USB Host Emulator";

static struct vsoc_hcd *hcd_to_vsoc_hcd(struct usb_hcd *hcd)
{
	return (struct vsoc_hcd *)(hcd->hcd_priv);
}

static struct usb_hcd *vsoc_hcd_to_hcd(struct vsoc_hcd *vsoc_hcd)
{
	return vsoc_hcd->hcd;
}

static int hcd_scrub_ep_buffer(struct vsoc_hcd *vsoc_hcd, int ep_num, int dir)
{
	int rc = 0;
	unsigned long flags;
	struct vsoc_usb_packet_buffer *buf;
	struct vsoc_usb_shm *shm = vsoc_hcd->shm;

	BUG_ON(!spin_is_locked(&vsoc_hcd->vsoc_hcd_lock));

	buf = (dir == IN) ? &shm->ep_in_buf[ep_num] : &shm->ep_out_buf[ep_num];
	spin_lock_irqsave(&shm->shm_lock, flags);
	buf->hcd_data_len = buf->gadget_data_len = 0;
	memset(buf->buffer, 0, VSOC_ENDPOINT_BUFFER_SIZE);
	spin_unlock_irqrestore(&shm->shm_lock, flags);
	return rc;
}

static int try_hcd_scrub_ep_buffer_by_urb(struct vsoc_hcd *vsoc_hcd,
					  struct urbp *urbp)
{
	int rc = 0;
	u8 ep_num, is_out;
	struct vsoc_usb_packet_buffer *buf;
	struct urb *urb;
	struct vsoc_usb_shm *shm = vsoc_hcd->shm;
	unsigned long flags;

	BUG_ON(!spin_is_locked(&vsoc_hcd->vsoc_hcd_lock));

	urb = urbp->urb;
	ep_num = usb_pipeendpoint(urb->pipe);
	is_out = usb_pipeout(urb->pipe);

	/*
	 * This URB is not in flight so don't mess with the ep buffers.
	 */
	if (!test_and_clear_bit(URB_IN_FLIGHT_BIT, &urbp->transaction_state))
		return rc;
	/*
	 * USB CONTROL transfers differ from BULK/INTERRUPT/ISO. Depending on
	 * the state of the transfer the packet could be in the input or the
	 * output packet buffer.
	 */
	if (usb_pipecontrol(urb->pipe)) {
		if (urbp->transaction_state == CONTROL_IN_STATE ||
		    urbp->transaction_state == CONTROL_IN_START_STATE)
			buf = &shm->ep_in_buf[ep_num];
		else
			buf = &shm->ep_out_buf[ep_num];
	} else if (is_out) {
		buf = &shm->ep_out_buf[ep_num];
	} else {
		buf = &shm->ep_in_buf[ep_num];
	}

	spin_lock_irqsave(&shm->shm_lock, flags);
	buf->hcd_data_len = buf->gadget_data_len = 0;
	spin_unlock_irqrestore(&shm->shm_lock, flags);

	return rc;
}

static int handle_hcd_controller_intr(struct vsoc_hcd *vsoc_hcd)
{
	int rc = 0;
	unsigned long flags;
	struct vsoc_usb_shm *shm = vsoc_hcd->shm;
	struct vsoc_usb_controller_regs *csr = &shm->csr;

	BUG_ON(!spin_is_locked(&shm->shm_lock));

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	if (test_and_clear_bit(G2H_RESET_COMPLETE, &csr->hcd_reg.intr)) {
		set_bit(G2H_RESET_COMPLETE, &vsoc_hcd->controller_action);
	}

	if (test_and_clear_bit(G2H_CONN_CHANGE, &csr->hcd_reg.intr)) {
		set_bit(G2H_CONN_CHANGE, &vsoc_hcd->controller_action);
	}
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);

	return rc;
}

static int handle_hcd_ep_intr_out(struct vsoc_hcd *vsoc_hcd, int ep_num)
{
	int rc = 0, set_tx_action = 0;
	unsigned long flags;
	struct vsoc_usb_shm *shm = vsoc_hcd->shm;
	struct vsoc_usb_controller_regs *csr = &shm->csr;

	BUG_ON(!spin_is_locked(&shm->shm_lock));

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);

	if (test_and_clear_bit(G2H_TRANSACTION_ERR,
		&csr->hcd_ep_out_reg[ep_num].intr)) {
		set_tx_action = 1;
		set_bit(G2H_TRANSACTION_ERR,
			&vsoc_hcd->tx_action_reason[ep_num]);
	}

	if (test_and_clear_bit(G2H_CONTROL_DATA_NAK,
		&csr->hcd_ep_out_reg[ep_num].intr)) {
		set_tx_action = 1;
		set_bit(G2H_CONTROL_DATA_NAK,
			&vsoc_hcd->tx_action_reason[ep_num]);
	}

	if (test_and_clear_bit(G2H_DATA_NAK,
		&csr->hcd_ep_out_reg[ep_num].intr)) {
		set_tx_action = 1;
		set_bit(G2H_DATA_NAK,
			&vsoc_hcd->tx_action_reason[ep_num]);
	}

	/*
	 * Gadget ACKing Ctrl SETUP packet.
	 */
	if (test_and_clear_bit(G2H_CONTROL_SETUP_ACK,
		&csr->hcd_ep_out_reg[ep_num].intr)) {
		set_tx_action = 1;
		set_bit(G2H_CONTROL_SETUP_ACK,
			&vsoc_hcd->tx_action_reason[ep_num]);
	}

	if (test_and_clear_bit(G2H_CONTROL_DATA_OUT_ACK,
		&csr->hcd_ep_out_reg[ep_num].intr)) {
		set_tx_action = 1;
		set_bit(G2H_CONTROL_DATA_OUT_ACK,
			&vsoc_hcd->tx_action_reason[ep_num]);
	}

	if (test_and_clear_bit(G2H_CONTROL_STATUS_ACK,
		&csr->hcd_ep_out_reg[ep_num].intr)) {
		set_tx_action = 1;
		set_bit(G2H_CONTROL_STATUS_ACK,
			&vsoc_hcd->tx_action_reason[ep_num]);
	}

	if (set_tx_action)
		set_bit(ep_num, &vsoc_hcd->tx_action);

	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);

	return rc;
}

static int handle_hcd_ep_intr_in(struct vsoc_hcd *vsoc_hcd, int ep_num)
{
	int rc = 0, set_rx_action = 0;
	unsigned long flags;
	struct vsoc_usb_shm *shm = vsoc_hcd->shm;
	struct vsoc_usb_controller_regs *csr = &shm->csr;

	BUG_ON(!spin_is_locked(&shm->shm_lock));

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);

	if (test_and_clear_bit(G2H_TRANSACTION_ERR,
		&csr->hcd_ep_in_reg[ep_num].intr)) {
		set_rx_action = 1;
		set_bit(G2H_TRANSACTION_ERR,
			&vsoc_hcd->rx_action_reason[ep_num]);
	}

	if (test_and_clear_bit(G2H_CONTROL_DATA_IN,
		&csr->hcd_ep_in_reg[ep_num].intr)) {
		set_rx_action = 1;
		set_bit(G2H_CONTROL_DATA_IN,
			&vsoc_hcd->rx_action_reason[ep_num]);
	}
	if (test_and_clear_bit(G2H_CONTROL_DATA_NAK,
		&csr->hcd_ep_in_reg[ep_num].intr)) {
		set_rx_action = 1;
		set_bit(G2H_CONTROL_DATA_NAK,
			&vsoc_hcd->rx_action_reason[ep_num]);
	}

	if (test_and_clear_bit(G2H_DATA_NAK,
		&csr->hcd_ep_in_reg[ep_num].intr)) {
		set_rx_action = 1;
		set_bit(G2H_DATA_NAK,
			&vsoc_hcd->rx_action_reason[ep_num]);
	}

	if (set_rx_action)
		set_bit(ep_num, &vsoc_hcd->rx_action);

	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);

	return rc;
}

static int handle_hcd_intr(struct vsoc_hcd *vsoc_hcd)
{
	int rc = 0, i;
	struct vsoc_usb_shm *shm = vsoc_hcd->shm;

	dbg("%s\n", __func__);

	BUG_ON(!spin_is_locked(&shm->shm_lock));

	handle_hcd_controller_intr(vsoc_hcd);

	for (i = 0; i < VSOC_NUM_ENDPOINTS; i++) {
		handle_hcd_ep_intr_in(vsoc_hcd, i);
		handle_hcd_ep_intr_out(vsoc_hcd, i);
	}

	return rc;
}

static void hcd_tasklet(unsigned long data)
{
	struct vsoc_hcd *vsoc_hcd = (struct vsoc_hcd *)data;
	struct vsoc_usb_shm *shm = vsoc_hcd->shm;
	unsigned long flags;
	int rc;
	dbg("%s\n",__func__);
	spin_lock_irqsave(&shm->shm_lock, flags);
	rc = handle_hcd_intr(vsoc_hcd);
	spin_unlock_irqrestore(&shm->shm_lock, flags);

	if (rc)
		printk(KERN_ERR "  handle_hcd_intr failed\n");

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	if (vsoc_hcd->controller_action || vsoc_hcd->rx_action)
		wake_up_interruptible(&vsoc_hcd->rxq);
	if (vsoc_hcd->tx_action)
		wake_up_interruptible(&vsoc_hcd->txq);
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
}

static int kick_hcd_internal(unsigned long data)
{
	struct vsoc_hcd *vsoc_hcd = (struct vsoc_hcd *)data;
	dbg("%s\n", __func__);
#ifdef DEBUG
	if (vsoc_hcd->shm->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}
#endif
	tasklet_schedule(&vsoc_hcd->hcd_tasklet);
	return 0;
}

/*
 * Generic routine to set interrupt bits in the virtual register area.
 * controller specific bits if ep_num == -1 && dir == NONE.
 */
static int kick_gadget(struct vsoc_hcd *vsoc_hcd, int ep_num,
		       enum transaction_direction dir, unsigned long bit)
{
	struct vsoc_usb_shm *shm = vsoc_hcd->shm;
	struct vsoc_usb_controller_regs *csr = &shm->csr;
	unsigned long flags, *gadget_intr_reg;
	int rc = 0;

	dbg("%s\n", __func__);

	BUG_ON(ep_num >= VSOC_NUM_ENDPOINTS);
	BUG_ON((dir == NONE) && (ep_num != -1));

	if (ep_num == -1)
		gadget_intr_reg = &csr->gadget_reg.intr;
	else
		gadget_intr_reg = (dir == IN) ?
			&csr->gadget_ep_in_reg[ep_num].intr :
			&csr->gadget_ep_out_reg[ep_num].intr;

	spin_lock_irqsave(&shm->shm_lock, flags);
	set_bit(bit, gadget_intr_reg);
	spin_unlock_irqrestore(&shm->shm_lock, flags);
	rc = vsoc_usb_h2g_kick();
	if (rc)
		dbg("In %s, vsoc_usb_h2g_kick() failed\n", __func__);

	return rc;
}

static void vsoc_hcd_giveback_urb(struct vsoc_hcd *vsoc_hcd, struct urbp *urbp,
				  int status)
{
	struct urb *urb;
	BUG_ON(!spin_is_locked(&vsoc_hcd->vsoc_hcd_lock));
	urb = urbp->urb;
	list_del(&urbp->urbp_list);
	kfree(urbp);

	usb_hcd_unlink_urb_from_ep(vsoc_hcd_to_hcd(vsoc_hcd), urb);
	spin_unlock(&vsoc_hcd->vsoc_hcd_lock);
	usb_hcd_giveback_urb(vsoc_hcd_to_hcd(vsoc_hcd), urb, status);
	spin_lock(&vsoc_hcd->vsoc_hcd_lock);

	return;
}

static int vsoc_hcd_ep_control_transaction(struct vsoc_hcd *vsoc_hcd,
					   int ep_num, int dir)
{
	struct vsoc_usb_shm *shm;
	struct vsoc_usb_controller_regs *csr;
	struct list_head *urbp_list_head;
	struct urbp *urbp;
	struct urb *urb;
	void *ubuf;
	struct vsoc_usb_packet_buffer *buf;
	unsigned long hcd_lock_flags, shm_lock_flags;
	unsigned long gadget_intr = 0, hcd_data_len;
	int rc = 0, inform_gadget = 0, walk_urbp_list = 0;

	dbg("%s handling ep-%d control transaction\n", __func__, ep_num);

	shm = vsoc_hcd->shm;
	csr = &shm->csr;

	BUG_ON(dir == NONE);

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, hcd_lock_flags);
	/*
	 * Control transfers always gets queued on the OUT list.
	 */
	urbp_list_head = &vsoc_hcd->urbp_list_out[ep_num];

	/*
	 * TODO(romitd): Introduce a new function to avoid goto try_next;
	 */
try_next:
	if (list_empty(urbp_list_head)) {
		if (!walk_urbp_list) {
			printk(KERN_WARNING "%s Empty list on ep[%d]\n",
			       __func__, ep_num);
			rc = -EFAULT;
		}
		goto unlock_hcd;
	}

	urbp = list_first_entry(urbp_list_head, struct urbp, urbp_list);
	urb = urbp->urb;
	buf = (dir == OUT) ? &shm->ep_out_buf[ep_num] : &shm->ep_in_buf[ep_num];

	spin_lock_irqsave(&shm->shm_lock, shm_lock_flags);
	/*
	 * Handle different states.
	 * TODO(romitd): Because of the many transaction states, we have many
	 * if then blocks. This may be refactored.
	 */
	if (urbp->transaction_state == CONTROL_SETUP_STATE) {
		struct usb_ctrlrequest *setup =
			(struct usb_ctrlrequest *)urb->setup_packet;
		dbg("%s CONTROL_SETUP_STATE\n", __func__);
		/* USB HS Setup packet is always 8 bytes */
		memcpy(buf->buffer, setup, sizeof(struct usb_ctrlrequest));
		buf->gadget_data_len = 0;
		buf->hcd_data_len = sizeof(struct usb_ctrlrequest);
		inform_gadget = 1;
		gadget_intr = H2G_CONTROL_SETUP;
		urbp->transaction_state = CONTROL_SETUP_ACK_WAIT_STATE;
		set_bit(URB_IN_FLIGHT_BIT, &urbp->transaction_state);
	} else if (urbp->transaction_state == CONTROL_OUT_START_STATE) {
		inform_gadget = 1;
		gadget_intr = H2G_CONTROL_DATA_OUT;
		hcd_data_len = urb->transfer_buffer_length -
					urb->actual_length;
		WARN_ON(buf->gadget_data_len != sizeof(struct usb_ctrlrequest));
		buf->hcd_data_len =
			min(hcd_data_len,
				(unsigned long) VSOC_ENDPOINT_BUFFER_SIZE);
		dbg("%s sending %lu bytes to gadget\n", __func__,
						       buf->hcd_data_len);
		ubuf = urb->transfer_buffer + urb->actual_length;
		memcpy(buf->buffer, ubuf, buf->hcd_data_len);
		buf->gadget_data_len = 0;
		urbp->transaction_state = CONTROL_OUT_STATE;
		set_bit(URB_IN_FLIGHT_BIT, &urbp->transaction_state);
	} else if (urbp->transaction_state == CONTROL_OUT_STATE) {
		urb->actual_length += buf->gadget_data_len;
		dbg("%s gadget copied %lu bytes\n", __func__, buf->gadget_data_len);
		if (urb->transfer_buffer_length == urb->actual_length) {
			urbp->transaction_state = TRANSFER_COMPLETE_STATE;
			buf->hcd_data_len = buf->gadget_data_len = 0;
		} else {
			inform_gadget = 1;
			gadget_intr = H2G_CONTROL_DATA_OUT;
			hcd_data_len = urb->transfer_buffer_length -
						urb->actual_length;
			buf->hcd_data_len =
				min(hcd_data_len,
				  (unsigned long) VSOC_ENDPOINT_BUFFER_SIZE);
			dbg("%s sending %lu bytes to gadget\n", __func__,
							buf->hcd_data_len);
			ubuf = urb->transfer_buffer + urb->actual_length;
			memcpy(buf->buffer, ubuf, buf->hcd_data_len);
			buf->gadget_data_len = 0;
			urbp->transaction_state = CONTROL_OUT_STATE;
			set_bit(URB_IN_FLIGHT_BIT, &urbp->transaction_state);
		}
	} else if (urbp->transaction_state == CONTROL_IN_START_STATE) {
		dbg("%s CONTROL_IN_START_STATE\n", __func__);
		inform_gadget = 1;
		gadget_intr = H2G_CONTROL_DATA_IN;
		buf->gadget_data_len = 0;
		hcd_data_len = urb->transfer_buffer_length -
				urb->actual_length;
		buf->hcd_data_len =
			min(hcd_data_len,
			    (unsigned long)VSOC_ENDPOINT_BUFFER_SIZE);
		dbg("%s expecting %lu bytes from gadget\n",__func__,
			 buf->hcd_data_len);
		urbp->transaction_state = CONTROL_IN_STATE;
	} else if (urbp->transaction_state == CONTROL_IN_STATE) {
		int is_short_transaction = 0;
		int max_packet_size;
		dbg("%s Got %lu bytes from gadget\n", __func__, buf->gadget_data_len);
		ubuf = urb->transfer_buffer + urb->actual_length;
		memcpy(ubuf, buf->buffer, buf->gadget_data_len);
		urb->actual_length += buf->gadget_data_len;
		max_packet_size = le16_to_cpu(urb->ep->desc.wMaxPacketSize);
		BUG_ON(!max_packet_size);
		/*
		 * Gadget will send data in multiples of wMaxPackeSize for that
		 * endpoint. If it doesn't its a short packet and signals no
		 * more data from gadget for this URB request. Proceed to retire
		 * this URB.
		 */
		is_short_transaction = (buf->gadget_data_len % max_packet_size);
		if ((urb->transfer_buffer_length == urb->actual_length) ||
		    is_short_transaction) {
			urbp->transaction_state = TRANSFER_COMPLETE_STATE;
			buf->hcd_data_len = buf->gadget_data_len = 0;
		} else {
			hcd_data_len = urb->transfer_buffer_length -
					urb->actual_length;
			buf->hcd_data_len =
				min(hcd_data_len,
				    (unsigned long)VSOC_ENDPOINT_BUFFER_SIZE);
			buf->gadget_data_len = 0;
			dbg("%s expecting %lu bytes from gadget\n",__func__,
			    buf->hcd_data_len);
			inform_gadget = 1;
			gadget_intr = H2G_CONTROL_DATA_IN;
		}
		/*
		 * TODO(romitd): Handle URB_ZERO_PACKET.
		 */
	}

	spin_unlock_irqrestore(&shm->shm_lock, shm_lock_flags);
	if (urbp->transaction_state == TRANSFER_COMPLETE_STATE) {
		vsoc_hcd_giveback_urb(vsoc_hcd, urbp, 0);
		kick_gadget(vsoc_hcd, ep_num, OUT, H2G_CONTROL_STATUS);
		walk_urbp_list = 1;
		goto try_next;
	}
unlock_hcd:
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, hcd_lock_flags);

	if (inform_gadget)
		rc = kick_gadget(vsoc_hcd, ep_num, dir, gadget_intr);

	return rc;
}

static int vsoc_hcd_handle_control_transaction(struct vsoc_hcd *vsoc_hcd,
	    int ep_num, unsigned long reason)
{
	struct list_head *urbp_list_head;
	struct urbp *urbp;
	struct urb *urb;
	unsigned long flags;
	int dir = NONE;
	int initiate_transfer = 0, rc = 0;

	dbg("%s\n", __func__);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);

	urbp_list_head = &vsoc_hcd->urbp_list_out[ep_num];
	if (list_empty(urbp_list_head)) {
		printk(KERN_WARNING "Control Transaction event on ep[%d] "
		       "but empty list in %s\n", ep_num, __func__);
		rc = -EFAULT;
		goto unlock;
	}

	urbp = list_first_entry(urbp_list_head, struct urbp, urbp_list);
	urb = urbp->urb;
	BUG_ON(ep_num != usb_pipeendpoint(urb->pipe));

	if (test_and_clear_bit(G2H_CONTROL_DATA_NAK, &reason))
		urbp->nak = 1;

	/*
	 * SETUP transaction of Control transfer.
	 */
	if (test_and_clear_bit(H2G_CONTROL_SETUP, &reason)) {
		dbg("%s H2G_CONTROL_SETUP\n", __func__);
		/* Initiate transfer only if this is the solitary URB */
		if (list_is_singular(urbp_list_head)) {
			hcd_scrub_ep_buffer(vsoc_hcd, ep_num, OUT);
			initiate_transfer = 1;
			urbp->transaction_state = CONTROL_SETUP_STATE;
			dir = OUT;
		}
	}

	/*
	 * SETUP ack from Gadget.
	 */
	if (test_and_clear_bit(G2H_CONTROL_SETUP_ACK, &reason)) {
		dbg("%s G2H_CONTROL_SETUP_ACK\n", __func__);
		BUG_ON((urbp->transaction_state &
			~(1UL << URB_IN_FLIGHT_BIT)) !=
			CONTROL_SETUP_ACK_WAIT_STATE);
		clear_bit(URB_IN_FLIGHT_BIT, &urbp->transaction_state);
		urbp->transaction_state = usb_pipein(urb->pipe) ?
						CONTROL_IN_START_STATE :
						CONTROL_OUT_START_STATE;
		initiate_transfer = 1;
		dir = usb_pipein(urb->pipe) ? IN : OUT;
	}

	/*
	 * Gadget is ready for IN.
	 */
	if (test_and_clear_bit(G2H_CONTROL_DATA_IN, &reason)) {
		dbg("%s G2H_CONTROL_SETUP_IN\n", __func__);
		initiate_transfer = 1;
		dir = IN;
	}

	/*
	 * Control Data OUT ack from gadget.
	 */
	if (test_and_clear_bit(G2H_CONTROL_DATA_OUT_ACK, &reason)) {
		BUG_ON((urbp->transaction_state &
			~(1UL << URB_IN_FLIGHT_BIT)) !=
			CONTROL_OUT_STATE);
		clear_bit(URB_IN_FLIGHT_BIT, &urbp->transaction_state);
		dbg("%s G2H_CONTROL_DATA_OUT_ACK", __func__);
		initiate_transfer = 1;
		dir = OUT;
	}
unlock:
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	if (initiate_transfer)
		return vsoc_hcd_ep_control_transaction(vsoc_hcd, ep_num, dir);
	return rc;
}

static int vsoc_hcd_handle_ep_rx_events(struct vsoc_hcd *vsoc_hcd, int ep_num)
{
	struct list_head *urbp_list_head;
	struct urbp *urbp;
	struct urb *urb;
	unsigned long flags, reason = 0;
	int rc = 0, is_control_event = 0;

	dbg("%s\n", __func__);
	dbg("   handling ep-%d-IN\n", ep_num);

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);

	if (test_and_clear_bit(G2H_CONTROL_DATA_IN,
		&vsoc_hcd->rx_action_reason[ep_num])) {
		set_bit(G2H_CONTROL_DATA_IN, &reason);
		is_control_event = 1;
	}
	if (test_and_clear_bit(G2H_CONTROL_DATA_NAK,
		&vsoc_hcd->rx_action_reason[ep_num])) {
		set_bit(G2H_CONTROL_DATA_NAK, &reason);
		is_control_event = 1;
	}

	urbp_list_head = is_control_event ? &vsoc_hcd->urbp_list_out[ep_num] :
					    &vsoc_hcd->urbp_list_in[ep_num];

	if (list_empty(urbp_list_head)) {
		printk(KERN_WARNING "%s event on ep[%d] but empty list in %s\n",
		       is_control_event ? "Control" : "Rx", ep_num, __func__);
		rc = -EFAULT;
		goto unlock;
	}

	urbp = list_first_entry(urbp_list_head, struct urbp, urbp_list);
	urb = urbp->urb;
	BUG_ON(ep_num != usb_pipeendpoint(urb->pipe));

	if (test_and_clear_bit(G2H_TRANSACTION_ERR,
		&vsoc_hcd->rx_action_reason[ep_num])) {
		dbg("%s G2H_TRANSACTION_ERR\n", __func__);
		urb->actual_length = 0;
		try_hcd_scrub_ep_buffer_by_urb(vsoc_hcd, urbp);
		vsoc_hcd_giveback_urb(vsoc_hcd, urbp, -EPROTO);
		rc = -ENXIO;
		/*
		 *
		 * TODO(romitd): Kick off the transfer for the next urb.
		 */
		goto unlock;
	}

	if (test_and_clear_bit(G2H_DATA_NAK,
		&vsoc_hcd->rx_action_reason[ep_num])) {
		set_bit(G2H_DATA_NAK, &reason);
	}

unlock:
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	if (rc) return rc;

	if (is_control_event) {
		BUG_ON(!usb_pipecontrol(urb->pipe));
		rc = vsoc_hcd_handle_control_transaction(vsoc_hcd, ep_num,
							 reason);
	}
	return rc;
}

static int vsoc_hcd_handle_ep_tx_events(struct vsoc_hcd *vsoc_hcd, int ep_num)
{
	struct list_head *urbp_list_head;
	struct urbp *urbp;
	struct urb *urb;
	unsigned long flags, reason = 0;
	int rc = 0, is_control_event = 0;

	dbg("%s\n", __func__);
	dbg("   handling ep-%d-OUT\n", ep_num);

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	urbp_list_head = &vsoc_hcd->urbp_list_out[ep_num];
	if (list_empty(urbp_list_head)) {
		printk(KERN_WARNING "Tx event on ep[%d] but empty list in %s\n",
		       ep_num, __func__);
		rc = -EFAULT;
		goto unlock;
	}

	urbp = list_first_entry(urbp_list_head, struct urbp, urbp_list);
	urb = urbp->urb;
	BUG_ON(ep_num != usb_pipeendpoint(urb->pipe));

	if (test_and_clear_bit(G2H_TRANSACTION_ERR,
		&vsoc_hcd->tx_action_reason[ep_num])) {
		dbg("%s G2H_TRANSACTION_ERR\n", __func__);
		urb->actual_length = 0;
		try_hcd_scrub_ep_buffer_by_urb(vsoc_hcd, urbp);
		vsoc_hcd_giveback_urb(vsoc_hcd, urbp, -EPROTO);
		rc = -ENXIO;
		/*
		 * TODO(romitd): Kick off the transfer for the next urb.
		 */
		goto unlock;
	}

	/* Handle Control transfers specially */
	if (test_and_clear_bit(H2G_CONTROL_SETUP,
			       &vsoc_hcd->tx_action_reason[ep_num])) {
		set_bit(H2G_CONTROL_SETUP, &reason);
		is_control_event  = 1;
	}
	if (test_and_clear_bit(G2H_CONTROL_SETUP_ACK,
			       &vsoc_hcd->tx_action_reason[ep_num])) {
		set_bit(G2H_CONTROL_SETUP_ACK, &reason);
		is_control_event = 1;
	}
	if (test_and_clear_bit(G2H_CONTROL_DATA_OUT_ACK,
		&vsoc_hcd->tx_action_reason[ep_num])) {
		set_bit(G2H_CONTROL_DATA_OUT_ACK, &reason);
		is_control_event = 1;
	}
	if (test_and_clear_bit(G2H_CONTROL_DATA_NAK,
			       &vsoc_hcd->tx_action_reason[ep_num])) {
		set_bit(G2H_CONTROL_DATA_NAK, &reason);
		is_control_event = 1;
	}
	if (test_and_clear_bit(G2H_DATA_NAK,
		&vsoc_hcd->tx_action_reason[ep_num])) {
		set_bit(G2H_DATA_NAK, &reason);
	}

unlock:
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	if (rc) return rc;

	if (is_control_event) {
		BUG_ON(!usb_pipecontrol(urb->pipe));
		rc = vsoc_hcd_handle_control_transaction(vsoc_hcd, ep_num,
							 reason);
	} else {
		dbg("%s TODO(romitd): Tx data event", __func__);
	}

	return rc;
}

/*
 * Called from vsoc_hcd_tx. The main Tx logic.
 */
static int _vsoc_hcd_tx(struct vsoc_hcd *vsoc_hcd)
{
	unsigned long flags, tx_action;
	int status, i;

	set_current_state(TASK_RUNNING);
	try_to_freeze();
	set_current_state(TASK_INTERRUPTIBLE);
	dbg("%s before sleep\n", __func__);
	wait_event_interruptible(vsoc_hcd->txq,
				 vsoc_hcd->tx_action || kthread_should_stop());
	dbg("%s after wakeup\n", __func__);
	if (kthread_should_stop())
		return 1;

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	tx_action = vsoc_hcd->tx_action;
	vsoc_hcd->tx_action = 0;
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);

	/*
	 * Go through the pending work per endpoint.
	 */
	status = 0;
	for (i = 0; i < VSOC_NUM_ENDPOINTS && tx_action; i++) {
		if (test_and_clear_bit(i, &tx_action))
			status = vsoc_hcd_handle_ep_tx_events(vsoc_hcd, i);
		if (status) {
			printk(KERN_INFO "%s, Error in ep-%d OUT\n",__func__,
			       i);
			status = 0;
		}
	}
	if (tx_action)
		printk(KERN_ERR "Unhandled tx_action[%lu] in %s\n", tx_action,
		       __func__);
	return 0;
}

static int vsoc_hcd_tx(void *data)
{
	struct vsoc_hcd *vsoc_hcd = (struct vsoc_hcd *)data;
	dbg("%s\n", __func__);
#ifdef DEBUG
	if (vsoc_hcd->shm->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}
#endif
	set_freezable();

	for(;;)
		if (_vsoc_hcd_tx(vsoc_hcd)) break;

	return 0;
}

static int vsoc_hcd_handle_controller_events(struct vsoc_hcd *vsoc_hcd,
					     unsigned long action)
{
	int rc = 0;

	dbg("%s\n", __func__);
	if (test_and_clear_bit(G2H_RESET_COMPLETE, &action)) {
		del_timer(&vsoc_hcd->port_connection_timer);
		dbg("%s GADGET_RESET_COMPLETE\n", __func__);
	}

	if (test_and_clear_bit(G2H_CONN_CHANGE, &action)) {
		dbg("%s GADGET_CONN_CHANGE\n", __func__);
		handle_gadget_conn_change(vsoc_hcd);
	}

	if (action)
		printk(KERN_ERR "Unhandled controller_action[%lu] in %s",
		       action, __func__);

	return rc;
}

/*
 * Called from vsoc_hcd_rx. The main Rx logic.
 */
static int _vsoc_hcd_rx(struct vsoc_hcd *vsoc_hcd)
{
	unsigned long controller_action, rx_action, flags;
	int status, i;

	set_current_state(TASK_RUNNING);
	try_to_freeze();
	set_current_state(TASK_INTERRUPTIBLE);
	dbg("%s before sleep\n", __func__);
	wait_event_interruptible(vsoc_hcd->rxq,
				 vsoc_hcd->controller_action ||
				 vsoc_hcd->rx_action ||
				 kthread_should_stop());
	dbg("%s after wakeup\n", __func__);
	if (kthread_should_stop())
		return 1;

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	controller_action = vsoc_hcd->controller_action;
	vsoc_hcd->controller_action = 0;
	rx_action = vsoc_hcd->rx_action;
	vsoc_hcd->rx_action = 0;
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);

	vsoc_hcd_handle_controller_events(vsoc_hcd, controller_action);
	/*
	 * Go through the pending work per endpoint.
	 */
	status = 0;
	for (i = 0; i < VSOC_NUM_ENDPOINTS && rx_action; i++) {
		if (test_and_clear_bit(i, &rx_action))
			status = vsoc_hcd_handle_ep_rx_events(vsoc_hcd, i);
		if (status) {
			printk(KERN_INFO "%s Error in ep-%d IN\n", __func__, i);
			status = 0;
		}
	}
	if (rx_action)
		printk(KERN_ERR "Unhandled rx_action[%lu] in %s\n", rx_action,
		       __func__);
	return 0;
}

/*
 * Handles rx_actions along with non-ep specific actions(aka controller actions)
 */
static int vsoc_hcd_rx(void *data)
{
	struct vsoc_hcd *vsoc_hcd = (struct vsoc_hcd *)data;

	dbg("%s\n", __func__);
#ifdef DEBUG
	if (vsoc_hcd->shm->magic != VSOC_USB_SHM_MAGIC)
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
	else {
		dbg("%s usb shm magic matched\n", __func__);
	}
#endif
	set_freezable();

	for(;;)
		if (_vsoc_hcd_rx(vsoc_hcd)) break;

	return 0;
}

static void device_connection_timeout(unsigned long arg)
{
	struct vsoc_hcd *vsoc_hcd;
	unsigned long flags;

	dbg("%s\n", __func__);
	vsoc_hcd = hcd_to_vsoc_hcd((struct usb_hcd *) arg);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	printk(KERN_INFO "Did not detect Gadget pullup. Disconnecting!\n");
	vsoc_hcd->port_status &= ~USB_PORT_STAT_CONNECTION;
	vsoc_hcd->port_status |= (USB_PORT_STAT_C_CONNECTION << 16);
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	if ((vsoc_hcd->port_status & PORT_C_MASK) != 0)
		usb_hcd_poll_rh_status((struct usb_hcd *) arg);
}

/*
 * Note: We depend on the shm layer to initialize the shared memory to 0 (at the
 * beginning. That way only when gadget is pulled up, the corresponding bit in
 * shared memory is set.
 */
static int is_gadget_connected(struct vsoc_hcd *vsoc_hcd)
{
	struct vsoc_usb_shm *shm = vsoc_hcd->shm;
	struct vsoc_usb_controller_regs *csr = &shm->csr;
	unsigned long flags;
	int connected = 0;

	spin_lock_irqsave(&shm->shm_lock, flags);
	if (test_bit(GADGET_PULLUP, &csr->gadget_reg.status))
		connected = 1;
	spin_unlock_irqrestore(&shm->shm_lock, flags);

	return connected;
}

static int vsoc_hcd_setup(struct usb_hcd *hcd)
{
	struct vsoc_hcd *vsoc_hcd;
	int i;

	dbg("%s\n", __func__);

	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_init(&vsoc_hcd->vsoc_hcd_lock);

	for (i = 0; i < VSOC_NUM_ENDPOINTS; i++) {
		INIT_LIST_HEAD(&vsoc_hcd->urbp_list_in[i]);
		INIT_LIST_HEAD(&vsoc_hcd->urbp_list_out[i]);
	}

	init_timer(&vsoc_hcd->port_connection_timer);
	vsoc_hcd->port_connection_timer.function = device_connection_timeout;
	vsoc_hcd->port_connection_timer.data = (unsigned long)hcd;
	hcd->power_budget = POWER_BUDGET;
	hcd->uses_new_polling = 1;

	init_waitqueue_head(&vsoc_hcd->txq);
	init_waitqueue_head(&vsoc_hcd->rxq);

	tasklet_init(&vsoc_hcd->hcd_tasklet, hcd_tasklet,
		     (unsigned long)vsoc_hcd);

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
	struct vsoc_usb_shm *shm;
	struct vsoc_usb_controller_regs *csr;
	unsigned long hcd_lock_flags, shm_lock_flags;
	int rc = 0;

	dbg("%s\n", __func__);

	vsoc_hcd = hcd_to_vsoc_hcd(hcd);

	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, hcd_lock_flags);
	/*
	 * We are not ready for Super Speed yet.
	 */
	if (!usb_hcd_is_primary_hcd(hcd)) {
		rc = -ENODEV;
		goto unlock;
	}

	vsoc_hcd->gadget_connected = is_gadget_connected(vsoc_hcd);
	vsoc_hcd->controller_action = vsoc_hcd->rx_action =
			vsoc_hcd->tx_action = 0;
	memset(vsoc_hcd->rx_action_reason, 0,
	       sizeof(vsoc_hcd->rx_action_reason));
	memset(vsoc_hcd->tx_action_reason, 0,
	       sizeof(vsoc_hcd->tx_action_reason));

	shm = vsoc_hcd->shm;
	csr = &shm->csr;

	spin_lock_irqsave(&shm->shm_lock, shm_lock_flags);
	/*
	 * clear HCD csr area & the EP buffers structures.
	 */
	memset(&csr->hcd_reg, 0, sizeof(csr->hcd_reg));
	memset(csr->hcd_ep_in_reg, 0, sizeof(csr->hcd_ep_in_reg));
	memset(csr->hcd_ep_out_reg, 0, sizeof(csr->hcd_ep_out_reg));

	/*
	 * TODO (romitd): Should we really cleanup the buffers here?
	 */
	memset(shm->ep_in_buf, 0, sizeof(shm->ep_in_buf));
	memset(shm->ep_out_buf, 0, sizeof(shm->ep_out_buf));

	spin_unlock_irqrestore(&shm->shm_lock, shm_lock_flags);

	vsoc_hcd->tx_thread = kthread_run(vsoc_hcd_tx, (void *)vsoc_hcd,
					  "vsoc_h_tx/%d",
					  hcd_to_bus(hcd)->busnum);
	if (IS_ERR(vsoc_hcd->tx_thread)) {
		rc = -ENODEV;
		goto unlock;
	}

	vsoc_hcd->rx_thread = kthread_run(vsoc_hcd_rx, (void *)vsoc_hcd,
					  "vsoc_h_rx/%d",
					  hcd_to_bus(hcd)->busnum);
	if (IS_ERR(vsoc_hcd->rx_thread)) {
		kthread_stop(vsoc_hcd->tx_thread);
		vsoc_hcd->tx_thread = NULL;
		rc = -ENODEV;
		goto unlock;
	}

	hcd->state = HC_STATE_RUNNING;

unlock:
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, hcd_lock_flags);

	return rc;
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
	u8 ep_num, is_in;
	int rc;

	dbg("%s\n", __func__);
	urbp = kmalloc(sizeof(*urbp), mem_flags);
	if (!urbp)
		return -ENOMEM;
	urbp->urb = urb;
	urbp->transaction_state = INIT_STATE;

	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	rc = usb_hcd_link_urb_to_ep(hcd, urb);
	if (rc) {
		kfree(urbp);
		goto unlock;
	}

	if (!vsoc_hcd->udev) {
		vsoc_hcd->udev = urb->dev;
		usb_get_dev(vsoc_hcd->udev);
	} else if (unlikely(vsoc_hcd->udev != urb->dev))
		printk(KERN_ERR "usb device address has changed!\n");

	ep_num = usb_pipeendpoint(urb->pipe);
	BUG_ON(ep_num >= VSOC_NUM_ENDPOINTS);
	is_in = usb_pipein(urb->pipe);
	if (usb_pipecontrol(urb->pipe))
		dbg("  control transfer on ep-%d\n", ep_num);
	else
		dbg("  ep-%d-%s\n", ep_num, is_in ? "IN" : "OUT");

	/*
	 * Control transfers are special, it has a  setup phase (OUT), followed
	 * by an optional IN or OUT transactions and then a status phase.
	 */
	if (usb_pipecontrol(urb->pipe)) {
		list_add_tail(&urbp->urbp_list,
			      &vsoc_hcd->urbp_list_out[ep_num]);
		set_bit(ep_num, &vsoc_hcd->tx_action);
		/* All control transfers start at the setup stage */
		set_bit(H2G_CONTROL_SETUP,
			&vsoc_hcd->tx_action_reason[ep_num]);
		wake_up_interruptible(&vsoc_hcd->txq);
	} else if (is_in) {
		list_add_tail(&urbp->urbp_list,
			      &vsoc_hcd->urbp_list_in[ep_num]);
		set_bit(ep_num, &vsoc_hcd->rx_action);
		set_bit(H2G_DATA_IN,
			&vsoc_hcd->rx_action_reason[ep_num]);
		wake_up_interruptible(&vsoc_hcd->rxq);
	} else {
		list_add_tail(&urbp->urbp_list,
			      &vsoc_hcd->urbp_list_out[ep_num]);
		set_bit(ep_num, &vsoc_hcd->tx_action);
		set_bit(H2G_DATA_OUT,
			&vsoc_hcd->tx_action_reason[ep_num]);
		wake_up_interruptible(&vsoc_hcd->txq);
	}
unlock:
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	return rc;
}

static int vsoc_hcd_urb_dequeue(struct usb_hcd *hcd, struct urb *urb,
				int status)
{
	struct vsoc_hcd *vsoc_hcd;
	struct urbp *urbp, *tmp;
	unsigned long flags;
	u8 ep_num, is_out;
	struct list_head *urbp_list;
	int rc;

	dbg("%s\n", __func__);
	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	ep_num = usb_pipeendpoint(urb->pipe);
	BUG_ON(ep_num >= VSOC_NUM_ENDPOINTS);
	is_out = usb_pipeout(urb->pipe);
	if (usb_pipecontrol(urb->pipe))
		dbg("  control transfer on ep-%d\n", ep_num);
	else
		dbg("  ep-%d-%s\n", ep_num, is_out ? "OUT" : "IN");

	urbp_list = (usb_pipecontrol(urb->pipe) || is_out) ?
			&vsoc_hcd->urbp_list_out[ep_num] :
			&vsoc_hcd->urbp_list_in[ep_num];

	list_for_each_entry_safe(urbp, tmp, urbp_list, urbp_list) {
		if (urb == urbp->urb) {
			try_hcd_scrub_ep_buffer_by_urb(vsoc_hcd, urbp);
			rc = usb_hcd_check_unlink_urb(hcd, urb, status);
			if (!rc && !list_empty(urbp_list)) {
				dbg("  found urb. freeing\n");
				list_del(&urbp->urbp_list);
				kfree(urbp);
				usb_hcd_unlink_urb_from_ep(hcd, urb);
				usb_hcd_giveback_urb(hcd, urb, status);
			}
			goto done;
		}
	}
done:
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	return rc;
}

/*
 * TODO (romitd): For isoch transfers.
 */
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
	BUG_ON(!spin_is_locked(&vsoc_hcd->vsoc_hcd_lock));
	if ((vsoc_hcd->port_status & USB_PORT_STAT_POWER) == 0) {
		vsoc_hcd->port_status = 0;
	} else if (vsoc_hcd->gadget_connected) {
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

	BUG_ON(!spin_is_locked(&vsoc_hcd->vsoc_hcd_lock));
	vsoc_hcd->active = 0;
	dbg("  vsoc_data:\n");
	dbg("  vsoc_hcd_rh_state: %d\n", vsoc_hcd->rh_state);
	dbg("  vsoc_hcd_port_status: 0x%08x\n", vsoc_hcd->port_status);
	dbg("  vsoc_hcd_old_status: 0x%08x\n", vsoc_hcd->old_status);
	dbg("  vsoc_hcd_timeout: 0x%lx\n", vsoc_hcd->timeout);
	dbg("  vsoc_hcd_udev: %p\n", vsoc_hcd->udev);
	dbg("  vsoc_hcd_active: %d\n", vsoc_hcd->active);
	dbg("  vsoc_hcd_old_active: %d\n", vsoc_hcd->old_active);
	dbg("  vsoc_hcd_resuming: %d\n", vsoc_hcd->resuming);

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
			if(!kick_gadget(vsoc_hcd, -1, NONE, H2G_RESET)) {
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
		} else if (disconnect) {
			dbg("%s disconnect in port status\n", __func__);
			kick_gadget(vsoc_hcd, -1, NONE, H2G_DISCONNECT);
		}
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
	int rc = 0;

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
		rc = 1;
		if (vsoc_hcd->rh_state == VSOC_HCD_RH_SUSPENDED)
			usb_hcd_resume_root_hub(hcd);
	}

done:
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);
	return rc;
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
			vsoc_hcd->port_status = 0;
			vsoc_hcd->resuming = 0;
			break;
		case USB_PORT_FEAT_ENABLE:
			vsoc_hcd->port_status &= ~USB_PORT_STAT_HIGH_SPEED;
			/* Fall through */
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
			vsoc_hcd->port_status |= (USB_PORT_STAT_C_SUSPEND
							<< 16);
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
		case USB_PORT_FEAT_RESET:
			dbg("%s %s:%s\n", __func__, "SetPortFeature",
			    "USB_PORT_FEAT_RESET");
			vsoc_hcd->port_status &= ~(USB_PORT_STAT_ENABLE |
						   USB_PORT_STAT_LOW_SPEED |
						   USB_PORT_STAT_HIGH_SPEED);
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

static int handle_gadget_connect(struct vsoc_hcd *vsoc_hcd)
{
	unsigned long flags;
	int rc = 0;

	dbg("%s\n", __func__);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	vsoc_hcd->gadget_connected = 1;
	vsoc_hcd->port_status |= USB_PORT_STAT_CONNECTION |
		(1 << USB_PORT_FEAT_C_CONNECTION);
	vsoc_hcd->port_status |= USB_PORT_STAT_HIGH_SPEED;
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);

	usb_hcd_poll_rh_status(vsoc_hcd_to_hcd(vsoc_hcd));
	return rc;
}

static int handle_gadget_disconnect(struct vsoc_hcd *vsoc_hcd)
{
	unsigned long flags;
	int rc = 0;

	dbg("%s\n", __func__);
	spin_lock_irqsave(&vsoc_hcd->vsoc_hcd_lock, flags);
	vsoc_hcd->gadget_connected = 0;
	vsoc_hcd->port_status = USB_PORT_STAT_POWER;
	vsoc_hcd->port_status |= (1 << USB_PORT_FEAT_C_CONNECTION);
	vsoc_hcd->udev = NULL;
	spin_unlock_irqrestore(&vsoc_hcd->vsoc_hcd_lock, flags);

	usb_hcd_poll_rh_status(vsoc_hcd_to_hcd(vsoc_hcd));
	return rc;
}

static int handle_gadget_conn_change(struct vsoc_hcd *vsoc_hcd)
{
	int rc;

	if (is_gadget_connected(vsoc_hcd))
		rc = handle_gadget_connect(vsoc_hcd);
	else
		rc = handle_gadget_disconnect(vsoc_hcd);

	return rc;
}

static int vsoc_hcd_bus_suspend(struct usb_hcd *hcd)
{
	struct vsoc_hcd *vsoc_hcd;
	int rc = 0;

	dbg("%s\n", __func__);
	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	spin_lock_irq(&vsoc_hcd->vsoc_hcd_lock);
	vsoc_hcd->rh_state = VSOC_HCD_RH_SUSPENDED;
	vsoc_set_link_state(vsoc_hcd);
	hcd->state = HC_STATE_SUSPENDED;
	spin_unlock_irq(&vsoc_hcd->vsoc_hcd_lock);
	return rc;
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
};

int vsoc_usb_hcd_probe(struct platform_device *pdev)
{
	struct usb_hcd *hcd;
	struct vsoc_hcd *vsoc_hcd;
	struct vsoc_usb_shm *shm;
	int rc;

	dbg("%s\n", __func__);
	dev_info(&pdev->dev, "%s, driver " DRIVER_VERSION "\n", driver_desc);

	shm = *((void **)dev_get_platdata(&pdev->dev));
	if (!shm) {
		dbg("%s couldn't get pointer to usb shared mem\n", __func__);
		return -ENODEV;
	}

	if (shm->magic != VSOC_USB_SHM_MAGIC) {
		printk(KERN_ERR "%s usb shm magic mismatch\n", __func__);
		return -EFAULT;
	} else
		dbg("%s usb shm magic matched\n", __func__);

	/*
	 * This HCD essentially would copy bytes from one region of memory to a
	 * different region of memory. We do not need DMA.
	 */
	pdev->dev.dma_mask = 0;

	hcd = usb_create_hcd(&vsoc_hcd_driver, &pdev->dev,
				dev_name(&pdev->dev));
	if (!hcd)
		return -ENOMEM;

	vsoc_hcd = hcd_to_vsoc_hcd(hcd);
	vsoc_hcd->hcd = hcd;
	vsoc_hcd->shm = shm;
	hcd->has_tt = 1;

	rc = vsoc_usb_register_g2h_ipi(kick_hcd_internal,
				       (unsigned long)vsoc_hcd);
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
	rc = usb_add_hcd(hcd, 0, 0);
	if (!rc)
		return 0;

	vsoc_usb_unregister_g2h_ipi();
put_usb2_hcd:
	usb_put_hcd(hcd);

	return rc;
}

int vsoc_usb_hcd_remove(struct platform_device *pdev)
{
	struct usb_hcd *hcd;

	dbg("%s\n", __func__);
	hcd = platform_get_drvdata(pdev);
	vsoc_usb_unregister_g2h_ipi();
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
