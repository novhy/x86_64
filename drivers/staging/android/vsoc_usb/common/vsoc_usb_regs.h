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

#ifndef __VSOC_USB_REGS_H
#define __VSOC_USB_REGS_H

#include <linux/spinlock.h>

/*
 * Shared memory holds USB packet per Endpoint.
 * To start with, things are simple.
 * The USB packet buffers reside in shared memory (One per Endpoint, per
 * direction). The size of a single packet buffer is 16KiB. (The size is based
 * on ADB packet size, which is the main use case for this driver).
 *
 * The following is an high level overview of an USB OUT transfer.
 * A transfer is broken down into transactions, roughly mimicking the different
 * phases in an USB transfer.
 *
 * Gadget driver queues an usb_request to the UCD. HCD submits an URB.
 * The above two steps are the corresponding USB transfer submissions.
 * The data is broken down into USB ep packet buffer sized chunks by the HCD
 * and copied into the packet buffer (corresponding to the ep).
 * The gadget controller is notified of the new packet (throuh IPI). It copies
 * the packet from shared memory into usb_request buffer and notifies success or
 * failure to the HCD (through IPI).
 * Once entire URB data is copied by UCD, the HCD completes the URB request.
 * Similarly, the UDC completes the usb_request when the entire data represented
 * by the usb_request is transferred.
 * On error, the URB/usb_request is also considered compete but with appropriate
 * status code set to notify the upper layers about the error condition.
 * IN transfers are similar (except for the direction ofcourse).
 *
 * Also, the data length for a URB may be different from that of the
 * corresponding usb_request. This means that there may be 'N' completions of
 * usb_request(s) for every single completion of URB requests (or vice-versa).
 */


#define VSOC_NUM_ENDPOINTS		3
#define VSOC_ENDPOINT_BUFFER_SIZE	(16 * (1 << 10))
#define VSOC_MIN_BUFFER_SIZE		(1 << 10)

enum intr_bitpos {
	/*
	 * Events raised to get HCD's attention. Originates in gadget.
	 * Before raising the (virtual) HCD interrupt one of these bits should
	 * be set.
	 */
	G2H_RESET_COMPLETE = 0x0, /* Gadget reset complete */
	G2H_CONN_CHANGE, /* Gadget connection state changed */
	G2H_CONTROL_SETUP_ACK, /* Gadget Ack's SETUP packet */
	G2H_TRANSACTION_ERR, /* Gadget raises Error on an EP */
	G2H_CONTROL_DATA_IN, /* Next stage of Control transfer is IN */
	G2H_DATA_NAK, /* Gadget NAK's a request */
	G2H_CONTROL_DATA_NAK, /* Gadget NAK's a control data request */
	G2H_CONTROL_DATA_OUT_ACK, /* Gadget Ack's Control OUT */
	G2H_CONTROL_STATUS_ACK, /* Gadget Ack's Control STATUS transaction */

	/*
	 * Events raised to get Gadgets's attention. Originates in host.
	 * Before raising the (virtual) interrupt on of these bits should be
	 * set.
	 */
	H2G_RESET, /* Reset gadget controller and all its end points. */
	H2G_DISCONNECT, /* HCD disconnected (powering down hub port). */
	H2G_CONTROL_SETUP, /* Control packet (in SETUP stage) sent. */
	H2G_CONTROL_DATA_IN, /* Data IN of Control Transfer */
	H2G_CONTROL_DATA_OUT, /* Control packet (data OUT) sent */
	H2G_CONTROL_STATUS, /* Control packet (status ack) sent */
	H2G_DATA_OUT, /* Bulk/Interrupt OUT packet sent */
	H2G_DATA_IN, /* Bulk/Interrupt data IN request sent */
	INTR_END,
};

enum status_bitpos {
	GADGET_PULLUP = 0x0, /* Gadget pullup status bit position. */
	HCD_CONNECTED, /* HCD connected status bit position. */
	STATUS_END,
};

/**
 * @hcd_data_len: Data length expected by HCD.
 * @gadget_data_len: Data length expected by gadget.
 * @buffer: The endpoint data buffer itself.
 */
struct vsoc_usb_packet_buffer {
	unsigned long hcd_data_len;
	unsigned long gadget_data_len;
	char buffer[VSOC_ENDPOINT_BUFFER_SIZE];
};

/**
 * @intr: Interrupt register area.
 * @status: Status register area.
 */
struct csr {
	unsigned long intr;
	unsigned long status;
};

/**
 * @hcd_reg: Host controller wide CSR.
 * @gadget_reg: Gadget controller wide CSR.
 * @hcd_ep_in_reg: HCD side EP IN interrupt CSR. One per EP.
 * @hcd_ep_out_reg: HCD side EP OUT interrupt CSR. One per EP.
 * @gadget_ep_in_reg: Gadget side EP IN interrupt CSR. One per EP.
 * @gadget_ep_out_reg: Gadget side EP OUT interrupt CSR. One per EP.
 */
struct vsoc_usb_controller_regs {
	struct csr hcd_reg;
	struct csr gadget_reg;
	struct csr hcd_ep_in_reg[VSOC_NUM_ENDPOINTS];
	struct csr hcd_ep_out_reg[VSOC_NUM_ENDPOINTS];
	struct csr gadget_ep_in_reg[VSOC_NUM_ENDPOINTS];
	struct csr gadget_ep_out_reg[VSOC_NUM_ENDPOINTS];
};

/**
 * @magic: magic value to identify the memory region. (Used for debugging).
 * @shm_lock: lock used to guard the access to the shared memory.
 * @csr: CSR area.
 * @ep_in_buf: All Input packet buffers.
 * @ep_out_buf: All Output packet buffers.
 */
struct vsoc_usb_shm {
	u32 magic;
	spinlock_t shm_lock;
	struct vsoc_usb_controller_regs csr;
	struct vsoc_usb_packet_buffer ep_in_buf[VSOC_NUM_ENDPOINTS];
	struct vsoc_usb_packet_buffer ep_out_buf[VSOC_NUM_ENDPOINTS];
};

#endif /* __VSOC_USB_REGS_H */
