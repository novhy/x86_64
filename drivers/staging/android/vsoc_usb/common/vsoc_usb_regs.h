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

/*
 * Shared memory holds USB packet per Endpoint.
 * To start with, things are simple.
 * Shared memory is divided into regions of 16KiB. One per Endpoint. (The
 * selection is based on ADB packet size(16KiB), which is the main use case for
 * this driver).
 *
 * The following is an example of an USB out transfer:
 * Gadget driver queues an usb_request to the UCD.
 * HCD submits an URB. The URB data is broken down into USB ep packets. The ep
 * packet is copied into the shared memory region (corresponding to the ep).
 * The gadget controller is notified of the new packet. It copies the packet
 * from shared memory into usb_request buffer and notifies the HCD.
 * Once entire URB data is copied by UCD, the HCD completes the URB request.
 * Similarly, the UCD completes the usb_request.
 * In transfers are similar (except for the direction ofcourse).
 *
 * Also, the data length for a URB may be different from that of the
 * corresponding usb_request. This means that there may be 'N' completions of
 * usb_request(s) for every single completion of URB requests (or vice-versa).
 */

#include <linux/spinlock.h>

#define VSOC_NUM_ENDPOINTS 3
#define VSOC_ENDPOINT_BUFFER_SIZE (16*(1<<10))

enum hcd_intr_bitpos {
	G2H_RESET_COMPLETE = 0x0,
	G2H_CONN_CHANGE,
	G2H_CONTROL_SETUP_ACK_NEXT_STATUS,
	G2H_CONTROL_SETUP_ACK_NEXT_IN,
	G2H_CONTROL_STATUS_ACK_NEXT_OUT,
	G2H_CONTROL_DATA_OUT_ACK,
	G2H_CONTROL_STATUS_ACK,
	G2H_DATA_OUT_ACK,
};

enum hcd_status_bitpos {
	HCD_CONNECTED = 0x0,
	HCD_DISCONNECTED,
};

enum gadget_intr_bitpos {
	H2G_RESET = 0x0,
	H2G_DISCONNECT,
	H2G_CONTROL_SETUP,
	H2G_CONTROL_DATA_OUT,
	H2G_CONTROL_DATA_IN_ACK,
	H2G_CONTROL_STATUS,
	H2G_DATA_OUT_REQ,
	H2G_DATA_IN_REQ,
	H2G_DATA_IN_ACK,
};

enum gadget_status_bitpos {
	GADGET_PULLUP = 0x0,
};

/*
enum ep_state {
	EP_RESET = 0x0,
	EP_CONTROL_SETUP,
	EP_CONTROL_IN,
	EP_CONTROL_OUT,
	EP_CONTROL_ACK_WAIT,
	EP_DATA_IN,
	EP_DATA_OUT,
	EP_DATA_ACK_WAIT,
};
*/

struct vsoc_usb_packet_buffer {
	/*	enum ep_state state; */
	unsigned long data_len; /* bytes remaining to be transferred */
	char buffer[VSOC_ENDPOINT_BUFFER_SIZE];
};


struct csr {
	unsigned long intr;
	unsigned long status;
};

struct vsoc_usb_controller_regs {
	struct csr hcd_reg;
	struct csr gadget_reg;
	struct csr hcd_ep_in_reg[VSOC_NUM_ENDPOINTS];
	struct csr hcd_ep_out_reg[VSOC_NUM_ENDPOINTS];
	struct csr gadget_ep_in_reg[VSOC_NUM_ENDPOINTS];
	struct csr gadget_ep_out_reg[VSOC_NUM_ENDPOINTS];
};

/*
 * TODO (romitd) better alignment for potential performance improvements.
 */
struct vsoc_usb_shm {
	u32 magic;
	spinlock_t shm_lock;
	struct vsoc_usb_controller_regs csr;
	struct vsoc_usb_packet_buffer ep_in_buf[VSOC_NUM_ENDPOINTS];
	struct vsoc_usb_packet_buffer ep_out_buf[VSOC_NUM_ENDPOINTS];
};

#endif /* __VSOC_USB_REGS_H */
