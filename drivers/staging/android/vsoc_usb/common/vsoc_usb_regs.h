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
 * Shared memory is divided into regions of 1024 bytes. One per Endpoint.
 * (1024 being the max endpoint size in SS devices).
 * The following is an example of an USB out transfer.
 * Gadget driver queues an usb_request to the UCD.
 * HCD submits an URB. The URB data is broken down into USB ep packets. The ep
 * packet is copied into the shared memory region (corresponding to the ep).
 * The gadget controller is notified of the new packet. It copies the packet
 * from shared memory into usb_request buffer and notifies the HCD.
 * Once entire URB data is copied by UCD, the HCD completes the URB request.
 * Similarly, the UCD completes the usb_request.
 *
 * TODO (romitd): We need to move to multipacket buffers. This will be done
 * once we the single packet scenario working.
 */

#include <linux/spinlock.h>

struct vsoc_usb_packet_buffer {
	char buffer[1024];
};

struct vsoc_usb_controller_status {
	spinlock_t hcd_status_lock;
	spinlock_t gadget_status_lock;
	struct {
		u32 status;
	} hcd_status;

	struct {
		u32 status;
	} gadget_status;

	struct {
		u32 intr_status;
	} hcd_ep_intr;

	struct {
		u32 intr_status;
	} gadget_ep_inter;

};

struct vsoc_usb_regs {
	u32 magic;
	struct vsoc_usb_controller_status vsoc_usb_status;
	struct vsoc_usb_packet_buffer in_buf[16];
	struct vsoc_usb_packet_buffer out_buf[16];
};
#endif /* __VSOC_USB_REGS_H */
