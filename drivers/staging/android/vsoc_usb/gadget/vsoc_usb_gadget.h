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

#ifndef __VSOC_USB_GADGET_H
#define __VSOC_USB_GADGET_H

#include "vsoc_usb_common.h"
#include "vsoc_usb_regs.h"
#include "vsoc_usb_shm.h"
#include <linux/usb/gadget.h>

#define	VSOC_USB_FIFO_SIZE   64
#define VSOC_USB_MAX_STREAMS 16

struct vsoc_usb_gadget_ep {
	struct list_head queue;
	unsigned long last_io;
	struct usb_gadget *gadget;
	const struct usb_endpoint_descriptor *desc;
	struct usb_ep ep;
	unsigned halted:1;
	unsigned wedged:1;
	unsigned already_seen:1;
	unsigned setup_state:1;
	unsigned stream_en:1;
};

struct vsoc_usb_gadget_request {
	struct list_head queue;
	struct usb_request req;
};

struct vsoc_usb_gadget {
	spinlock_t lock;
	struct vsoc_usb_gadget_ep *gep;
	int address;
	struct usb_gadget gadget;
	struct usb_gadget_driver *driver;
	struct vsoc_usb_gadget_request fifo_req;
	u8 fifo_buf[VSOC_USB_FIFO_SIZE];
	u16 devstatus;
	unsigned udc_suspended:1;
	unsigned pullup:1;
	struct vsoc_usb_regs *usb_regs;
};

extern const char gadget_name[];
extern const char ep0name[];

int vsoc_usb_gadget_get_num_endpoints(void);
const char *vsoc_usb_gadget_get_ep_name(int i);
const struct usb_ep_caps *vsoc_usb_gadget_get_ep_caps(int i);

#endif /* __VSOC_USB_GADGET_H */
