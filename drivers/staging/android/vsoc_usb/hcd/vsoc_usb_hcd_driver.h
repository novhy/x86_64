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

#ifndef __VSOC_USB_HCD_DRIVER_H
#define __VSOC_USB_HCD_DRIVER_H

#include "vsoc_usb_hcd.h"
#include "vsoc_usb_regs.h"

#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/pm.h>

#define PORT_C_MASK \
	((USB_PORT_STAT_C_CONNECTION \
	| USB_PORT_STAT_C_ENABLE \
	| USB_PORT_STAT_C_SUSPEND \
	| USB_PORT_STAT_C_OVERCURRENT \
	| USB_PORT_STAT_C_RESET) << 16)

#define POWER_BUDGET 500

#define VSOC_HCD_PORT_SUSPEND_MS 20
#define VSOC_HCD_RESET_MS 50
#define VSOC_GADGET_RESET_MS 2000

enum vsoc_hcd_rh_state {
	VSOC_HCD_RH_RESET,
	VSOC_HCD_RH_SUSPENDED,
	VSOC_HCD_RH_RUNNING
};

struct urbp {
	struct urb *urb;
	struct list_head urbp_list;
};

struct vsoc_hcd {
	enum vsoc_hcd_rh_state rh_state;
	u32 port_status;
	u32 old_status;
	unsigned long timeout;
	struct usb_hcd *hcd;
	struct usb_device *udev;
	struct list_head urbp_list;
	struct timer_list port_connection_timer;
	struct task_struct *tx_thread, *rx_thread;
	wait_queue_head_t txq, rxq;
	struct tasklet_struct hcd_tasklet;
	unsigned long action;
	u32 stream_en_ep;
	u8 num_stream[30 / 2];
	struct vsoc_usb_regs *regs;
	unsigned active:1;
	unsigned old_active:1;
	unsigned resuming:1;
	unsigned gadget_connected:1;
	spinlock_t vsoc_hcd_lock;
};

int vsoc_usb_hcd_probe(struct platform_device *pdev);
int vsoc_usb_hcd_remove(struct platform_device *pdev);
int vsoc_usb_hcd_suspend(struct platform_device *pdev, pm_message_t state);
int vsoc_usb_hcd_resume(struct platform_device *pdev);

#endif /* __VSOC_USB_HCD_DRIVER_H */
