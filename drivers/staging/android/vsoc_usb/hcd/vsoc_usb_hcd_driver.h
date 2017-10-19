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

/*
 * State of a transaction marked in an URBP.
 */
enum vsoc_hcd_ep_transaction_state {
	INIT_STATE = 0x0,
	CONTROL_SETUP_STATE,
	CONTROL_SETUP_ACK_WAIT_STATE,
	CONTROL_IN_START_STATE,
	CONTROL_IN_STATE,
	CONTROL_OUT_START_STATE,
	CONTROL_OUT_STATE,
	CONTROL_STATUS_STATE,
	DATA_IN_STATE,
	DATA_IN_ACK_STATE,
	DATA_OUT_STATE,
	DATA_OUT_ACK_STATE,
	TRANSFER_COMPLETE_STATE,
};

struct urbp {
	struct urb *urb;
	struct list_head urbp_list;
	unsigned long transaction_state;
	unsigned nak:1; /* Gadget is NAKing the request */
};

/*
 * The top bit in the transaction state will be set if the URB is in flight.
 */
#define URB_IN_FLIGHT_BIT \
	(sizeof(((struct urbp *)(0))->transaction_state) * 8 - 1)


/*
 * TODO (romitd): Document the fields of this structure
 */
struct vsoc_hcd {
	spinlock_t vsoc_hcd_lock;
	struct vsoc_usb_shm *shm;
	struct task_struct *tx_thread, *rx_thread;
	struct usb_hcd *hcd;
	struct usb_device *udev;
	/*
	 * TODO (romitd):
	 * This assumes we have only one port in the root hub.
	 * If we support multiple devices we should have a pair of list_head
	 * arrays per gadget (corresponding to a unique USB address). Should be
	 * a simple change (USB hub supports a max of 127 devices).
	 */
	struct list_head urbp_list_in[VSOC_NUM_ENDPOINTS];
	struct list_head urbp_list_out[VSOC_NUM_ENDPOINTS];

	/* Timer to handle disconnected gadget during startup */
	struct timer_list port_connection_timer;

	wait_queue_head_t txq, rxq;
	struct tasklet_struct hcd_tasklet;
	unsigned long controller_action; /* bits specific to controller */
	unsigned long rx_action; /* bit represting pending Rx ep activity */
	unsigned long tx_action; /* bit representing pending Tx ep activity */

	/* action reason for each pair of Tx and Rx ep */
	unsigned long rx_action_reason[VSOC_NUM_ENDPOINTS];
	unsigned long tx_action_reason[VSOC_NUM_ENDPOINTS];

	enum vsoc_hcd_rh_state rh_state; /* state of the root hub */

	/* port status, used during connection change */
	u32 port_status;
	u32 old_status;
	unsigned long timeout; /* timeout value during enumeration */

	unsigned active:1;
	unsigned old_active:1;
	unsigned resuming:1;
	unsigned gadget_connected:1;
};


int vsoc_usb_hcd_probe(struct platform_device *pdev);
int vsoc_usb_hcd_remove(struct platform_device *pdev);
int vsoc_usb_hcd_suspend(struct platform_device *pdev, pm_message_t state);
int vsoc_usb_hcd_resume(struct platform_device *pdev);

#endif /* __VSOC_USB_HCD_DRIVER_H */
