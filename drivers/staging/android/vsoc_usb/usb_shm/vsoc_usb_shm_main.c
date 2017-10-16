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
 */

#define DEBUG 1
#include <linux/spinlock.h>
#include "vsoc_usb_shm.h"

/*
 * We expect to get the shared memory region differently in intra-domain Vs
 * inter-domain implementations. This is an indirection to isolate this
 * separation.
 */
struct vsoc_shm_ops {
	void *(*get_mem) (size_t size, gfp_t flags);
	void (*put_mem) (const void *ptr);
};

static struct vsoc_shm_ops vsoc_shm_ops = {
	.get_mem = kzalloc,
	.put_mem = kfree,
};

/*
 * Structure for Cross domain IPI routines
 */
struct vsoc_usb_xipi {
	spinlock_t lock;
	int (*kick)(unsigned long data);
	unsigned long data;
};

static struct vsoc_shm_ops *vsoc_shm_helper = &vsoc_shm_ops;
static struct vsoc_usb_shm *vsoc_usb_shm[VSOC_USB_MAX_NUM_CONTROLLER];
static struct vsoc_usb_xipi h2g_ipi, g2h_ipi;

struct vsoc_usb_shm *vsoc_usb_shm_get(unsigned int index)
{
	dbg("%s\n", __func__);
	if (index >= VSOC_USB_MAX_NUM_CONTROLLER) {
		printk(KERN_ERR "Requesting out of bounds VSoC USB memory "
		       "region");
		return NULL;
	}
	return vsoc_usb_shm[index];
}
EXPORT_SYMBOL_GPL(vsoc_usb_shm_get);

int vsoc_usb_register_h2g_ipi(int (*kick)(unsigned long data),
			      unsigned long data)
{
	int rc = 0;
	unsigned long flags;
	dbg("%s\n", __func__);
	spin_lock_irqsave(&h2g_ipi.lock, flags);
	h2g_ipi.kick = kick;
	h2g_ipi.data = data;
	spin_unlock_irqrestore(&h2g_ipi.lock, flags);

	return rc;
}
EXPORT_SYMBOL_GPL(vsoc_usb_register_h2g_ipi);

int vsoc_usb_unregister_h2g_ipi(void)
{
	unsigned long flags;
	dbg("%s\n", __func__);
	spin_lock_irqsave(&h2g_ipi.lock, flags);
	memset(&h2g_ipi, 0, sizeof(h2g_ipi));
	spin_unlock_irqrestore(&h2g_ipi.lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(vsoc_usb_unregister_h2g_ipi);

int vsoc_usb_register_g2h_ipi(int (*kick)(unsigned long data),
			      unsigned long data)
{
	int rc = 0;
	unsigned long flags;
	dbg("%s\n", __func__);
	spin_lock_irqsave(&g2h_ipi.lock, flags);
	g2h_ipi.kick = kick;
	g2h_ipi.data = data;
	spin_unlock_irqrestore(&g2h_ipi.lock, flags);

	return rc;
}
EXPORT_SYMBOL_GPL(vsoc_usb_register_g2h_ipi);

int vsoc_usb_unregister_g2h_ipi(void)
{
	unsigned long flags;
	dbg("%s\n", __func__);
	spin_lock_irqsave(&g2h_ipi.lock, flags);
	memset(&g2h_ipi, 0, sizeof(g2h_ipi));
	spin_unlock_irqrestore(&g2h_ipi.lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(vsoc_usb_unregister_g2h_ipi);

int vsoc_usb_h2g_kick(void)
{
	int rc = 0;
	unsigned long flags;
	dbg("%s\n", __func__);

	spin_lock_irqsave(&h2g_ipi.lock, flags);
	if (h2g_ipi.kick)
		rc = h2g_ipi.kick(h2g_ipi.data);
	else
		rc = -EFAULT;
	spin_unlock_irqrestore(&h2g_ipi.lock, flags);

	return rc;
}
EXPORT_SYMBOL_GPL(vsoc_usb_h2g_kick);

int vsoc_usb_g2h_kick(void)
{
	int rc = 0;
	unsigned long flags;
	dbg("%s\n", __func__);

	spin_lock_irqsave(&g2h_ipi.lock, flags);
	if (g2h_ipi.kick)
		rc = g2h_ipi.kick(g2h_ipi.data);
	else
		rc = -EFAULT;
	spin_unlock_irqrestore(&g2h_ipi.lock, flags);

	return rc;
}
EXPORT_SYMBOL_GPL(vsoc_usb_g2h_kick);

static int __init vsoc_usb_shm_init(void)
{
	int rc;
	int i;
	dbg("%s\n", __func__);
	spin_lock_init(&h2g_ipi.lock);
	spin_lock_init(&g2h_ipi.lock);

	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		vsoc_usb_shm[i] =
		    vsoc_shm_helper->get_mem(sizeof(struct vsoc_usb_shm),
					     GFP_KERNEL);
		if (!vsoc_usb_shm[i]) {
			rc = -ENOMEM;
			i--;
			goto err_get_mem;
		}

		/*
		 * Initialize the shm magic and the spinlock.
		 */
		vsoc_usb_shm[i]->magic = VSOC_USB_SHM_MAGIC;
		spin_lock_init(&vsoc_usb_shm[i]->shm_lock);
	}

	printk(KERN_INFO "VSoC USB Shared Memory Helper Driver loaded.\n");
	return 0;

err_get_mem:
	while (i >= 0) {
		vsoc_shm_helper->put_mem(vsoc_usb_shm[i--]);
	}

	return rc;
}

static void __exit vsoc_usb_shm_exit(void)
{
	int i;
	dbg("%s\n", __func__);
	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		vsoc_shm_helper->put_mem(vsoc_usb_shm[i]);
	}
	printk(KERN_INFO "VSoC USB Shared Memory Helper Driver unloaded.\n");
	return;
}

module_init(vsoc_usb_shm_init);
module_exit(vsoc_usb_shm_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("VSoC USB Shared Memory Helper Driver");
MODULE_AUTHOR("Google Inc.");
