/*
 * drivers/android/staging/vsoc.c
 *
 * Android Virtual System on a Chip (VSoC) driver
 *
 * Copyright (C) 2017 Google, Inc.
 *
 * Author: ghartman@google.com
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
 *
 * Based on drivers/char/kvm_ivshmem.c - driver for KVM Inter-VM shared memory
 *         Copyright 2009 Cam Macdonell <cam@cs.ualberta.ca>
 *
 * Based on cirrusfb.c and 8139cp.c:
 *	   Copyright 1999-2001 Jeff Garzik
 *	   Copyright 2001-2004 Jeff Garzik
 *
 */

#include <linux/dma-mapping.h>
#include <linux/futex.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/cdev.h>
#include "uapi/vsoc_shm.h"

#define VSOC_DEV_NAME "vsoc"

/*
 * Description of the ivshmem-doorbell PCI device used by QEmu. These
 * constants follow docs/specs/ivshmem-spec.txt, which can be found in
 * the QEmu repository. This was last reconciled with the version that
 * came out with 2.8
 */

/*
 * These constants are determined KVM Inter-VM shared memory device
 * register offsets
 */
enum {
	IntrMask	= 0x00,	   /* Interrupt Mask */
	IntrStatus	= 0x04,	   /* Interrupt Status */
	IVPosition	= 0x08,	   /* VM ID */
	Doorbell	= 0x0c,	   /* Doorbell */
};

static const int REGISTER_BAR = 0;
static const int MAX_REGISTER_BAR_LEN = 0x100;
/*
 * The MSI-x BAR is not used directly.
 *
 * static const int MSI_X_BAR = 1;
 */
static const int SHARED_MEMORY_BAR = 2;

typedef struct {
	char name[sizeof(vsoc_device_name) + 1];
	wait_queue_head_t wait_queue;
	/* Flag indicating that an interrupt has been signalled by the host. */
	atomic_t *incoming_signalled;
	/* Flag indicating the guest has signalled the host. */
	atomic_t *outgoing_signalled;
	int irq_requested;
	int device_created;
} vsoc_region_data_t;

typedef struct vsoc_device {
	// Kernel virtual address of REGISTER_BAR.
	void __iomem * regs;
	// Physical address of SHARED_MEMORY_BAR.
	dma_addr_t shm_phys_start;
	// Kernel virtual address of SHARED_MEMORY_BAR.
	void * kernel_mapped_shm;
	// Size of the entire shared memory window in bytes.
	size_t shm_size;
	// Pointer to the virtual address of the shared memory layout structure.
	// This is probably identical to kernel_mapped_shm, but saving this
	// here saves a lot of annoying casts.
	vsoc_shm_layout_descriptor * layout;
	// Points to a table of region descriptors in the kernel's virtual
	// address space. Calculated from
	// vsoc_shm_layout_descriptor.vsoc_region_desc_offset
	vsoc_device_region * regions;
	// Head of a list of permissions that have been granted.
	struct list_head permissions;
	struct pci_dev * dev;
	// Per-region (and therefore per-interrupt) information.
	vsoc_region_data_t * regions_data;
	// Table of msi-x entries. This has to be separated from
	// vsoc_region_data_t because the kernel deals with them as an array.
	struct msix_entry * msix_entries;
	/*
	 * Flags that indicate what we've initialzied. These are used to do an
	 * orderly cleanup of the device.
	 */
	char enabled_device;
	char requested_regions;
	char cdev_added;
	char msix_enabled;
	/* Mutex that protectes the permission list */
	struct mutex mtx;
	/* Major number assigned by the kernel */
	int major;

	struct cdev cdev;
	struct class *class;
} vsoc_device;

static vsoc_device vsoc_dev;

/*
 * TODO(ghartman): Add a /sys filesystem entry that summarizes the permissions.
 */

typedef struct {
	fd_scoped_permission permission;
	struct list_head list;
} fd_scoped_permission_node_t;

typedef struct {
	fd_scoped_permission_node_t* fd_scoped_permission_node;
} vsoc_private_data_t;

static long vsoc_ioctl(struct file *, unsigned int, unsigned long);
static int vsoc_mmap(struct file *, struct vm_area_struct *);
static int vsoc_open(struct inode *, struct file *);
static int vsoc_release(struct inode *, struct file *);
static ssize_t vsoc_read(struct file *, char *, size_t, loff_t *);
static ssize_t vsoc_write(struct file *, const char *, size_t, loff_t *);
static loff_t vsoc_lseek(struct file * filp, loff_t offset, int origin);
static int do_create_fd_scoped_permission(fd_scoped_permission *np,
					  fd_scoped_permission* __user arg);
static void do_destroy_fd_scoped_permission(fd_scoped_permission* perm);
static long do_vsoc_describe_region(struct file *, vsoc_device_region __user *);

static const struct file_operations vsoc_ops = {
	.owner	 = THIS_MODULE,
	.open	= vsoc_open,
	.mmap	= vsoc_mmap,
	.read	= vsoc_read,
	.unlocked_ioctl	  = vsoc_ioctl,
	.compat_ioctl	  = vsoc_ioctl,
	.write	 = vsoc_write,
	.llseek	 = vsoc_lseek,
	.release = vsoc_release,
};

static struct pci_device_id vsoc_id_table[] = {
	{ 0x1af4, 0x1110, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{ 0 },
};
MODULE_DEVICE_TABLE (pci, vsoc_id_table);

static void vsoc_remove_device(struct pci_dev* pdev);
static int vsoc_probe_device (struct pci_dev *pdev,
			      const struct pci_device_id * ent);

static struct pci_driver vsoc_pci_driver = {
	.name		= "vsoc",
	.id_table	= vsoc_id_table,
	.probe	   = vsoc_probe_device,
	.remove	  = vsoc_remove_device,
};

static int do_create_fd_scoped_permission(fd_scoped_permission *np,
					  fd_scoped_permission* __user arg)
{
	atomic_t* owner_ptr = NULL;
	if (copy_from_user(np, arg, sizeof(*np)))
		return -EFAULT;
	// The region must be well formed and have non-zero size
	if (np->region_begin_offset >= np->region_end_offset)
		return -EINVAL;
	// The region must fit in the memory window
	if (np->region_end_offset > vsoc_dev.shm_size)
		return -EINVAL;
	// The owner flag must reside in the memory window
	if (np->owner_offset + sizeof(np->owner_offset)
	    > vsoc_dev.shm_size)
		return -EINVAL;
	// Owner offset must be naturally aligned in the window
	if (np->owner_offset & (sizeof(np->owner_offset) - 1))
		return -EINVAL;
	// The owner value must change if we can claim the memory
	if (np->owned_value == VSOC_REGION_FREE)
		return -EINVAL;
	owner_ptr = (atomic_t*) vsoc_dev.kernel_mapped_shm + np->owner_offset;
	// We've already verified that this is in the shared memory window, so
	// it should be safe to write to this address.
	if (atomic_cmpxchg(owner_ptr,
			   VSOC_REGION_FREE,
			   np->owned_value) != VSOC_REGION_FREE)
		return -EBUSY;
	return 0;
}

static void do_destroy_fd_scoped_permission_node(fd_scoped_permission_node_t* node) {
	if (node) {
		do_destroy_fd_scoped_permission(&node->permission);
		mutex_lock(&vsoc_dev.mtx);
		list_del(&node->list);
		mutex_unlock(&vsoc_dev.mtx);
		kfree(node);
	}
}

static void do_destroy_fd_scoped_permission(fd_scoped_permission* perm)
{
	atomic_t* owner_ptr = NULL;
	int prev = 0;
	if (!perm)
		return;
	owner_ptr = (atomic_t*) vsoc_dev.kernel_mapped_shm + perm->owner_offset;
	prev = atomic_xchg(owner_ptr, VSOC_REGION_FREE);
	if (prev != perm->owned_value)
		printk("VSoC: %x-%x: owner %x: expected to be %x was %x",
		       perm->region_begin_offset, perm->region_end_offset,
		       perm->owner_offset, perm->owned_value, prev);
}

static long do_vsoc_describe_region(struct file *filp,
				    vsoc_device_region __user *dest) {
	u32 minor = iminor(file_inode(filp));
	if (minor >= vsoc_dev.layout->region_count) {
		printk(KERN_ERR "VSoC: do_vsoc_describe_region: invalid region %d\n",
		       minor);
		return -ENOENT;
	}
	if (copy_to_user(dest, vsoc_dev.regions + minor,
			 sizeof(vsoc_dev.regions[minor])))
		return -EFAULT;
	return 0;
}

static long vsoc_ioctl(struct file * filp,
		       unsigned int cmd, unsigned long arg)
{
	int rv = 0;
	u32 region_number = iminor(file_inode(filp));

	switch (cmd) {
	case VSOC_CREATE_FD_SCOPED_PERMISSION:
	{
		fd_scoped_permission_node_t* node = NULL;
		if (!filp->private_data) {
			printk(KERN_ERR "Vsoc: No private data on fd, region %d\n",
			       region_number);
			return -EBADFD;
		}
		// EBUSY because this fd already has a permission.
		if (((vsoc_private_data_t*)filp->private_data)->fd_scoped_permission_node)
			return -EBUSY;
		node = kzalloc(sizeof(*node), GFP_KERNEL);
		// We can't allocate memory for the permission
		if (!node)
			return -ENOMEM;
		INIT_LIST_HEAD(&node->list);
		rv = do_create_fd_scoped_permission(
			&node->permission, (fd_scoped_permission __user *)arg);
		if (!rv) {
			mutex_lock(&vsoc_dev.mtx);
			list_add(&node->list, &vsoc_dev.permissions);
			mutex_unlock(&vsoc_dev.mtx);
			((vsoc_private_data_t*)filp->private_data)->fd_scoped_permission_node = node;
		} else {
			kfree(node);
			return rv;
		}
		break;
	}
	case VSOC_GET_FD_SCOPED_PERMISSION:
	{
		fd_scoped_permission_node_t* node = NULL;
		if (!filp->private_data) {
			printk(KERN_ERR "Vsoc: No private data on fd, region %d\n",
			       region_number);
			return -EBADFD;
		}
		node = ((vsoc_private_data_t*)filp->private_data)->fd_scoped_permission_node;
		if (!node)
			return -ENOENT;
		if (copy_to_user((fd_scoped_permission __user *)arg,
				&node->permission,
				sizeof(node->permission)))
			return -EFAULT;
	}
	case VSOC_MAYBE_SEND_INTERRUPT_TO_HOST:
		if (!atomic_xchg(vsoc_dev.regions_data[region_number].outgoing_signalled, 1)) {
			writel(region_number, vsoc_dev.regs + Doorbell);
			return 0;
		} else {
			return -EBUSY;
		}
		break;
	case VSOC_WAIT_FOR_INCOMING_INTERRUPT:
		wait_event_interruptible(
			vsoc_dev.regions_data[region_number].wait_queue,
			(atomic_read(vsoc_dev.regions_data[region_number].incoming_signalled) != 0));
		break;
	case VSOC_DESCRIBE_REGION:
		return do_vsoc_describe_region(
			filp, (vsoc_device_region __user *)arg);
	default:
		printk("VSoC: bad ioctl (\n");
	}
	return 0;
}

static ssize_t vsoc_read(struct file * filp, char * buffer, size_t len,
				loff_t * poffset)
{
	int bytes_read = 0;
	unsigned long offset;
	u32 region_number = iminor(file_inode(filp));
	ssize_t max_len;
	if (region_number >= vsoc_dev.layout->region_count) {
		printk(KERN_ERR "VSoC: region %d doesn't exist\n",
		       region_number);
		return -ENODEV;
	}
	if (!vsoc_dev.kernel_mapped_shm) {
		printk(KERN_ERR "VSoC: cannot read from shm (NULL)\n");
		return 0;
	}
	offset = *poffset +
		vsoc_dev.regions[region_number].region_begin_offset;
	if (offset > vsoc_dev.regions[region_number].region_end_offset)
		return 0;
	max_len = vsoc_dev.regions[region_number].region_end_offset -
		offset;
	if (len > max_len) {
		len = max_len;
	}

	if (len == 0) return 0;

	bytes_read = copy_to_user(buffer, vsoc_dev.kernel_mapped_shm + offset,
					len);
	if (bytes_read > 0) {
		return -EFAULT;
	}

	*poffset += len;
	return len;
}

static loff_t vsoc_lseek(struct file * filp, loff_t offset, int origin)
{
	u32 region_number = iminor(file_inode(filp));
	loff_t max_offset;

	if (region_number >= vsoc_dev.layout->region_count) {
		printk(KERN_ERR "VSoC: region %d doesn't exist\n",
		       region_number);
		return -ENODEV;
	}

	max_offset = vsoc_dev.regions[region_number].region_end_offset -
		vsoc_dev.regions[region_number].region_begin_offset;

	switch (origin) {
	case SEEK_SET: break;
	case SEEK_CUR:
		if (offset > 0 && offset + filp->f_pos < 0) {
			return -EOVERFLOW;
		}
		offset += filp->f_pos;
		break;
	case SEEK_END:
		if (offset > 0 && offset + filp->f_pos < 0) {
			return -EOVERFLOW;
		}
		offset += max_offset;
		break;
	case SEEK_DATA:
		// Doesn't work if region is empty, but that shouldn't happen
		if (offset >= max_offset) {
			return -EINVAL;
		}
		if (offset < 0) {
			offset = 0;
		}
		break;
	case SEEK_HOLE:
		// Next hole is always the end of the region, unless offset is beyond that
		if (offset < max_offset) {
			offset = max_offset;
		}
		break;
	default:
		return -EINVAL;
	}

	if (offset < 0 || offset > max_offset) {
		return -EINVAL;
	}

	filp->f_pos = offset;

	return offset;
}

static ssize_t vsoc_write(struct file * filp, const char * buffer,
				size_t len, loff_t * poffset)
{
	int bytes_written = 0;
	unsigned long offset;
	u32 region_number = iminor(file_inode(filp));
	ssize_t max_len;

	if (region_number >= vsoc_dev.layout->region_count) {
		printk(KERN_ERR "VSoC: region %d doesn't exist\n",
		       region_number);
		return -ENODEV;
	}
	if (!vsoc_dev.kernel_mapped_shm) {
		printk(KERN_ERR "VSoC: cannot write to shm (NULL)\n");
		return 0;
	}
	offset = *poffset +
		vsoc_dev.regions[region_number].region_begin_offset;
	max_len = vsoc_dev.regions[region_number].region_end_offset -
		offset;
	if (max_len < 0)
		max_len = 0;

	if (len > max_len) {
		len = max_len;
	}

	if (len == 0) return 0;

	bytes_written = copy_from_user(vsoc_dev.kernel_mapped_shm + offset,
				       buffer, len);
	if (bytes_written > 0) {
		return -EFAULT;
	}
	*poffset += len;
	return len;
}

static irqreturn_t vsoc_interrupt(int irq, void *dev_instance)
{
	struct vsoc_device * dev = dev_instance;

	if (unlikely(dev == NULL))
		return IRQ_NONE;

	if (unlikely((irq < 0) || (irq >= dev->layout->region_count))) {
		printk(KERN_INFO "VSoC: invalid irq (irq = 0x%04x)\n",
		       irq);
		return IRQ_NONE;
	}

	wake_up_interruptible(&dev->regions_data[irq].wait_queue);
	return IRQ_HANDLED;
}

static int vsoc_probe_device(struct pci_dev *pdev,
			     const struct pci_device_id * ent)
{
	int result;
	int i;
	dma_addr_t reg_size;
	dev_t devt;

	vsoc_dev.dev = pdev;
	result = pci_enable_device(pdev);
	if (result) {
		printk(KERN_ERR "VSoC: pci_enable_device failed %s: error %d\n",
		       pci_name(pdev), result);
		return result;
	}
	vsoc_dev.enabled_device = 1;
	result = pci_request_regions(pdev, "vsoc");
	if (result < 0) {
		printk(KERN_ERR "VSoC: pci_request_regions failed\n");
		vsoc_remove_device(pdev);
		return -EBUSY;
	}
	vsoc_dev.requested_regions = 1;
	/* Set up the control registers in BAR 0 */
	reg_size = pci_resource_len(pdev, REGISTER_BAR);
	if (reg_size > MAX_REGISTER_BAR_LEN)
		vsoc_dev.regs = pci_iomap(pdev, REGISTER_BAR, MAX_REGISTER_BAR_LEN);
	else
		vsoc_dev.regs = pci_iomap(pdev, REGISTER_BAR, reg_size);

	if (!vsoc_dev.regs) {
		printk(KERN_ERR "VSoC: cannot ioremap registers of size %zu\n",
		       (size_t)reg_size);
		vsoc_remove_device(pdev);
		return -EBUSY;
	}

	/* Map the shared memory in BAR 2 */
	vsoc_dev.shm_phys_start = pci_resource_start(pdev, SHARED_MEMORY_BAR);
	vsoc_dev.shm_size = pci_resource_len(pdev, SHARED_MEMORY_BAR);

	printk(KERN_INFO "VSoC: shared memory @ DMA %p size=0x%zx\n",
	       (void*)vsoc_dev.shm_phys_start, vsoc_dev.shm_size);
	/* TODO(ghartman): ioremap_wc should work here */
	vsoc_dev.kernel_mapped_shm = ioremap_nocache(
		vsoc_dev.shm_phys_start, vsoc_dev.shm_size);
	if (!vsoc_dev.kernel_mapped_shm) {
		printk(KERN_ERR "VSoC: cannot iomap region\n");
		vsoc_remove_device(pdev);
		return -EBUSY;
	}

	vsoc_dev.layout =
		(vsoc_shm_layout_descriptor*) vsoc_dev.kernel_mapped_shm;
	printk(KERN_INFO "VSoC: major_version: %d\n",
	       vsoc_dev.layout->major_version);
	printk(KERN_INFO "VSoC: minor_version: %d\n",
	       vsoc_dev.layout->minor_version);
	printk(KERN_INFO "VSoC: size: 0x%x\n", vsoc_dev.layout->size);
	printk(KERN_INFO "VSoC: regions: %d\n", vsoc_dev.layout->region_count);
	if (vsoc_dev.layout->major_version !=
	    CURRENT_VSOC_LAYOUT_MAJOR_VERSION) {
		printk(KERN_ERR
		       "VSoC: driver supports only major_version %d\n",
		       CURRENT_VSOC_LAYOUT_MAJOR_VERSION);
		vsoc_remove_device(pdev);
		return -EBUSY;
	}
	result = alloc_chrdev_region(&devt, 0, vsoc_dev.layout->region_count,
				     VSOC_DEV_NAME);
	if (result) {
		printk(KERN_ERR "VSoC: alloc_chrdev_region failed\n");
		vsoc_remove_device(pdev);
		return -EBUSY;
	}
	vsoc_dev.major = MAJOR(devt);
	cdev_init(&vsoc_dev.cdev, &vsoc_ops);
	vsoc_dev.cdev.owner = THIS_MODULE;
	result = cdev_add(&vsoc_dev.cdev, devt, vsoc_dev.layout->region_count);
	if (result) {
		printk(KERN_ERR "VSoC: cdev_add error\n");
		vsoc_remove_device(pdev);
		return -EBUSY;
	}
	vsoc_dev.cdev_added = 1;
	vsoc_dev.class = class_create(THIS_MODULE, VSOC_DEV_NAME);
	if (!vsoc_dev.class) {
		printk(KERN_ERR "VSoC: class_create failed\n");
		vsoc_remove_device(pdev);
		return -EBUSY;
	}
	vsoc_dev.regions = (vsoc_device_region*)
		(vsoc_dev.kernel_mapped_shm +
		 vsoc_dev.layout->vsoc_region_desc_offset);
	vsoc_dev.msix_entries = kzalloc(
		vsoc_dev.layout->region_count * sizeof(vsoc_dev.msix_entries[0]),
		GFP_KERNEL);
	if (!vsoc_dev.msix_entries) {
		printk(KERN_ERR "VSoC: unable to allocate msix_entries\n");
		vsoc_remove_device(pdev);
		return -ENOSPC;
	}
	vsoc_dev.regions_data = kzalloc(
		vsoc_dev.layout->region_count * sizeof(vsoc_dev.regions_data[0]),
		GFP_KERNEL);
	if (!vsoc_dev.regions_data) {
		printk(KERN_ERR "VSoC: unable to allocate regions' data\n");
		vsoc_remove_device(pdev);
		return -ENOSPC;
	}
	for (i = 0; i < vsoc_dev.layout->region_count; ++i)
		vsoc_dev.msix_entries[i].entry = i;

	result = pci_enable_msix(vsoc_dev.dev, vsoc_dev.msix_entries,
				 vsoc_dev.layout->region_count);
	if (result) {
		printk(KERN_INFO "VSoC: pci_enable_msix failed: %d\n", result);
		vsoc_remove_device(pdev);
		return -ENOSPC;
	}
	vsoc_dev.msix_enabled = 1;
	for (i = 0; i < vsoc_dev.layout->region_count; ++i) {
		const vsoc_device_region* region = vsoc_dev.regions + i;
		vsoc_dev.regions_data[i].name[
			sizeof(vsoc_dev.regions_data[i].name) - 1] = '\0';
		memcpy(vsoc_dev.regions_data[i].name,
		       region->device_name,
		       sizeof(vsoc_dev.regions_data[i].name) - 1);
		printk(KERN_INFO "VSoC: region %d name=%s\n", i,
		       vsoc_dev.regions_data[i].name);
		init_waitqueue_head(&vsoc_dev.regions_data[i].wait_queue);
		vsoc_dev.regions_data[i].incoming_signalled =
			vsoc_dev.kernel_mapped_shm +
			region->region_begin_offset +
			region->host_to_guest_signal_table.interrupt_signalled_offset;
		vsoc_dev.regions_data[i].outgoing_signalled =
			vsoc_dev.kernel_mapped_shm +
			region->region_begin_offset +
			region->guest_to_host_signal_table.interrupt_signalled_offset;

		result = request_irq(vsoc_dev.msix_entries[i].vector,
				     vsoc_interrupt, 0,
				     vsoc_dev.regions_data[i].name, &vsoc_dev);
		if (result) {
			printk(KERN_INFO "VSoC: request_irq failed irq=%d vector=%d\n",
			       i, vsoc_dev.msix_entries[i].vector);
			vsoc_remove_device(pdev);
			return -ENOSPC;
		}
		vsoc_dev.regions_data[i].irq_requested = 1;
		if (!device_create(vsoc_dev.class,
				   NULL,
				   MKDEV(vsoc_dev.major, i),
				   NULL,
				   vsoc_dev.regions_data[i].name)) {
			printk(KERN_ERR "VSoC: device_create failed\n");
			vsoc_remove_device(pdev);
			return -EBUSY;
		}
		vsoc_dev.regions_data[i].device_created = 1;
	}
	return 0;
}

/*
 * This should undo all of the allocations in the probe function in reverse
 * order.
 *
 * Notes:
 *
 *   The device may have been partially initialized, so double check
 *   that the allocations happened.
 *
 *   This function may be called multiple times, so mark resources as freed
 *   as they are deallocated.
 */
static void vsoc_remove_device(struct pci_dev* pdev)
{
	int i;
	/*
	 * pdev is the first thing to be set on probe and the last thing
	 * to be cleared here. If it's NULL then there is no cleanup.
	 */
	if (!pdev || !vsoc_dev.dev)
		return;
	printk(KERN_INFO "VSoC: remove_device\n");
	if (vsoc_dev.regions_data) {
		for (i = 0; i < vsoc_dev.layout->region_count; ++i) {
			if (vsoc_dev.regions_data[i].device_created) {
				device_destroy(
					vsoc_dev.class, MKDEV(vsoc_dev.major, i));
				vsoc_dev.regions_data[i].device_created = 0;
			}
			if (vsoc_dev.regions_data[i].irq_requested) {
				free_irq(vsoc_dev.msix_entries[i].vector, NULL);
			}
			vsoc_dev.regions_data[i].irq_requested = 0;
		}
		kfree(vsoc_dev.regions_data);
		vsoc_dev.regions_data = 0;
	}
	if (vsoc_dev.msix_enabled) {
		pci_disable_msix(pdev);
		vsoc_dev.msix_enabled = 0;
	}
	if (vsoc_dev.msix_entries) {
		kfree(vsoc_dev.msix_entries);
		vsoc_dev.msix_entries = 0;
	}
	vsoc_dev.regions = 0;
	if (vsoc_dev.class) {
		class_destroy(vsoc_dev.class);
		vsoc_dev.class = 0;
	}
	if (vsoc_dev.cdev_added) {
		cdev_del(&vsoc_dev.cdev);
		vsoc_dev.cdev_added = 0;
	}
	if (vsoc_dev.major && vsoc_dev.layout) {
		unregister_chrdev_region(MKDEV(vsoc_dev.major, 0),
					 vsoc_dev.layout->region_count);
		vsoc_dev.major = 0;
	}
	vsoc_dev.layout = 0;
	if (vsoc_dev.kernel_mapped_shm && pdev) {
		pci_iounmap(pdev, vsoc_dev.kernel_mapped_shm);
		vsoc_dev.kernel_mapped_shm = 0;
	}
	if (vsoc_dev.regs && pdev) {
		pci_iounmap(pdev, vsoc_dev.regs);
		vsoc_dev.regs = 0;
	}
	if (vsoc_dev.requested_regions && pdev) {
		pci_release_regions(pdev);
		vsoc_dev.requested_regions = 0;
	}
	if (vsoc_dev.enabled_device && pdev) {
		pci_disable_device(pdev);
		vsoc_dev.enabled_device = 0;
	}
	/* Do this last: it indicates that the device is not initialized. */
	vsoc_dev.dev = NULL;
}

static void __exit vsoc_cleanup_module (void)
{
	vsoc_remove_device(vsoc_dev.dev);
	pci_unregister_driver(&vsoc_pci_driver);
}

static int __init vsoc_init_module (void)
{
	int err = -ENOMEM;

	INIT_LIST_HEAD(&vsoc_dev.permissions);
	mutex_init(&vsoc_dev.mtx);

	err = pci_register_driver(&vsoc_pci_driver);
	if (err < 0) {
		return err;
	}

	return 0;
}


static int vsoc_open(struct inode * inode, struct file * filp)
{
	int region_number = MINOR(inode->i_rdev);
	if (region_number >= vsoc_dev.layout->region_count) {
		printk(KERN_ERR "VSoC: region %d doesn't exist\n",
		       region_number);
		return -ENODEV;
	}
	filp->private_data = kzalloc(sizeof(vsoc_private_data_t), GFP_KERNEL);
	if (!filp->private_data) {
		return -ENOMEM;
	}
	return 0;
}

static int vsoc_release(struct inode * inode, struct file * filp)
{
	vsoc_private_data_t* private_data = NULL;
	fd_scoped_permission_node_t* node = NULL;

	if (!filp->private_data) {
		return 0;
	}
	private_data = (vsoc_private_data_t*)filp->private_data;

	node = private_data->fd_scoped_permission_node;
	do_destroy_fd_scoped_permission_node(node);
	private_data->fd_scoped_permission_node = NULL;

	kfree(private_data);
	filp->private_data = NULL;

	return 0;
}

static int vsoc_mmap(struct file *filp, struct vm_area_struct * vma)
{
	u32 region_number = iminor(file_inode(filp));
	unsigned long len = vma->vm_end - vma->vm_start;
	ssize_t max_len;
	unsigned long off;

	if (region_number >= vsoc_dev.layout->region_count) {
		printk(KERN_ERR "VSoC: region %d doesn't exist\n",
		       region_number);
		return -ENODEV;
	}
	off = (vma->vm_pgoff << PAGE_SHIFT)  +
		vsoc_dev.regions[region_number].region_begin_offset;
	max_len = vsoc_dev.regions[region_number].region_end_offset - off;
	if (max_len < len) {
		return -EINVAL;
	}
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	off += vsoc_dev.shm_phys_start;
	if (io_remap_pfn_range(vma, vma->vm_start, off >> PAGE_SHIFT,
			       len, vma->vm_page_prot)) {
		return -EAGAIN;
	}
	return 0;
}


module_init(vsoc_init_module);
module_exit(vsoc_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Greg Hartman <ghartman@google.com>");
MODULE_DESCRIPTION("VSoC interpretation of QEmu's ivshmem device");
MODULE_VERSION("1.0");
