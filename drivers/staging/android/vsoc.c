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
 *                                       PCI device:
 *         Copyright 2009 Cam Macdonell <cam@cs.ualberta.ca>
 *
 * Based on cirrusfb.c and 8139cp.c:
 *	   Copyright 1999-2001 Jeff Garzik
 *	   Copyright 2001-2004 Jeff Garzik
 *
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/cdev.h>

#define VSOC_DEVICE_MINOR_NUM 0
#define VSOC_DEV_NAME "vsoc"

enum {
	/*
	 * These constants are determined KVM Inter-VM shared memory device
	 * register offsets
	 */
	IntrMask	= 0x00,	   /* Interrupt Mask */
	IntrStatus	= 0x04,	   /* Interrupt Status */
	IVPosition	= 0x08,	   /* VM ID */
	Doorbell	= 0x0c,	   /* Doorbell */
};

typedef struct vsoc_device {
	void __iomem * regs;

	void * base_addr;

	unsigned int regaddr;
	unsigned int reg_size;

	unsigned int ioaddr;
	unsigned int ioaddr_size;
	unsigned int irq;

	struct list_head permissions;
	struct pci_dev *dev;
	char (*msix_names)[256];
	struct msix_entry *msix_entries;
	int nvectors;

	bool		 enabled;

} vsoc_device;

static struct mutex vsoc_mtx;
static int event_num;
static struct semaphore sema;
static wait_queue_head_t wait_queue;

static vsoc_device vsoc_dev;

static int vsoc_major, vsoc_minor;
static int num_vsoc_devs;
static bool doorbell_mode;

static struct cdev cdev;
static struct class *vsoc_class;

/**
 * Attaches a permission, the ability to read and write a region of memory, to
 * an open file description (see open(2)). Ownership of the region follows the
 * file descriptor, even when it is passed among processes.
 *
 * region_begin_offset and region_end_offset define the region of memory that
 * is controlled by the permission. owner_offset points to a word, also in
 * shared memory, that controls ownership of the region.
 *
 * ownership of the region expires when the associated file description is
 * released.
 *
 * At most one permission can be attached to each file description.
 *
 * This is useful when implementing HALs like gralloc that scope and pass
 * ownership of shared resources via file descriptors.
 *
 * The caller is responsibe for doing any fencing.
 *
 * The calling process will normally identify a currently free region of
 * memory. It will construct a proposed fd_scoped_permission structure:
 *
 *   region_begin_offset and region_end_offset describe the region being claimed
 *
 *   owner_offset points to the location in shared memory that indicates the
 *   owner of the region
 *
 *   before_owned_value gives the value that the caller found at owner_offset
 *   that indicated that the region was free.
 *
 *   after_owned_value is the value that will be stored at owner_offset when
 *   the description is released, destroying the permission.
 *
 *   owned_value is the value that will be stored in owner_offset iff the
 *   permission can be granted. It must be different than before_owned_value.
 *
 * Two fd_scoped_permission structures are compatible if they vary only by
 * their owned_value fields.
 *
 * The driver ensures that, for any group of simultaneous callers proposing
 * compatible fd_scoped_permissions, it will accept exactly one of the
 * propopsals. The other callers will get a failure with errno of EAGAIN.
 *
 * A process receiving a file descriptor can identify the region being
 * granted using the get_fd_scoped_permission ioctl.
 *
 * TODO(ghartman): Add a /sys filesystem entry that summarizes the permissions.
 */
typedef struct {
	u32 region_begin_offset;
	u32 region_end_offset;
	u32 owner_offset;
	u32 before_owned_value;
	u32 after_owned_value;
	u32 owned_value;
} fd_scoped_permission;

typedef struct {
	fd_scoped_permission permission;
	struct list_head list;
} fd_scoped_permission_node;

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

enum vsoc_ioctl {
	set_sema,
	down_sema,
	empty,
	wait_event,
	wait_event_irq,
	read_ivposn,
	read_livelist,
	sema_irq,
	create_fd_scoped_permission = _IOW(0xF5, 0, fd_scoped_permission),
	get_fd_scoped_permission = _IOR(0xF5, 1, fd_scoped_permission)
};

static const struct file_operations vsoc_ops = {
	.owner	 = THIS_MODULE,
	.open	= vsoc_open,
	.mmap	= vsoc_mmap,
	.read	= vsoc_read,
	.unlocked_ioctl	  = vsoc_ioctl,
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
	.name		= "kvm-shmem",
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
	if (np->region_end_offset > vsoc_dev.ioaddr_size)
		return -EINVAL;
	// The owner flag must reside in the memory window
	if (np->owner_offset + sizeof(np->owner_offset)
	    > vsoc_dev.ioaddr_size)
		return -EINVAL;
	// Owner offset must be naturally aligned in the window
	if (np->owner_offset & (sizeof(np->owner_offset) - 1))
		return -EINVAL;
	// The owner value must change if we can claim the memory
	if (np->owned_value == np->before_owned_value)
		return -EINVAL;
	owner_ptr = (atomic_t*) vsoc_dev.base_addr + np->owner_offset;
	// We've already verified that this is in the shared memory window, so
	// it should be safe to write to this address.
	if (atomic_cmpxchg(owner_ptr,
			   np->before_owned_value,
			   np->owned_value) != np->before_owned_value)
		return -EBUSY;
	return 0;
}

static void do_destroy_fd_scoped_permission(fd_scoped_permission* perm)
{
	atomic_t* owner_ptr = NULL;
	int prev = 0;
	if (!perm)
		return;
	owner_ptr = (atomic_t*) vsoc_dev.base_addr + perm->owner_offset;
	prev = atomic_xchg(owner_ptr, perm->after_owned_value);
	if (prev != perm->owned_value)
		printk("VSOC: %x-%x: owner %x: expected to be %x was %x",
		       perm->region_begin_offset, perm->region_end_offset,
		       perm->owner_offset, perm->owned_value, prev);
}


static long vsoc_ioctl(struct file * filp,
			      unsigned int cmd, unsigned long arg)
{

	int rv = 0;
	uint32_t msg;

	printk("VSOC: args is %ld\n", arg);
	switch (cmd) {
	case set_sema:
		printk("VSOC: initialize semaphore\n");
		printk("VSOC: args is %ld\n", arg);
		sema_init(&sema, arg);
		break;
	case down_sema:
		printk("VSOC: sleeping on semaphore (cmd = %d)\n", cmd);
		rv = down_interruptible(&sema);
		printk("VSOC: waking\n");
		break;
	case empty:
		msg = ((arg & 0xff) << 16) + (cmd & 0xff);
		printk("VSOC: args is %ld\n", arg);
		printk("VSOC: ringing sema doorbell\n");
		writel(msg, vsoc_dev.regs + Doorbell);
		break;
	case wait_event:
		printk("VSOC: sleeping on event (cmd = %d)\n", cmd);
		wait_event_interruptible(wait_queue, (event_num == 1));
		printk("VSOC: waking\n");
		event_num = 0;
		break;
	case wait_event_irq:
		msg = ((arg & 0xff) << 16) + 0;
		printk("VSOC: ringing wait_event doorbell on %zu (msg = %d)\n", arg, msg);
		writel(msg, vsoc_dev.regs + Doorbell);
		break;
	case read_ivposn:
		msg = readl( vsoc_dev.regs + IVPosition);
		printk("VSOC: my posn is %d\n", msg);
		rv = copy_to_user((void *)arg, &msg, sizeof(msg));
		if (rv > 0)
			return -EFAULT;
		break;
	case sema_irq:
		// 2 is the actual code, but we use 7 from the user
		msg = ((arg & 0xff) << 8) + (cmd & 0xff);
		printk("VSOC: args is %ld\n", arg);
		printk("VSOC: ringing sema doorbell\n");
		writel(msg, vsoc_dev.regs + Doorbell);
		break;
	case create_fd_scoped_permission:
	{
		fd_scoped_permission_node* node = NULL;
		// EBUSY because this fd already has a permission.
		if (filp->private_data)
			return -EBUSY;
		node = kmalloc(sizeof(*node), GFP_KERNEL);
		// We can't allocate memory for the permission
		if (!node)
			return -ENOMEM;
		INIT_LIST_HEAD(&node->list);
		rv = do_create_fd_scoped_permission(
			&node->permission, (fd_scoped_permission __user *)arg);
		if (!rv) {
			mutex_lock(&vsoc_mtx);
			list_add(&node->list, &vsoc_dev.permissions);
			mutex_unlock(&vsoc_mtx);
			filp->private_data = node;
		} else {
			kfree(node);
			return rv;
		}
		break;
	}
	case get_fd_scoped_permission:
	{
		fd_scoped_permission_node* node =
			(fd_scoped_permission_node*) filp->private_data;
		if (!node)
			return -ENOENT;
		if (copy_to_user((fd_scoped_permission __user *)arg,
				 &node->permission,
				 sizeof(node->permission)))
			return -EFAULT;
	}
	default:
		printk("VSOC: bad ioctl (\n");
	}
	return 0;
}

static ssize_t vsoc_read(struct file * filp, char * buffer, size_t len,
				loff_t * poffset)
{
	int bytes_read = 0;
	unsigned long offset;

	offset = *poffset;

	if (!vsoc_dev.base_addr) {
		printk(KERN_ERR "VSOC: cannot read from ioaddr (NULL)\n");
		return 0;
	}

	if (len > vsoc_dev.ioaddr_size - offset) {
		len = vsoc_dev.ioaddr_size - offset;
	}

	if (len == 0) return 0;

	bytes_read = copy_to_user(buffer, vsoc_dev.base_addr+offset, len);
	if (bytes_read > 0) {
		return -EFAULT;
	}

	*poffset += len;
	return len;
}

static loff_t vsoc_lseek(struct file * filp, loff_t offset, int origin)
{

	loff_t retval = -1;

	switch (origin) {
	case 1:
		offset += filp->f_pos;
	case 0:
		retval = offset;
		if (offset > vsoc_dev.ioaddr_size) {
			offset = vsoc_dev.ioaddr_size;
		}
		filp->f_pos = offset;
	}

	return retval;
}

static ssize_t vsoc_write(struct file * filp, const char * buffer,
				 size_t len, loff_t * poffset)
{

	int bytes_written = 0;
	unsigned long offset;

	offset = *poffset;

	if (!vsoc_dev.base_addr) {
		printk(KERN_ERR "VSOC: cannot write to ioaddr (NULL)\n");
		return 0;
	}

	if (len > vsoc_dev.ioaddr_size - offset) {
		len = vsoc_dev.ioaddr_size - offset;
	}

	if (len == 0) return 0;

	bytes_written = copy_from_user(vsoc_dev.base_addr+offset,
				       buffer, len);
	if (bytes_written > 0) {
		return -EFAULT;
	}

//	printk(KERN_INFO "VSOC: wrote %u bytes at offset %lu\n", (unsigned) len, offset);
	*poffset += len;
	return len;
}

static irqreturn_t vsoc_interrupt (int irq, void *dev_instance)
{
	struct vsoc_device * dev = dev_instance;
	u32 status;

	if (unlikely(dev == NULL))
		return IRQ_NONE;

	status = readl(dev->regs + IntrStatus);
	if (!status || (status == 0xFFFFFFFF))
		return IRQ_NONE;

	/* depending on the message we wake different structures */
	if (status == sema_irq) {
		up(&sema);
	} else if (status == wait_event_irq  || status == 1) {
		event_num = 1;
		wake_up_interruptible(&wait_queue);
	}

	printk(KERN_INFO "VSOC: interrupt (status = 0x%04x)\n",
	       status);

	return IRQ_HANDLED;
}

static int request_msix_vectors(struct vsoc_device *ivs_info, int nvectors)
{
	int i, err;
	const char *name = "vsoc";

	printk(KERN_INFO "devname is %s\n", name);
	ivs_info->nvectors = nvectors;


	ivs_info->msix_entries = kmalloc(nvectors * sizeof *ivs_info->msix_entries,
					 GFP_KERNEL);
	ivs_info->msix_names = kmalloc(nvectors * sizeof *ivs_info->msix_names,
				       GFP_KERNEL);

	for (i = 0; i < nvectors; ++i)
		ivs_info->msix_entries[i].entry = i;

	err = pci_enable_msix(ivs_info->dev, ivs_info->msix_entries,
			      ivs_info->nvectors);
	if (err > 0) {
		printk(KERN_INFO "no MSI. Back to INTx.\n");
		return -ENOSPC;
	}

	if (err) {
		printk(KERN_INFO "some error below zero %d\n", err);
		return err;
	}

	for (i = 0; i < nvectors; i++) {

		snprintf(ivs_info->msix_names[i], sizeof *ivs_info->msix_names,
			 "%s-config", name);

		err = request_irq(ivs_info->msix_entries[i].vector,
				  vsoc_interrupt, 0,
				  ivs_info->msix_names[i], ivs_info);

		if (err) {
			printk(KERN_INFO "couldn't allocate irq for msi-x entry %d with vector %d\n", i, ivs_info->msix_entries[i].vector);
			return -ENOSPC;
		}
	}

	return 0;
}

static int vsoc_probe_device (struct pci_dev *pdev,
				     const struct pci_device_id * ent) {

	int result;

	printk("VSOC: Probing for VSOC Device\n");

	result = pci_enable_device(pdev);
	if (result) {
		printk(KERN_ERR "Cannot probe VSOC device %s: error %d\n",
		       pci_name(pdev), result);
		return result;
	}

	result = pci_request_regions(pdev, "vsoc");
	if (result < 0) {
		printk(KERN_ERR "VSOC: cannot request regions\n");
		goto pci_disable;
	} else printk(KERN_ERR "VSOC: result is %d\n", result);

	if (pdev->irq == 0) {
		doorbell_mode = true;
	}

	vsoc_dev.ioaddr = pci_resource_start(pdev, 2);
	vsoc_dev.ioaddr_size = pci_resource_len(pdev, 2);

	vsoc_dev.base_addr = pci_iomap(pdev, 2, 0);
	printk(KERN_INFO "VSOC: iomap base = 0x%lu \n",
	       (unsigned long) vsoc_dev.base_addr);

	if (!vsoc_dev.base_addr) {
		printk(KERN_ERR "VSOC: cannot iomap region of size %d\n",
		       vsoc_dev.ioaddr_size);
		goto pci_release;
	}

	printk(KERN_INFO "VSOC: ioaddr = %x ioaddr_size = %d\n",
	       vsoc_dev.ioaddr, vsoc_dev.ioaddr_size);

	vsoc_dev.regaddr =  pci_resource_start(pdev, 0);
	vsoc_dev.reg_size = pci_resource_len(pdev, 0);
	vsoc_dev.regs = pci_iomap(pdev, 0, 0x100);

	vsoc_dev.dev = pdev;

	if (!vsoc_dev.regs) {
		printk(KERN_ERR "VSOC: cannot ioremap registers of size %d\n",
		       vsoc_dev.reg_size);
		goto reg_release;
	}

	/* set all masks to on */
	writel(0xffffffff, vsoc_dev.regs + IntrMask);

	/* by default initialize semaphore to 0 */
	sema_init(&sema, 0);

	init_waitqueue_head(&wait_queue);
	event_num = 0;

	if (request_msix_vectors(&vsoc_dev, 4) != 0) {
		if (doorbell_mode == true) goto end;
		printk(KERN_INFO "regular IRQs\n");
		if (request_irq(pdev->irq, vsoc_interrupt, IRQF_SHARED,
				"vsoc", &vsoc_dev)) {
			printk(KERN_ERR "VSOC: cannot get interrupt %d\n", pdev->irq);
			printk(KERN_INFO "VSOC: irq = %u regaddr = %x reg_size = %d\n",
			       pdev->irq, vsoc_dev.regaddr, vsoc_dev.reg_size);
		}
	} else {
		printk(KERN_INFO "MSI-X enabled\n");
	}
end:
	return 0;


reg_release:
	pci_iounmap(pdev, vsoc_dev.base_addr);
pci_release:
	pci_release_regions(pdev);
pci_disable:
	pci_disable_device(pdev);
	return -EBUSY;

}

static void vsoc_remove_device(struct pci_dev* pdev)
{

	printk(KERN_INFO "Unregister vsoc device.\n");
	if (!doorbell_mode)
		free_irq(pdev->irq,&vsoc_dev);
	pci_iounmap(pdev, vsoc_dev.regs);
	pci_iounmap(pdev, vsoc_dev.base_addr);
	pci_release_regions(pdev);
	pci_disable_device(pdev);

}

static void __exit vsoc_cleanup_module (void)
{
	pci_unregister_driver (&vsoc_pci_driver);
	device_destroy(vsoc_class, MKDEV(vsoc_major, vsoc_minor));
	class_destroy(vsoc_class);
	cdev_del(&cdev);
	unregister_chrdev_region(MKDEV(vsoc_major, vsoc_minor),
				 num_vsoc_devs);
}

static int __init vsoc_init_module (void)
{
	int err = -ENOMEM;
	dev_t major, devt;

	INIT_LIST_HEAD(&vsoc_dev.permissions);
	major = MKDEV(vsoc_major, 0);
	num_vsoc_devs = 1;
	mutex_init(&vsoc_mtx);

	err = alloc_chrdev_region(&major, 0, num_vsoc_devs,
				  VSOC_DEV_NAME);
	if (err) {
		pr_err("alloc_chrdev_region failed\n");
		return err;
	}

	vsoc_major = MAJOR(major);

	cdev_init(&cdev, &vsoc_ops);
	cdev.owner = THIS_MODULE;

	devt = MKDEV(vsoc_major, vsoc_minor);

	err = cdev_add(&cdev, devt, 1);
	if (err) {
		pr_err("cdev_add error\n");
		goto unregister_device;
	}

	vsoc_class = class_create(THIS_MODULE, VSOC_DEV_NAME);

	if (!vsoc_class) {
		pr_err("class_create error\n");
		goto del_cdev;
	}

	major = MKDEV(vsoc_major, vsoc_minor);
	if (!device_create(vsoc_class,
			   NULL,
			   major,
			   NULL,
			   VSOC_DEV_NAME "%d",
			   vsoc_minor)) {
		pr_err("device_create failed\n");
		goto destroy_class;
	}

	err = pci_register_driver(&vsoc_pci_driver);
	if (err < 0) {
		goto error;
	}

	return 0;

error:
	device_destroy(vsoc_class, MKDEV(vsoc_major, vsoc_minor));
destroy_class:
	class_destroy(vsoc_class);
del_cdev:
	cdev_del(&cdev);
unregister_device:
	unregister_chrdev_region(MKDEV(vsoc_major, vsoc_minor),
				 num_vsoc_devs);
	return err;
}


static int vsoc_open(struct inode * inode, struct file * filp)
{
	printk(KERN_INFO "Opening vsoc device\n");
	if (MINOR(inode->i_rdev) != VSOC_DEVICE_MINOR_NUM) {
		printk(KERN_INFO "minor number is %d\n", VSOC_DEVICE_MINOR_NUM);
		return -ENODEV;
	}
	filp->private_data = NULL;
	return 0;
}

static int vsoc_release(struct inode * inode, struct file * filp)
{
	if (filp->private_data) {
		fd_scoped_permission_node* node =
			(fd_scoped_permission_node*)filp->private_data;
		do_destroy_fd_scoped_permission(&node->permission);
		mutex_lock(&vsoc_mtx);
		list_del(&node->list);
		mutex_unlock(&vsoc_mtx);
		kfree(node);
		filp->private_data = NULL;
	}
	return 0;
}

static int vsoc_mmap(struct file *filp, struct vm_area_struct * vma)
{

	unsigned long off;
	unsigned long start;

	mutex_lock(&vsoc_mtx);

	off = vma->vm_pgoff << PAGE_SHIFT;
	start = vsoc_dev.ioaddr;

	if ((off + (vma->vm_end - vma->vm_start)) > vsoc_dev.ioaddr_size) {
		mutex_unlock(&vsoc_mtx);
		printk(KERN_INFO "vma->vm_end: %lu\n", vma->vm_end);
		printk(KERN_INFO "vma->vm_start: %lu\n", vma->vm_start);
		printk(KERN_INFO "vma->ioaddr_size: %u\n", vsoc_dev.ioaddr_size);
		printk(KERN_INFO "length check_failed\n");
		return -EINVAL;
	}

	off += start;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	if (io_remap_pfn_range(vma, vma->vm_start, off >> PAGE_SHIFT,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
		mutex_unlock(&vsoc_mtx);
		printk(KERN_INFO "EAGAIN\n");
		return -EAGAIN;
	}
	mutex_unlock(&vsoc_mtx);
	return 0;
}


module_init(vsoc_init_module);
module_exit(vsoc_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Greg Hartman <ghartman@google.com>");
MODULE_DESCRIPTION("VSoC interpretation of QEmu's ivshmem device");
MODULE_VERSION("1.0");
