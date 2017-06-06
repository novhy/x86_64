/*
 * drivers/char/kvm_ivshmem.c - driver for KVM Inter-VM shared memory PCI device
 *
 * Copyright 2009 Cam Macdonell <cam@cs.ualberta.ca>
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

#define TRUE 1
#define FALSE 0
#define KVM_IVSHMEM_DEVICE_MINOR_NUM 0
#define IVSHMEM_DEV_NAME "ivshmem"

enum {
	/* KVM Inter-VM shared memory device register offsets */
	IntrMask	= 0x00,	   /* Interrupt Mask */
	IntrStatus	= 0x04,	   /* Interrupt Status */
	IVPosition	= 0x08,	   /* VM ID */
	Doorbell	= 0x0c,	   /* Doorbell */
};

typedef struct kvm_ivshmem_device {
	void __iomem * regs;

	void * base_addr;

	unsigned int regaddr;
	unsigned int reg_size;

	unsigned int ioaddr;
	unsigned int ioaddr_size;
	unsigned int irq;

	struct pci_dev *dev;
	char (*msix_names)[256];
	struct msix_entry *msix_entries;
	int nvectors;

	bool		 enabled;

} kvm_ivshmem_device;

static struct mutex ivshmem_mtx;
static int event_num;
static struct semaphore sema;
static wait_queue_head_t wait_queue;

static kvm_ivshmem_device kvm_ivshmem_dev;

static int ivshmem_major, ivshmem_minor;
static int num_ivshmem_devs;
static bool doorbell_mode;

static struct cdev cdev;
static struct class *ivshmem_class;

static long kvm_ivshmem_ioctl(struct file *, unsigned int, unsigned long);
static int kvm_ivshmem_mmap(struct file *, struct vm_area_struct *);
static int kvm_ivshmem_open(struct inode *, struct file *);
static int kvm_ivshmem_release(struct inode *, struct file *);
static ssize_t kvm_ivshmem_read(struct file *, char *, size_t, loff_t *);
static ssize_t kvm_ivshmem_write(struct file *, const char *, size_t, loff_t *);
static loff_t kvm_ivshmem_lseek(struct file * filp, loff_t offset, int origin);

enum ivshmem_ioctl { set_sema, down_sema, empty, wait_event, wait_event_irq, read_ivposn, read_livelist, sema_irq };

static const struct file_operations kvm_ivshmem_ops = {
	.owner	 = THIS_MODULE,
	.open	= kvm_ivshmem_open,
	.mmap	= kvm_ivshmem_mmap,
	.read	= kvm_ivshmem_read,
	.unlocked_ioctl	  = kvm_ivshmem_ioctl,
	.write	 = kvm_ivshmem_write,
	.llseek	 = kvm_ivshmem_lseek,
	.release = kvm_ivshmem_release,
};

static struct pci_device_id kvm_ivshmem_id_table[] = {
	{ 0x1af4, 0x1110, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{ 0 },
};
MODULE_DEVICE_TABLE (pci, kvm_ivshmem_id_table);

static void kvm_ivshmem_remove_device(struct pci_dev* pdev);
static int kvm_ivshmem_probe_device (struct pci_dev *pdev,
				     const struct pci_device_id * ent);

static struct pci_driver kvm_ivshmem_pci_driver = {
	.name		= "kvm-shmem",
	.id_table	= kvm_ivshmem_id_table,
	.probe	   = kvm_ivshmem_probe_device,
	.remove	  = kvm_ivshmem_remove_device,
};

static long kvm_ivshmem_ioctl(struct file * filp,
			      unsigned int cmd, unsigned long arg)
{

	int rv = 0;
	uint32_t msg;

	printk("KVM_IVSHMEM: args is %ld\n", arg);
#if 1
	switch (cmd) {
	case set_sema:
		printk("KVM_IVSHMEM: initialize semaphore\n");
		printk("KVM_IVSHMEM: args is %ld\n", arg);
		sema_init(&sema, arg);
		break;
	case down_sema:
		printk("KVM_IVSHMEM: sleeping on semaphore (cmd = %d)\n", cmd);
		rv = down_interruptible(&sema);
		printk("KVM_IVSHMEM: waking\n");
		break;
	case empty:
		msg = ((arg & 0xff) << 16) + (cmd & 0xff);
		printk("KVM_IVSHMEM: args is %ld\n", arg);
		printk("KVM_IVSHMEM: ringing sema doorbell\n");
		writel(msg, kvm_ivshmem_dev.regs + Doorbell);
		break;
	case wait_event:
		printk("KVM_IVSHMEM: sleeping on event (cmd = %d)\n", cmd);
		wait_event_interruptible(wait_queue, (event_num == 1));
		printk("KVM_IVSHMEM: waking\n");
		event_num = 0;
		break;
	case wait_event_irq:
		msg = ((arg & 0xff) << 16) + 0;
		printk("KVM_IVSHMEM: ringing wait_event doorbell on %zu (msg = %d)\n", arg, msg);
		writel(msg, kvm_ivshmem_dev.regs + Doorbell);
		break;
	case read_ivposn:
		msg = readl( kvm_ivshmem_dev.regs + IVPosition);
		printk("KVM_IVSHMEM: my posn is %d\n", msg);
		rv = copy_to_user((void *)arg, &msg, sizeof(msg));
		if (rv > 0)
			return -EFAULT;
		break;
	case sema_irq:
		// 2 is the actual code, but we use 7 from the user
		msg = ((arg & 0xff) << 8) + (cmd & 0xff);
		printk("KVM_IVSHMEM: args is %ld\n", arg);
		printk("KVM_IVSHMEM: ringing sema doorbell\n");
		writel(msg, kvm_ivshmem_dev.regs + Doorbell);
		break;
	default:
		printk("KVM_IVSHMEM: bad ioctl (\n");
	}
#endif

	return 0;
}

static ssize_t kvm_ivshmem_read(struct file * filp, char * buffer, size_t len,
				loff_t * poffset)
{
	int bytes_read = 0;
	unsigned long offset;

	offset = *poffset;

	if (!kvm_ivshmem_dev.base_addr) {
		printk(KERN_ERR "KVM_IVSHMEM: cannot read from ioaddr (NULL)\n");
		return 0;
	}

	if (len > kvm_ivshmem_dev.ioaddr_size - offset) {
		len = kvm_ivshmem_dev.ioaddr_size - offset;
	}

	if (len == 0) return 0;

	bytes_read = copy_to_user(buffer, kvm_ivshmem_dev.base_addr+offset, len);
	if (bytes_read > 0) {
		return -EFAULT;
	}

	*poffset += len;
	return len;
}

static loff_t kvm_ivshmem_lseek(struct file * filp, loff_t offset, int origin)
{

	loff_t retval = -1;

	switch (origin) {
	case 1:
		offset += filp->f_pos;
	case 0:
		retval = offset;
		if (offset > kvm_ivshmem_dev.ioaddr_size) {
			offset = kvm_ivshmem_dev.ioaddr_size;
		}
		filp->f_pos = offset;
	}

	return retval;
}

static ssize_t kvm_ivshmem_write(struct file * filp, const char * buffer,
				 size_t len, loff_t * poffset)
{

	int bytes_written = 0;
	unsigned long offset;

	offset = *poffset;

	if (!kvm_ivshmem_dev.base_addr) {
		printk(KERN_ERR "KVM_IVSHMEM: cannot write to ioaddr (NULL)\n");
		return 0;
	}

	if (len > kvm_ivshmem_dev.ioaddr_size - offset) {
		len = kvm_ivshmem_dev.ioaddr_size - offset;
	}

	if (len == 0) return 0;

	bytes_written = copy_from_user(kvm_ivshmem_dev.base_addr+offset,
				       buffer, len);
	if (bytes_written > 0) {
		return -EFAULT;
	}

//	printk(KERN_INFO "KVM_IVSHMEM: wrote %u bytes at offset %lu\n", (unsigned) len, offset);
	*poffset += len;
	return len;
}

static irqreturn_t kvm_ivshmem_interrupt (int irq, void *dev_instance)
{
	struct kvm_ivshmem_device * dev = dev_instance;
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

	printk(KERN_INFO "KVM_IVSHMEM: interrupt (status = 0x%04x)\n",
	       status);

	return IRQ_HANDLED;
}

static int request_msix_vectors(struct kvm_ivshmem_device *ivs_info, int nvectors)
{
	int i, err;
	const char *name = "ivshmem";

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
				  kvm_ivshmem_interrupt, 0,
				  ivs_info->msix_names[i], ivs_info);

		if (err) {
			printk(KERN_INFO "couldn't allocate irq for msi-x entry %d with vector %d\n", i, ivs_info->msix_entries[i].vector);
			return -ENOSPC;
		}
	}

	return 0;
}

static int kvm_ivshmem_probe_device (struct pci_dev *pdev,
				     const struct pci_device_id * ent) {

	int result;

	printk("KVM_IVSHMEM: Probing for KVM_IVSHMEM Device\n");

	result = pci_enable_device(pdev);
	if (result) {
		printk(KERN_ERR "Cannot probe KVM_IVSHMEM device %s: error %d\n",
		       pci_name(pdev), result);
		return result;
	}

	result = pci_request_regions(pdev, "kvm_ivshmem");
	if (result < 0) {
		printk(KERN_ERR "KVM_IVSHMEM: cannot request regions\n");
		goto pci_disable;
	} else printk(KERN_ERR "KVM_IVSHMEM: result is %d\n", result);

	if (pdev->irq == 0) {
		doorbell_mode = true;
	}

	kvm_ivshmem_dev.ioaddr = pci_resource_start(pdev, 2);
	kvm_ivshmem_dev.ioaddr_size = pci_resource_len(pdev, 2);

	kvm_ivshmem_dev.base_addr = pci_iomap(pdev, 2, 0);
	printk(KERN_INFO "KVM_IVSHMEM: iomap base = 0x%lu \n",
	       (unsigned long) kvm_ivshmem_dev.base_addr);

	if (!kvm_ivshmem_dev.base_addr) {
		printk(KERN_ERR "KVM_IVSHMEM: cannot iomap region of size %d\n",
		       kvm_ivshmem_dev.ioaddr_size);
		goto pci_release;
	}

	printk(KERN_INFO "KVM_IVSHMEM: ioaddr = %x ioaddr_size = %d\n",
	       kvm_ivshmem_dev.ioaddr, kvm_ivshmem_dev.ioaddr_size);

	kvm_ivshmem_dev.regaddr =  pci_resource_start(pdev, 0);
	kvm_ivshmem_dev.reg_size = pci_resource_len(pdev, 0);
	kvm_ivshmem_dev.regs = pci_iomap(pdev, 0, 0x100);

	kvm_ivshmem_dev.dev = pdev;

	if (!kvm_ivshmem_dev.regs) {
		printk(KERN_ERR "KVM_IVSHMEM: cannot ioremap registers of size %d\n",
		       kvm_ivshmem_dev.reg_size);
		goto reg_release;
	}

	/* set all masks to on */
	writel(0xffffffff, kvm_ivshmem_dev.regs + IntrMask);

	/* by default initialize semaphore to 0 */
	sema_init(&sema, 0);

	init_waitqueue_head(&wait_queue);
	event_num = 0;

	if (request_msix_vectors(&kvm_ivshmem_dev, 4) != 0) {
		if (doorbell_mode == true) goto end;
		printk(KERN_INFO "regular IRQs\n");
		if (request_irq(pdev->irq, kvm_ivshmem_interrupt, IRQF_SHARED,
				"kvm_ivshmem", &kvm_ivshmem_dev)) {
			printk(KERN_ERR "KVM_IVSHMEM: cannot get interrupt %d\n", pdev->irq);
			printk(KERN_INFO "KVM_IVSHMEM: irq = %u regaddr = %x reg_size = %d\n",
			       pdev->irq, kvm_ivshmem_dev.regaddr, kvm_ivshmem_dev.reg_size);
		}
	} else {
		printk(KERN_INFO "MSI-X enabled\n");
	}
end:
	return 0;


reg_release:
	pci_iounmap(pdev, kvm_ivshmem_dev.base_addr);
pci_release:
	pci_release_regions(pdev);
pci_disable:
	pci_disable_device(pdev);
	return -EBUSY;

}

static void kvm_ivshmem_remove_device(struct pci_dev* pdev)
{

	printk(KERN_INFO "Unregister kvm_ivshmem device.\n");
	if (!doorbell_mode)
		free_irq(pdev->irq,&kvm_ivshmem_dev);
	pci_iounmap(pdev, kvm_ivshmem_dev.regs);
	pci_iounmap(pdev, kvm_ivshmem_dev.base_addr);
	pci_release_regions(pdev);
	pci_disable_device(pdev);

}

static void __exit kvm_ivshmem_cleanup_module (void)
{
	pci_unregister_driver (&kvm_ivshmem_pci_driver);
	device_destroy(ivshmem_class, MKDEV(ivshmem_major, ivshmem_minor));
	class_destroy(ivshmem_class);
	cdev_del(&cdev);
	unregister_chrdev_region(MKDEV(ivshmem_major, ivshmem_minor),
				 num_ivshmem_devs);
}

static int __init kvm_ivshmem_init_module (void)
{

	int err = -ENOMEM;

	dev_t major, devt;

	major = MKDEV(ivshmem_major, 0);
	num_ivshmem_devs = 1;

	mutex_init(&ivshmem_mtx);

	err = alloc_chrdev_region(&major, 0, num_ivshmem_devs,
				  IVSHMEM_DEV_NAME);
	if (err) {
		pr_err("alloc_chrdev_region failed\n");
		return err;
	}

	ivshmem_major = MAJOR(major);

	cdev_init(&cdev, &kvm_ivshmem_ops);
	cdev.owner = THIS_MODULE;

	devt = MKDEV(ivshmem_major, ivshmem_minor);

	err = cdev_add(&cdev, devt, 1);
	if (err) {
		pr_err("cdev_add error\n");
		goto unregister_device;
	}

	ivshmem_class = class_create(THIS_MODULE, IVSHMEM_DEV_NAME);

	if (!ivshmem_class) {
		pr_err("class_create error\n");
		goto del_cdev;
	}

	major = MKDEV(ivshmem_major, ivshmem_minor);
	if (!device_create(ivshmem_class,
			   NULL,
			   major,
			   NULL,
			   IVSHMEM_DEV_NAME "%d",
			   ivshmem_minor)) {
		pr_err("device_create failed\n");
		goto destroy_class;
	}

	err = pci_register_driver(&kvm_ivshmem_pci_driver);
	if (err < 0) {
		goto error;
	}

	return 0;

error:
	device_destroy(ivshmem_class, MKDEV(ivshmem_major, ivshmem_minor));
destroy_class:
	class_destroy(ivshmem_class);
del_cdev:
	cdev_del(&cdev);
unregister_device:
	unregister_chrdev_region(MKDEV(ivshmem_major, ivshmem_minor),
				 num_ivshmem_devs);
	return err;
}


static int kvm_ivshmem_open(struct inode * inode, struct file * filp)
{
	printk(KERN_INFO "Opening kvm_ivshmem device\n");
	if (MINOR(inode->i_rdev) != KVM_IVSHMEM_DEVICE_MINOR_NUM) {
		printk(KERN_INFO "minor number is %d\n", KVM_IVSHMEM_DEVICE_MINOR_NUM);
		return -ENODEV;
	}

	return 0;
}

static int kvm_ivshmem_release(struct inode * inode, struct file * filp)
{

	return 0;
}

static int kvm_ivshmem_mmap(struct file *filp, struct vm_area_struct * vma)
{

	unsigned long off;
	unsigned long start;

	mutex_lock(&ivshmem_mtx);

	off = vma->vm_pgoff << PAGE_SHIFT;
	start = kvm_ivshmem_dev.ioaddr;

	if ((off + (vma->vm_end - vma->vm_start)) > kvm_ivshmem_dev.ioaddr_size) {
		mutex_unlock(&ivshmem_mtx);
		printk(KERN_INFO "vma->vm_end: %lu\n", vma->vm_end);
		printk(KERN_INFO "vma->vm_start: %lu\n", vma->vm_start);
		printk(KERN_INFO "vma->ioaddr_size: %u\n", kvm_ivshmem_dev.ioaddr_size);
		printk(KERN_INFO "length check_failed\n");
		return -EINVAL;
	}

	off += start;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	if (io_remap_pfn_range(vma, vma->vm_start, off >> PAGE_SHIFT,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
		mutex_unlock(&ivshmem_mtx);
		printk(KERN_INFO "EAGAIN\n");
		return -EAGAIN;
	}
	mutex_unlock(&ivshmem_mtx);
	return 0;
}


module_init(kvm_ivshmem_init_module);
module_exit(kvm_ivshmem_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cam Macdonell <cam@cs.ualberta.ca>");
MODULE_DESCRIPTION("KVM inter-VM shared memory module");
MODULE_VERSION("1.0");
