#include "vsoc_usb_shm.h"

struct vsoc_shm_ops {
	void *(*get_mem) (size_t size, gfp_t flags);
	void (*put_mem) (const void *ptr);
};

struct vsoc_shm_ops vsoc_shm_ops = {
	.get_mem = kzalloc,
	.put_mem = kfree,
};

struct vsoc_shm_ops *vsoc_shm_helper = &vsoc_shm_ops;

struct vsoc_usb_regs *vsoc_usb_shm_regs[VSOC_USB_MAX_NUM_CONTROLLER];

struct vsoc_usb_regs *vsoc_usb_shm_get_regs(int i)
{
	return vsoc_usb_shm_regs[i];
}

EXPORT_SYMBOL_GPL(vsoc_usb_shm_get_regs);

static int __init vsoc_usb_shm_init(void)
{
	int retval;
	int i;

	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		vsoc_usb_shm_regs[i] =
		    vsoc_shm_helper->get_mem(sizeof(struct vsoc_usb_regs),
					     GFP_KERNEL);
		if (!vsoc_usb_shm_regs[i]) {
			retval = -ENOMEM;
			i--;
			goto err_get_mem;
		}
		vsoc_usb_shm_regs[i]->magic = VSOC_USB_SHM_MAGIC;
	}
	printk(KERN_INFO "VSoC USB Shared Memory Helper Driver loaded.\n");
	return 0;

err_get_mem:
	while (i >= 0) {
		vsoc_shm_helper->put_mem(vsoc_usb_shm_regs[i--]);
	}

	return retval;
}

static void __exit vsoc_usb_shm_exit(void)
{
	int i;

	for (i = 0; i < VSOC_USB_MAX_NUM_CONTROLLER; i++) {
		vsoc_shm_helper->put_mem(vsoc_usb_shm_regs[i]);
	}
	printk(KERN_INFO "VSoC USB Shared Memory Helper Driver unloaded.\n");
	return;
}

module_init(vsoc_usb_shm_init);
module_exit(vsoc_usb_shm_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("VSoC USB Shared Memory Helper Driver");
MODULE_AUTHOR("Google Inc.");
