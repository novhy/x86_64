obj-m += vsoc_usb_hcd.o

vsoc_usb_hcd-objs := vsoc_usb_hcd_main.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

