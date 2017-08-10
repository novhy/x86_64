obj-m += vsoc_usb_hcd.o
ccflags-y := -I$(src)/../common

vsoc_usb_hcd-objs := vsoc_usb_hcd_main.o vsoc_usb_hcd_driver.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

