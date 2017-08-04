obj-m += vsoc_usb_gadget.o

vsoc_usb_gadget-objs := vsoc_usb_gadget_main.o vsoc_usb_gadget_driver.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

