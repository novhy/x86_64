obj-m += vsoc_usb_shm.o
ccflags-y := -I$(src)/../common

vsoc_usb_shm-objs := vsoc_usb_shm_main.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

