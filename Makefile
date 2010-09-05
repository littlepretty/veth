# comment/uncomment the following line to disable/enable debugging

DEBUG = y

ifeq ($(DEBUG),y)
	DEBFLAGS = -O -g -DVETH_DEBUG -DDEBUG_HDR    # "-O" is needed to expand inlines
else
	DEBFLAGS = -O2
endif

EXTRA_CFLAGS += $(DEBFLAGS)

ifneq ($(KERNELRELEASE),)
	obj-m := veth.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
