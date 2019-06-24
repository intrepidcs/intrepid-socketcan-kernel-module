obj-m 		= intrepid.o
KVERSION 	= $(shell uname -r)
all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
install:
	mkdir -p /lib/modules/$(KVERSION)/extra
	cp intrepid.ko /lib/modules/$(KVERSION)/extra/
	grep -q -F 'intrepid' /etc/modules || echo 'intrepid' | tee -a /etc/modules
	depmod -a
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
reload: all
	-sudo rmmod intrepid
	sudo modprobe can
	sudo modprobe can_raw
	sudo modprobe can_dev
	sudo insmod intrepid.ko
