obj-m := laf.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -Wunused-function -Werror=strict-prototypes

uninstall:
	sudo rmmod laf
	sudo rm /lib/modules/$(shell uname -r)/kernel/net/laf/laf.ko
	sudo rmdir /lib/modules/$(shell uname -r)/kernel/net/laf
	echo "** NOW REMOVE laf FROM YOUR /etc/modules.conf OR /etc/modules-load.d FILE **"

install: all
	sudo mkdir /lib/modules/$(shell uname -r)/kernel/net/laf
	sudo cp -f laf.ko /lib/modules/$(shell uname -r)/kernel/net/laf
	sudo depmod -a
	echo "** NOW ADD laf TO YOUR /etc/modules.conf OR /etc/modules-load.d FILE **"

unload:
	sudo rmmod laf

load: all
	sudo insmod laf.ko

reset: clean unload load

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test: test-send test-recv

clean-test:
	rm -f test-recv
	rm -f test-send

test-recv:
	gcc test-recv.c -o test-recv
	./test-recv

test-send:
	gcc test-send.c -o test-send
	./test-send
