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

load:
	sudo insmod laf.ko

reset: unload load

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

clean-test:
	rm -f lalala

test:
	gcc test.c -o lalala
	./lalala
