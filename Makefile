obj-m := laf.o

all: lafctl modules

lafctl:
	$(CC) lafctl.c -O2 -o lafctl

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -Wunused-function -Werror=strict-prototypes

uninstall:
	sudo rm /usr/bin/lafctl
	sudo rm /etc/laf.cfg
	sudo rm /lib/systemd/system/laf.service
	sudo rmmod laf
	sudo rm /lib/modules/$(shell uname -r)/kernel/net/laf/laf.ko
	sudo rmdir /lib/modules/$(shell uname -r)/kernel/net/laf
	echo "** NOW REMOVE laf FROM YOUR /etc/modules.conf OR /etc/modules-load.d FILE **"

install: all
	sudo cp -f lafctl      /usr/bin
	sudo cp -f laf.cfg     /etc
	sudo cp -f laf.service /lib/systemd/system/
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
	rm lafctl

mrproper: clean
	rm -f *.mod.* *.o *.ko .laf.* modules.order
