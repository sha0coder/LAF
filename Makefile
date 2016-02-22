ifndef EXTRA_CFLAGS
	EXTRA_CFLAGS = -s -O3 -fno-strict-aliasing -ffast-math -funroll-loops -pipe # -Wall -Wextra -pedantic
endif

ifndef CC
	CC = gcc
endif

obj-m := laf.o

all: laffun lafctl lafd modules

laffun:
	$(CC) $(EXTRA_CFLAGS) -c laffun.c

lafctl:
	$(CC) $(EXTRA_CFLAGS) laffun.o lafctl.c -o lafctl

lafd:
	$(CC) $(EXTRA_CFLAGS) laffun.o lafd.c $(shell pkg-config --cflags dbus-1) -o lafd $(shell pkg-config --libs dbus-1)

modules:
	sudo bash scripts/premake.sh
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -Wunused-function -Werror=strict-prototypes

modules-install:
	sudo cp -f laf.ko /lib/modules/$(shell uname -r)/kernel/net/laf
	sudo depmod -a

modules-uninstall:
	sudo rmmod laf
	sudo rm /lib/modules/$(shell uname -r)/kernel/net/laf/laf.ko
	sudo rmdir /lib/modules/$(shell uname -r)/kernel/net/laf

uninstall:
	sudo rm /usr/bin/lafctl
	sudo rm /usr/bin/lafd
	sudo rm /etc/laf.cfg
	sudo rm /lib/systemd/system/laf.service
	sudo rm /etc/dbus-1/system.d/lafd.conf
	sudo rmmod laf
	sudo rm /lib/modules/$(shell uname -r)/kernel/net/laf/laf.ko
	sudo rmdir /lib/modules/$(shell uname -r)/kernel/net/laf
	sudo systemctl disable laf.service
	echo "** NOW REMOVE laf FROM YOUR /etc/modules.conf OR /etc/modules-load.d FILE **"

install:
	sudo cp -f lafctl      /usr/bin
	sudo cp -f lafd        /usr/bin
	sudo cp -f laf.cfg     /etc
	sudo cp -f laf.service /lib/systemd/system/
	sudo cp -f lafd.conf   /etc/dbus-1/system.d/
	sudo mkdir -p /lib/modules/$(shell uname -r)/kernel/net/laf
	sudo cp -f laf.ko /lib/modules/$(shell uname -r)/kernel/net/laf
	sudo depmod -a
	sudo systemctl enable laf.service
	echo "** NOW ADD laf TO YOUR /etc/modules.conf OR /etc/modules-load.d FILE **"

unload:
	sudo rmmod laf

load: all
	sudo insmod laf.ko

reset: clean unload load

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f laffun.o lafctl lafd

mrproper: clean
	rm -f *.mod.* *.o *.ko .laf.* modules.order
