obj-m := laf.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -Wunused-function -Werror=strict-prototypes

uninstall:
	sudo rmmod laf

install: all
	sudo insmod laf.ko

reset: uninstall install

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

clean-test:
	rm -f lalala

test:
	gcc test.c -o lalala
	./lalala
