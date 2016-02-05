obj-m := laf.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -Wunused-function -Werror=strict-prototypes

uninstall:
	sudo rmmod laf

install:
	sudo insmod laf.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f lalala

test:
	gcc test.c -o lalala
	./lalala
