obj-m := laf.o

all:
	#rmmod laf
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -Wunused-function -Werror=strict-prototypes
	insmod laf.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


