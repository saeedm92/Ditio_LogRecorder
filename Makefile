LOCAL_CFLAGS = $(WARNING_CFLAGS) -Iinclude -D_FILE_OFFSET_BITS=64
ccflags-y := -Wframe-larger-than=2048

KDIR=/home/saeed/android/android_hammerhead/system/out/target/product/hammerhead/obj/KERNEL_OBJ

log_recorder-objs := my_log_recorder.o entry_fast.o mbed_lib/aes.o mbed_lib/entropy.o mbed_lib/ctr_drbg.o mbed_lib/rsa.o mbed_lib/bignum.o mbed_lib/md.o mbed_lib/oid.o mbed_lib/sha256.o mbed_lib/defs.o mbed_lib/md5.o mbed_lib/asn1parse.o

obj-m += log_recorder.o

PWD := $(shell pwd)
EXTRA_CFLAGS = -fno-pic -Wno-unused-result -Wno-unused-value -Wno-unused-variable

#all: kern_mod

kern_mod:
	$(MAKE) ARCH=arm SUBARCH=arm CROSS_COMPILE=/home/saeed/android/android_hammerhead/system/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.8/bin/arm-linux-androideabi- -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
	rm *.ko *.mod.c -rf *.o

