obj-m := dbd.o
KERNELBUILD := /lib/modules/`uname -r`/build
default: clean
	@echo "  BUILD kmod"
	@make -C $(KERNELBUILD) M=$(shell pwd) modules
	gcc -o server server.c
clean:
	@echo "  CLEAN kmod"
	@rm -rf *.o *.unsigned *.order .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers .*.d
