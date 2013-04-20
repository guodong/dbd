obj-m := dbd.o
KERNELBUILD := /lib/modules/`uname -r`/build
default: clean client server
	@echo "  BUILD kmod"
	@make -C $(KERNELBUILD) M=$(shell pwd) modules

client: client.c log.c
	gcc -o client client.c log.c gateway.c -lpthread
	
server:
	gcc -o server server.c
clean:
	@echo "  CLEAN kmod"
	@rm -rf *.o *.unsigned *.order .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers .*.d client server
