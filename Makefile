obj-m += mydbd.o
mydbd-objs := dbd.o cbt.o
KERNELBUILD := /lib/modules/`uname -r`/build
Debug: clean
	@make -C $(KERNELBUILD) M=$(shell pwd) modules

client: client.c log.c hashtable.c option.c mysql.o cache.o
	@rm -rf client
	gcc -o client client.c log.c hashtable.c gateway.c option.c cache.c mysql.o -lpthread -L/usr/lib64/mysql -lmysqlclient

server:
	gcc -o server server.c

manage: option.o
	@rm -rf manage
	gcc -o manage option.o manage.c

option.o: option.c option.h
	@rm -rf option.o
	gcc -c option.c

cache.o: cache.c list.h hashtable.h
	@rm -rf cache.o
	gcc -c list.h hashtable.c cache.c

mysql.o: mysql.c
	gcc -c mysql.c -L /usr/local/mysql/lib/*.a
clean:
	@echo "  CLEAN kmod"
	@rm -rf *.o *.unsigned *.order .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers .*.d *.layout
