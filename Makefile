obj-m += driver.o
 
KDIR = /lib/modules/$(shell uname -r)/build
 
 
all: module userland
	
module:
	make -C $(KDIR)  M=$(shell pwd) modules

userland:
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi create_jobs_userland .c -o create_jobs_userland -lcrypto -lssl
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi queue_ops_userland.c -o queue_ops_userland -lcrypto -lssl

clean:
	make -C $(KDIR)  M=$(shell pwd) clean
	rm -f create_jobs_userland
	rm -f queue_ops_userland